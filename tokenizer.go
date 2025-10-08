package tokenizer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/exp/maps"

	"github.com/superfly/tokenizer/flysrc"
)

var FilteredHeaders = []string{headerProxyAuthorization, headerProxyTokenizer}

// UpstreamTrust is the trusted certificate pool to use for upstream requests.
var UpstreamTrust *x509.CertPool

func init() {
	var err error
	UpstreamTrust, err = x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
}

const headerProxyTokenizer = "Proxy-Tokenizer"

type tokenizer struct {
	*goproxy.ProxyHttpServer

	// OpenProxy dictates whether requests without any sealed secrets are allowed.
	OpenProxy bool

	// RequireFlySrc will reject requests without a fly-src when set.
	RequireFlySrc bool

	// tokenizerHostnames is a list of hostnames where tokenizer can be reached.
	// If provided, this allows tokenizer to transparently proxy requests (ie.
	// accept normal HTTP requests with arbitrary hostnames) while blocking
	// circular requests back to itself. Any DNS names for tokenizer as well as
	// static IP addresses should be included.
	tokenizerHostnames []string

	priv *[32]byte
	pub  *[32]byte
}

type Option func(*tokenizer)

// OpenProxy specifies that requests without any sealed secrets are allowed.
func OpenProxy() Option {
	return func(t *tokenizer) {
		t.OpenProxy = true
	}
}

// RequireFlySrc specifies that requests without a fly-src will be rejected.
func RequireFlySrc() Option {
	return func(t *tokenizer) {
		t.RequireFlySrc = true
	}
}

// TokenizerHostnames is a list of hostnames where tokenizer can be reached. If
// provided, this allows tokenizer to transparently proxy requests (ie. accept
// normal HTTP requests with arbitrary hostnames) while blocking circular
// requests back to itself. Any DNS names for tokenizer as well as static IP
// addresses should be included.
func TokenizerHostnames(hostnames ...string) Option {
	return func(t *tokenizer) {
		t.tokenizerHostnames = hostnames
	}
}

func NewTokenizer(openKey string, opts ...Option) *tokenizer {
	privBytes, err := hex.DecodeString(openKey)
	if err != nil {
		logrus.WithError(err).Panic("bad private key")
	}
	if len(privBytes) != 32 {
		logrus.Panicf("bad private key size: %d", len(privBytes))
	}
	priv := (*[32]byte)(privBytes)
	pub := new([32]byte)
	curve25519.ScalarBaseMult(pub, priv)

	proxy := goproxy.NewProxyHttpServer()
	tkz := &tokenizer{ProxyHttpServer: proxy, priv: priv, pub: pub}

	for _, opt := range opts {
		opt(tkz)
	}

	hostnameMap := map[string]bool{}
	for _, hostname := range tkz.tokenizerHostnames {
		hostnameMap[hostname] = true
	}

	// fly-proxy rewrites incoming requests to not include the full URI so we
	// have to look at the host header.
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case len(hostnameMap) == 0:
			logrus.WithFields(reqLogFields(r)).Warn("I'm not that kind of server")
			http.Error(w, "I'm not that kind of server", 400)
			return
		case r.Host == "":
			logrus.WithFields(reqLogFields(r)).Warn("must specify host")
			http.Error(w, "must specify host", 400)
			return
		}

		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			if strings.Contains(err.Error(), "missing port in address") {
				host = r.Host
			} else {
				logrus.WithFields(reqLogFields(r)).Warn("bad host")
				http.Error(w, "bad host", 400)
				return
			}
		}

		if hostnameMap[host] {
			logrus.WithFields(reqLogFields(r)).Warn("circular request")
			http.Error(w, "circular request", 400)
			return
		}

		r.URL.Scheme = "http"
		r.URL.Host = r.Host
		tkz.ServeHTTP(w, r)
	})

	proxy.Tr = &http.Transport{
		Dial: dialFunc(tkz.tokenizerHostnames),
		// probably not necessary, but I don't want to worry about desync/smuggling
		DisableKeepAlives: true,
	}
	proxy.ConnectDial = nil
	proxy.ConnectDialWithReq = nil
	proxy.OnRequest().HandleConnectFunc(tkz.HandleConnect)
	proxy.OnRequest().DoFunc(tkz.HandleRequest)
	proxy.OnResponse().DoFunc(tkz.HandleResponse)

	return tkz
}

func (t *tokenizer) SealKey() string {
	return hex.EncodeToString(t.pub[:])
}

// data that we can pass around between callbacks
type proxyUserData struct {
	// processors from our handling of the initial CONNECT request if this is a
	// tunneled connection.
	connectProcessors []RequestProcessor

	// start time of the CONNECT request if this is a tunneled connection.
	connectStart time.Time
	connLog      logrus.FieldLogger

	// start time of the current request. gets reset between requests within a
	// tunneled connection.
	requestStart time.Time
	reqLog       logrus.FieldLogger
}

// HandleConnect implements goproxy.FuncHttpsHandler
func (t *tokenizer) HandleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	logger := logrus.WithField("connect_host", host)
	logger = logger.WithFields(reqLogFields(ctx.Req))
	if host == "" {
		logger.Warn("no host in CONNECT request")
		ctx.Resp = errorResponse(ErrBadRequest)
		return goproxy.RejectConnect, ""
	}

	pud := &proxyUserData{
		connLog:      logger,
		connectStart: time.Now(),
	}

	_, port, _ := strings.Cut(host, ":")
	if port == "443" {
		pud.connLog.Warn("attempt to proxy to https downstream")
		ctx.Resp = errorResponse(ErrBadRequest)
		return goproxy.RejectConnect, ""
	}

	connectProcessors, safeSecret, err := t.processorsFromRequest(ctx.Req)
	if safeSecret != "" {
		pud.connLog = pud.connLog.WithField("secret", safeSecret)
	}
	if err != nil {
		pud.connLog.WithError(err).Warn("find processor (CONNECT)")
		ctx.Resp = errorResponse(err)
		return goproxy.RejectConnect, ""
	}

	pud.connectProcessors = connectProcessors
	ctx.UserData = pud

	return goproxy.HTTPMitmConnect, host
}

func getSource(req *http.Request) string {
	var forwards []string
	if forwardedFor := req.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		forwards = strings.Split(forwardedFor, ", ")
	}

	srcs := append(forwards, req.RemoteAddr)
	return strings.Join(srcs, ", ")
}

func reqLogFields(req *http.Request) logrus.Fields {
	return logrus.Fields{
		"source":    getSource(req),
		"method":    req.Method,
		"host":      req.Host,
		"path":      req.URL.Path,
		"queryKeys": strings.Join(maps.Keys(req.URL.Query()), ", "),
	}
}

// HandleRequest implements goproxy.FuncReqHandler
func (t *tokenizer) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if ctx.UserData == nil {
		ctx.UserData = &proxyUserData{}
	}
	pud, ok := ctx.UserData.(*proxyUserData)

	if !ok || !pud.requestStart.IsZero() || pud.reqLog != nil {
		logrus.Warn("bad proxyUserData")
		return nil, errorResponse(ErrInternal)
	}

	pud.requestStart = time.Now()
	if pud.connLog != nil {
		pud.reqLog = pud.connLog
	} else {
		pud.reqLog = logrus.WithFields(reqLogFields(ctx.Req))
	}

	fsrc, err := flysrc.FromRequest(req)
	if err != nil {
		if t.RequireFlySrc {
			pud.reqLog.Warn(err.Error())
			return nil, errorResponse(ErrBadRequest)
		}
	} else {
		req = req.Clone(flysrc.WithFlySrc(req.Context(), fsrc))
		pud.reqLog = pud.reqLog.WithFields(logrus.Fields{
			"flysrc-org":       fsrc.Org,
			"flysrc-app":       fsrc.App,
			"flysrc-instance":  fsrc.Instance,
			"flysrc-timestamp": fsrc.Timestamp,
		})
	}

	processors := append([]RequestProcessor(nil), pud.connectProcessors...)
	reqProcessors, safeSecret, err := t.processorsFromRequest(req)
	if safeSecret != "" {
		pud.reqLog = pud.reqLog.WithField("secret", safeSecret)
	}
	if err != nil {
		pud.reqLog.WithError(err).Warn("find processor")
		return req, errorResponse(err)
	} else {
		processors = append(processors, reqProcessors...)
	}

	if len(processors) == 0 && !t.OpenProxy {
		pud.reqLog.Warn("no processors")
		return nil, errorResponse(ErrBadRequest)
	}

	pud.reqLog = pud.reqLog.WithField("processors", len(processors))

	for _, processor := range processors {
		if err := processor(req); err != nil {
			pud.reqLog.WithError(err).Warn("run processor")
			return nil, errorResponse(ErrBadRequest)
		}
	}

	for _, h := range FilteredHeaders {
		req.Header.Del(h)
	}

	return req, nil
}

// HandleResponse implements goproxy.FuncRespHandler
func (t *tokenizer) HandleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// This callback is hit twice if there was an error in the downstream
	// request. The first time a nil request is given and the second time we're
	// given whatever we returned the first time. Skip logging on the second
	// call. This should continue to work okay if
	// https://github.com/elazarl/goproxy/pull/512 is ever merged.
	if ctx.Error != nil && resp != nil {
		return resp
	}

	pud, ok := ctx.UserData.(*proxyUserData)
	if !ok || pud.requestStart.IsZero() || pud.reqLog == nil {
		logrus.Warn("missing proxyUserData")
		return errorResponse(ErrInternal)
	}

	log := pud.reqLog.WithField("durMS", int64(time.Since(pud.requestStart)/time.Millisecond))

	if !pud.connectStart.IsZero() {
		log = log.WithField("connDurMS", int64(time.Since(pud.connectStart)/time.Millisecond))
	}
	if resp != nil {
		log = log.WithField("status", resp.StatusCode)
		resp.Header.Set("Connection", "close")
	}

	// reset pud for next request in tunnel
	pud.requestStart = time.Time{}
	pud.reqLog = nil

	if ctx.Error != nil {
		log.WithError(ctx.Error).Warn()
		return errorResponse(ctx.Error)
	}

	log.Info()

	return resp
}

func (t *tokenizer) processorsFromRequest(req *http.Request) ([]RequestProcessor, string, error) {
	hdrs := req.Header[headerProxyTokenizer]
	processors := make([]RequestProcessor, 0, len(hdrs))

	var safeSecret string
	for _, hdr := range hdrs {
		b64Secret, params, err := parseHeaderProxyTokenizer(hdr)
		if err != nil {
			return nil, safeSecret, err
		}

		ctSecret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Secret))
		if err != nil {
			return nil, safeSecret, fmt.Errorf("bad Proxy-Tokenizer encoding: %w", err)
		}

		jsonSecret, ok := box.OpenAnonymous(nil, ctSecret, t.pub, t.priv)
		if !ok {
			return nil, safeSecret, errors.New("failed Proxy-Tokenizer decryption")
		}

		secret := new(Secret)
		if err = json.Unmarshal(jsonSecret, secret); err != nil {
			return nil, safeSecret, fmt.Errorf("bad secret json: %w", err)
		}

		safeSecret = secret.StripHazmatString()
		if err = secret.AuthRequest(req); err != nil {
			return nil, safeSecret, fmt.Errorf("unauthorized to use secret: %w", err)
		}

		for _, v := range secret.RequestValidators {
			if err := v.Validate(req); err != nil {
				return nil, safeSecret, fmt.Errorf("request validator failed: %w", err)
			}
		}

		processor, err := secret.Processor(params)
		if err != nil {
			return nil, safeSecret, err
		}
		processors = append(processors, processor)
	}

	return processors, safeSecret, nil
}

func parseHeaderProxyTokenizer(hdr string) (string, map[string]string, error) {
	b64Secret, paramJSON, _ := strings.Cut(hdr, ";")

	b64Secret = strings.TrimFunc(b64Secret, unicode.IsSpace)
	paramJSON = strings.TrimFunc(paramJSON, unicode.IsSpace)

	if b64Secret == "" {
		return "", nil, fmt.Errorf("%w: bad tokenizer header", ErrBadRequest)
	}

	processorParams := make(map[string]string)
	if paramJSON != "" {
		if err := json.Unmarshal([]byte(paramJSON), &processorParams); err != nil {
			return "", nil, fmt.Errorf("%w: %w", ErrBadRequest, err)
		}
	}

	return b64Secret, processorParams, nil
}

func formatHeaderProxyTokenizer(b64Secret string, processorParams map[string]string) string {
	hdr := b64Secret

	if len(processorParams) > 0 {
		paramJSON, _ := json.Marshal(processorParams)
		hdr = fmt.Sprintf("%s; %s", hdr, paramJSON)
	}

	return hdr
}

func errorResponse(err error) *http.Response {
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, ErrNotAuthorized):
		status = http.StatusProxyAuthRequired
	case errors.Is(err, ErrBadRequest):
		status = http.StatusBadRequest
	case errors.Is(err, ErrInternal):
		status = http.StatusBadGateway
	}

	return &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader([]byte(err.Error()))),
		Header:     make(http.Header),
	}
}

// dialFunc returns a function for dialing network addresses. Ours does a few
// special things.
//   - It denies connections to the given set of IP addresses. This is to prevent
//     circular requests back to tokenizer. Invalid IPs are ignored.
//   - It rejects requests for TLS upstreams. We need to see/modify requests, so
//     our proxy can't do passthrough TLS.
//   - It forces the upstream connection to be TLS. We want the actual upstream
//     connection to be over TLS because security.
func dialFunc(badAddrs []string) func(string, string) (net.Conn, error) {
	_, fdaaNet, err := net.ParseCIDR("fdaa::/8")
	if err != nil {
		panic(err)
	}

	netDialer := net.Dialer{}

	baMap := map[string]bool{}
	for _, ba := range badAddrs {
		if ip := net.ParseIP(ba); ip != nil {
			baMap[ip.String()] = true
		}
	}

	if len(baMap) != 0 {
		netDialer.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}

			switch ip := net.ParseIP(h); {
			case ip == nil:
				return fmt.Errorf("bad ip: %s", address)
			case ip.IsPrivate():
				return fmt.Errorf("%w: dialing private address %s denied", ErrBadRequest, address)
			case ip.IsLoopback():
				return fmt.Errorf("%w: dialing loopback address %s denied", ErrBadRequest, address)
			case fdaaNet.Contains(ip):
				return fmt.Errorf("%w: dialing fdaa::/8 address %s denied", ErrBadRequest, address)
			case baMap[ip.String()]:
				return fmt.Errorf("%w: dialing address %s denied", ErrBadRequest, address)
			default:
				return nil
			}
		}
	}

	return func(network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, fmt.Errorf("%w: dialing network %s not supported", ErrBadRequest, network)
		}

		hostname, port, _ := strings.Cut(addr, ":")
		if hostname == "" {
			return nil, fmt.Errorf("%w: attempt to dial without host: %q", ErrBadRequest, addr)
		}
		switch port {
		case "443":
			return nil, fmt.Errorf("%w: proxied request must be HTTP", ErrBadRequest)
		case "80", "":
			port = "443"
		}
		addr = fmt.Sprintf("%s:%s", hostname, port)

		return tls.DialWithDialer(&netDialer, network, addr, &tls.Config{RootCAs: UpstreamTrust})
	}
}
