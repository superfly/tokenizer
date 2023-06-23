package tokenizer

import (
	"bytes"
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
	"unicode"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

var FilteredHeaders = []string{headerProxyAuthorization, headerProxyTokenizer}

var upstreamTrust *x509.CertPool

func init() {
	var err error
	upstreamTrust, err = x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
}

const headerProxyTokenizer = "Proxy-Tokenizer"

type tokenizer struct {
	*goproxy.ProxyHttpServer
	priv *[32]byte
	pub  *[32]byte
}

var _ goproxy.HttpsHandler = new(tokenizer)
var _ goproxy.ReqHandler = new(tokenizer)
var _ http.Handler = new(tokenizer)

func NewTokenizer(openKey string) *tokenizer {
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

	// fly-proxy rewrites incoming requests to not include the full URI so we
	// have to look at the host header.
	tkz.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" {
			http.Error(w, "must specify host", 400)
			return
		}
		r.URL.Scheme = "http"
		r.URL.Host = r.Host
		tkz.ServeHTTP(w, r)
	})

	proxy.Tr = &http.Transport{
		Dial: forceTLSDialer,
		// probably not necessary, but I don't want to worry about desync/smuggling
		DisableKeepAlives: true,
	}
	proxy.ConnectDial = nil
	proxy.ConnectDialWithReq = nil
	proxy.OnRequest().HandleConnect(tkz)
	proxy.OnRequest().Do(tkz)

	return tkz
}

// HandleConnect implements goproxy.HttpsHandler
func (t *tokenizer) HandleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	_, port, _ := strings.Cut(host, ":")
	if port == "443" {
		logrus.WithField("host", host).Warn("attempt to proxy to https downstream")
		ctx.Resp = &http.Response{StatusCode: http.StatusBadRequest}
		return goproxy.RejectConnect, ""
	}

	processors, err := t.processorsFromRequest(ctx.Req)
	if err != nil {
		ctx.Resp = errorResponse(err)
		return goproxy.RejectConnect, ""
	}

	ctx.UserData = processors
	return goproxy.HTTPMitmConnect, host
}

// Handle implements goproxy.ReqHandler
func (t *tokenizer) Handle(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	var processors []RequestProcessor
	if ctx.UserData != nil {
		processors = ctx.UserData.([]RequestProcessor)
	}

	if reqProcessors, err := t.processorsFromRequest(req); err != nil {
		return req, errorResponse(err)
	} else {
		processors = append(processors, reqProcessors...)
	}

	for _, processor := range processors {
		if err := processor(req); err != nil {
			logrus.WithError(err).Warn("run processor")
			return nil, &http.Response{StatusCode: http.StatusBadRequest}
		}
	}

	for _, h := range FilteredHeaders {
		req.Header.Del(h)
	}

	return req, nil
}

func (t *tokenizer) processorsFromRequest(req *http.Request) ([]RequestProcessor, error) {
	hdrs := req.Header[headerProxyTokenizer]
	processors := make([]RequestProcessor, 0, len(hdrs))

	for _, hdr := range hdrs {
		b64Secret, params, err := parseHeaderProxyTokenizer(hdr)
		if err != nil {
			return nil, err
		}

		ctSecret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Secret))
		if err != nil {
			return nil, fmt.Errorf("bad Proxy-Tokenizer encoding: %w", err)
		}

		jsonSecret, ok := box.OpenAnonymous(nil, ctSecret, t.pub, t.priv)
		if !ok {
			return nil, errors.New("failed Proxy-Tokenizer decryption")
		}

		secret := new(Secret)
		if err = json.Unmarshal(jsonSecret, secret); err != nil {
			return nil, fmt.Errorf("bad secret json: %w", err)
		}

		if err = secret.AuthRequest(req); err != nil {
			return nil, fmt.Errorf("unauthorized to use secret: %w", err)
		}

		for _, v := range secret.RequestValidators {
			if err := v.Validate(req); err != nil {
				return nil, fmt.Errorf("request validator failed: %w", err)
			}
		}

		processor, err := secret.Processor(params)
		if err != nil {
			return nil, err
		}

		processors = append(processors, processor)
	}

	return processors, nil
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
	}

	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader([]byte(err.Error())))}
}

func forceTLSDialer(network, addr string) (net.Conn, error) {
	if network != "tcp" {
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
	return tls.Dial("tcp", addr, &tls.Config{RootCAs: upstreamTrust})
}
