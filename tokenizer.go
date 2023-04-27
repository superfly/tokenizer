package tokenizer

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
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
	secrets SecretStore
}

var _ goproxy.HttpsHandler = new(tokenizer)
var _ goproxy.ReqHandler = new(tokenizer)
var _ http.Handler = new(tokenizer)

func NewTokenizer(ss SecretStore) *tokenizer {
	proxy := goproxy.NewProxyHttpServer()
	tkz := &tokenizer{ProxyHttpServer: proxy, secrets: ss}

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

	proxy.Tr = &http.Transport{Dial: forceTLSDialer}
	proxy.OnRequest().HandleConnect(tkz)
	proxy.OnRequest().Do(tkz)

	return tkz
}

// HandleConnect implements goproxy.HttpsHandler
func (t *tokenizer) HandleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	_, port, _ := strings.Cut(host, ":")
	if port != "80" {
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
		secretKey, processorParams, err := parseHeaderProxyTokenizer(hdr)
		if err != nil {
			logrus.WithError(err).WithField("hdr", hdr).Warn("parse tokenizer header")
			return nil, err
		}

		secret, err := t.secrets.get(req.Context(), secretKey)
		if err != nil {
			logrus.WithError(err).WithField("key", secretKey).Warn("secret lookup")
			return nil, err
		}

		if err := secret.AuthorizeAccess(req); err != nil {
			logrus.WithError(err).Warn("failed authz")
			return nil, err
		}

		processor, err := secret.Processor(processorParams)
		if err != nil {
			logrus.WithError(err).Warn("processor lookup")
			return nil, err
		}

		processors = append(processors, processor)
	}

	return processors, nil
}

func errorResponse(err error) *http.Response {
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
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
	switch port {
	case "443":
		return nil, fmt.Errorf("%w: proxied request must be HTTP", ErrBadRequest)
	case "80":
		port = "443"
	}
	addr = fmt.Sprintf("%s:%s", hostname, port)
	return tls.Dial("tcp", addr, &tls.Config{RootCAs: upstreamTrust})
}
