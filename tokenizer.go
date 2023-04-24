package tokenizer

import (
	"encoding/pem"
	"errors"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
)

const (
	caPath        = "/_proxy_ca"
	headerReplace = "X-Tokenizer-Replace"
)

type tokenizer struct {
	*goproxy.ProxyHttpServer
	secrets SecretStore
}

var _ goproxy.HttpsHandler = new(tokenizer)
var _ goproxy.ReqHandler = new(tokenizer)
var _ http.Handler = new(tokenizer)

func NewTokenizer(ss SecretStore) *tokenizer {
	ca := newFakeCA()
	proxy := goproxy.NewProxyHttpServer()
	tkz := &tokenizer{ProxyHttpServer: proxy, secrets: ss}

	proxy.CertStore = ca
	proxy.OnRequest().HandleConnect(tkz)
	proxy.OnRequest().Do(tkz)
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != caPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		for _, cert := range ca.Chain() {
			pem.Encode(w, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
		}
	})

	return tkz
}

// HandleConnect implements goproxy.HttpsHandler
func (t *tokenizer) HandleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	hdrs := ctx.Req.Header[headerReplace]
	processors := make([]RequestProcessor, 0, len(hdrs))

	for _, hdr := range hdrs {
		secretKey, processorParams, err := parseHeaderReplace(hdr)
		if err != nil {
			logrus.WithField("hdr", hdr).Warn("bad replace header")
			ctx.Resp = &http.Response{StatusCode: http.StatusBadRequest}
			return goproxy.RejectConnect, ""
		}

		secret, err := t.secrets.get(ctx.Req.Context(), secretKey)
		switch {
		case errors.Is(err, ErrNotFound):
			logrus.WithField("key", secretKey).Warn("bad key")
			ctx.Resp = &http.Response{StatusCode: http.StatusNotFound}
			return goproxy.RejectConnect, ""
		case err != nil:
			logrus.WithError(err).Warn("failed secret lookup")
			ctx.Resp = &http.Response{StatusCode: http.StatusNotFound}
			return goproxy.RejectConnect, ""
		}

		if err := secret.AuthorizeAccess(ctx.Req); err != nil {
			logrus.WithError(err).Warn("failed authz")
			ctx.Resp = &http.Response{StatusCode: http.StatusUnauthorized}
			return goproxy.RejectConnect, ""
		}

		processor, err := secret.Processor(processorParams)
		if err != nil {
			logrus.WithError(err).Warn("bad secret")
			ctx.Resp = &http.Response{StatusCode: http.StatusInternalServerError}
			return goproxy.RejectConnect, ""
		}

		processors = append(processors, processor)
	}

	ctx.UserData = processors
	return goproxy.MitmConnect, host
}

// Handle implements goproxy.ReqHandler
func (t *tokenizer) Handle(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	processors := ctx.UserData.([]RequestProcessor)
	for _, processor := range processors {
		if err := processor(req); err != nil {
			logrus.WithError(err).Warn("processor failure")
			return nil, &http.Response{StatusCode: http.StatusBadRequest}
		}
	}
	return req, nil
}
