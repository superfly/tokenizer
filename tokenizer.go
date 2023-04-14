package main

import (
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
)

const (
	caPath             = "/_proxy_ca"
	headerAuth         = "Proxy-Authorization"
	headerReplace      = "X-Tokenizer-Replace"
	headerReplaceDelim = "="
	dataAuthType       = "auth type"
	dataSecret         = "secret"
	authTypeSecret     = "shared secret"
)

type tokenizer struct {
	*goproxy.ProxyHttpServer
	secrets secretStore
}

var _ goproxy.HttpsHandler = new(tokenizer)
var _ goproxy.ReqHandler = new(tokenizer)
var _ http.Handler = new(tokenizer)

func newTokenizer(vault secretStore) *tokenizer {
	ca := newFakeCA()
	proxy := goproxy.NewProxyHttpServer()
	tkz := &tokenizer{ProxyHttpServer: proxy, secrets: vault}

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
	auth := ctx.Req.Header.Get(headerAuth)
	if auth == "" {
		logrus.Warn("missing auth header")
		ctx.Resp = &http.Response{StatusCode: http.StatusProxyAuthRequired}
		return goproxy.RejectConnect, ""
	}

	hdrs := ctx.Req.Header[headerReplace]
	mapping := make(map[string]string, len(hdrs))
	ctx.UserData = mapping

	for _, hdr := range hdrs {
		token, path, ok := strings.Cut(hdr, headerReplaceDelim)
		if !ok {
			logrus.WithField("hdr", hdr).Warn("bad replace header")
			ctx.Resp = &http.Response{StatusCode: http.StatusBadRequest}
			return goproxy.RejectConnect, ""
		}

		data, err := t.secrets.get(ctx.Req.Context(), path)
		switch {
		case errors.Is(err, errNotFound):
			logrus.WithField("path", path).Warn("bad path")
			ctx.Resp = &http.Response{StatusCode: http.StatusNotFound}
			return goproxy.RejectConnect, ""
		case err != nil:
			logrus.WithError(err).Warn("failed vault lookup")
			ctx.Resp = &http.Response{StatusCode: http.StatusNotFound}
			return goproxy.RejectConnect, ""
		}

		if err = t.authorize(auth, data); err != nil {
			logrus.WithError(err).Warn("failed authz")
			ctx.Resp = &http.Response{StatusCode: http.StatusUnauthorized}
			return goproxy.RejectConnect, ""
		}

		mapping[token] = data[dataSecret]
	}

	return goproxy.MitmConnect, host
}

const authSecret = "my secret"

func (t *tokenizer) authorize(auth string, data map[string]string) error {
	switch data[dataAuthType] {
	case authTypeSecret:
		if subtle.ConstantTimeCompare([]byte(auth), []byte(authSecret)) == 1 {
			return nil
		}
		return errors.New("bad auth secret")
	default:
		return fmt.Errorf("bad auth type: %s", data[dataAuthType])
	}
}

// Handle implements goproxy.ReqHandler
func (t *tokenizer) Handle(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// todo make this good
	mapping := ctx.UserData.(map[string]string)
	for token, replacement := range mapping {
		for _, v := range req.Header {
			for i := range v {
				if v[i] == token {
					v[i] = replacement
				}
			}
		}
	}

	return req, nil
}

func replaceReader(mapping map[string]string, r io.Reader) {
}

func replaceString(mapping map[string]string, str string) string {
	for token, replacement := range mapping {
		str = strings.ReplaceAll(str, token, replacement)
	}
	return str
}
