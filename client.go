package tokenizer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

var downstreamTrust *x509.CertPool

func init() {
	var err error
	downstreamTrust, err = x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
}

type ClientOption http.Header

func WithSecret(key string, params map[string]string) ClientOption {
	return ClientOption(http.Header{headerProxyTokenizer: {formatHeaderProxyTokenizer(key, params)}})
}

func WithAuth(auth string) ClientOption {
	return ClientOption(http.Header{headerProxyAuthorization: {fmt.Sprintf("Bearer %s", auth)}})
}

func Client(proxyURL string, opts ...ClientOption) (*http.Client, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	hdrs := make(http.Header, len(opts))
	for _, o := range opts {
		mergeHeader(hdrs, o)
	}

	var t http.RoundTripper
	t = &http.Transport{
		Proxy:             http.ProxyURL(u),
		TLSClientConfig:   &tls.Config{RootCAs: downstreamTrust},
		ForceAttemptHTTP2: true,
	}
	t = headerInjector(t, hdrs)

	return &http.Client{Transport: t}, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rtf roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rtf(req)
}

type ctxKey string

var ctxKeyInjected ctxKey = "injected"

func headerInjector(t http.RoundTripper, h http.Header) http.RoundTripper {
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		// avoid duplicate injections on retries, etc...
		if r.Context().Value(ctxKeyInjected) == nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxKeyInjected, true))
			r.Header = maps.Clone(r.Header)
			mergeHeader(r.Header, h)
		}
		return t.RoundTrip(r)
	})
}

func mergeHeader(dst, src map[string][]string) {
	for k, vs := range src {
		dst[k] = append(dst[k], vs...)
		slices.Sort(dst[k])
		dst[k] = slices.Compact(dst[k])
	}
}
