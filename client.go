package tokenizer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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

type ClientOption func(*clientOptions)

type clientOptions struct {
	headers   http.Header
	transport *http.Transport
}

func (co *clientOptions) getTransport() *http.Transport {
	if co.transport != nil {
		return co.transport.Clone()
	}
	return http.DefaultTransport.(*http.Transport).Clone()
}

func WithSecret(sealedSecret string, params map[string]string) ClientOption {
	return func(co *clientOptions) {
		if co.headers == nil {
			co.headers = make(http.Header)
		}
		co.headers.Add(headerProxyTokenizer, formatHeaderProxyTokenizer(sealedSecret, params))
	}
}

func WithAuth(auth string) ClientOption {
	return func(co *clientOptions) {
		if co.headers == nil {
			co.headers = make(http.Header)
		}
		co.headers.Add(headerProxyAuthorization, fmt.Sprintf("Bearer %s", auth))
	}
}

func WithTransport(t *http.Transport) ClientOption {
	return func(co *clientOptions) {
		co.transport = t
	}
}

func Client(proxyURL string, opts ...ClientOption) (*http.Client, error) {
	t, err := Transport(proxyURL, opts...)
	if err != nil {
		return nil, err
	}

	return &http.Client{Transport: t}, nil
}

func Transport(proxyURL string, opts ...ClientOption) (http.RoundTripper, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	copts := &clientOptions{}
	for _, o := range opts {
		o(copts)
	}

	t := copts.getTransport()
	t.Proxy = http.ProxyURL(u)
	t.TLSClientConfig = &tls.Config{RootCAs: downstreamTrust}
	// t.ForceAttemptHTTP2 = true

	return forceHTTP(headerInjector(t, copts.headers)), nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rtf roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rtf(req)
}

func forceHTTP(t http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if strings.EqualFold(r.URL.Scheme, "https") {
			r = r.Clone(r.Context())
			r.URL.Scheme = "http"
		}
		return t.RoundTrip(r)
	})
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
