package tokenizer

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/sirupsen/logrus"
	"github.com/superfly/flysrc-go"
	"github.com/superfly/macaroon"
	tkmac "github.com/superfly/tokenizer/macaroon"
	"golang.org/x/crypto/nacl/box"
)

func TestTokenizer(t *testing.T) {
	appServer := httptest.NewTLSServer(echo)
	defer appServer.Close()

	u, err := url.Parse(appServer.URL)
	assert.NoError(t, err)
	u.Scheme = "http"
	appURL := u.String()
	appHost := u.Host
	appPort := u.Port()

	var (
		pub, priv, _ = box.GenerateKey(rand.Reader)
		sealKey      = hex.EncodeToString(pub[:])
		openKey      = hex.EncodeToString(priv[:])
	)

	flysrcParser, err := flysrc.New(
		flysrc.WithPubkey(flySrcVerifyKey(t)),
		flysrc.WithFlyProxyNet(&net.IPNet{
			IP:   net.ParseIP("127.0.0.1"),
			Mask: net.CIDRMask(16, 32),
		}),
	)

	assert.NoError(t, err)

	// we can build a server without a fly src parser
	tkz := NewTokenizer(openKey)
	assert.True(t, tkz != nil)

	tkz = NewTokenizer(openKey, WithFlysrcParser(flysrcParser))
	tkz.ProxyHttpServer.Verbose = true

	tkzServer := httptest.NewServer(tkz)
	defer tkzServer.Close()

	req, err := http.NewRequest(http.MethodPost, appURL+"/foo", nil)
	assert.NoError(t, err)

	auth := "trustno1"
	token := "supersecret"
	secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: &InjectProcessorConfig{Token: token}}).Seal(sealKey)
	assert.NoError(t, err)

	// TLS error (proxy doesn't trust upstream)
	client, err := Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
	assert.NoError(t, err)
	resp, err := client.Get(appURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

	// make proxy trust upstream
	UpstreamTrust.AddCert(appServer.Certificate())

	// error if no secrets
	client, err = Client(tkzServer.URL, WithAuth(auth))
	assert.NoError(t, err)
	resp, err = client.Get(appURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	t.Run("inject processor", func(t *testing.T) {
		auth := "trustno1"
		token := "supersecret"
		secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: &InjectProcessorConfig{Token: token}}).Seal(sealKey)
		assert.NoError(t, err)

		// no auth
		client, err = Client(tkzServer.URL, WithSecret(secret, nil))
		assert.NoError(t, err)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

		// bad auth
		client, err = Client(tkzServer.URL, WithSecret(secret, nil), WithAuth("bogus"))
		assert.NoError(t, err)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

		// happy path
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// Inject dst param
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, map[string]string{ParamDst: "Foo"}))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Foo": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// Inject fmt param
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, map[string]string{ParamFmt: "Other %s"}))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Other %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// CONNECT proxy
		conn, err := net.Dial("tcp", tkzServer.Listener.Addr().String())
		connreader := bufio.NewReader(conn)
		assert.NoError(t, err)
		creq, err := http.NewRequest(http.MethodConnect, appURL, nil)
		assert.NoError(t, err)
		opts := clientOptions{}
		WithAuth(auth)(&opts)
		WithSecret(secret, nil)(&opts)
		mergeHeader(creq.Header, opts.headers)
		assert.NoError(t, creq.Write(conn))
		resp, err = http.ReadResponse(connreader, creq)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// request via CONNECT proxy
		client = &http.Client{Transport: &http.Transport{Dial: func(network, addr string) (net.Conn, error) { return conn, nil }}}
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// good auth + bad auth
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil), WithAuth("bogus"))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// one good auth, one missing auth
		otherSecret, err := (&Secret{AuthConfig: NewBearerAuthConfig("other"), ProcessorConfig: &InjectProcessorConfig{Token: token}}).Seal(sealKey)
		assert.NoError(t, err)
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil), WithSecret(otherSecret, nil))
		assert.NoError(t, err)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	})

	t.Run("inject hmac processor", func(t *testing.T) {
		auth := "secreter"
		key := []byte("trustno2")
		secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: &InjectHMACProcessorConfig{Key: key, Hash: "sha256"}}).Seal(sealKey)
		assert.NoError(t, err)

		// InjectHMAC - sign request body
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		req.Body = io.NopCloser(bytes.NewReader([]byte("foo")))
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %x", hmacSHA256(t, key, "foo"))}},
			Body:    "foo",
		}, doEcho(t, client, req))

		// InjectHMAC - sign param
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, map[string]string{ParamPayload: "my payload"}))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %x", hmacSHA256(t, key, "my payload"))}},
			Body:    "",
		}, doEcho(t, client, req))

		// InjectHMAC - dst param
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, map[string]string{ParamDst: "Foo"}))
		assert.NoError(t, err)
		req.Body = io.NopCloser(bytes.NewReader([]byte("foo")))
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Foo": {fmt.Sprintf("Bearer %x", hmacSHA256(t, key, "foo"))}},
			Body:    "foo",
		}, doEcho(t, client, req))

		// InjectHMAC - fmt param
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, map[string]string{ParamFmt: "%X"}))
		assert.NoError(t, err)
		req.Body = io.NopCloser(bytes.NewReader([]byte("foo")))
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("%X", hmacSHA256(t, key, "foo"))}},
			Body:    "foo",
		}, doEcho(t, client, req))
	})

	t.Run("oauth processor", func(t *testing.T) {
		auth := "secret-oauth-auth"
		token := &OAuthToken{AccessToken: "access-token", RefreshToken: "refresh-token"}
		secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: &OAuthProcessorConfig{token}}).Seal(sealKey)
		assert.NoError(t, err)

		// OAuth - access token (implicit)
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token.AccessToken)}},
			Body:    "",
		}, doEcho(t, client, req))

		// OAuth - access token (explicit)
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, map[string]string{ParamSubtoken: SubtokenAccess}))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token.AccessToken)}},
			Body:    "",
		}, doEcho(t, client, req))

		// OAuth - refresh token (explicit)
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, map[string]string{ParamSubtoken: SubtokenRefresh}))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token.RefreshToken)}},
			Body:    "",
		}, doEcho(t, client, req))
	})

	t.Run("allow-hosts validator", func(t *testing.T) {
		auth := "allow-host auth"
		token := "allow-host secret"
		secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: &InjectProcessorConfig{Token: token}, RequestValidators: []RequestValidator{AllowHosts(appHost)}}).Seal(sealKey)
		assert.NoError(t, err)

		// allowed hosts - good
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// allowed hosts - bad
		badHostReq, err := http.NewRequest(http.MethodPost, "http://127.0.0.1.nip.io:"+appPort, nil)
		assert.NoError(t, err)
		badHostReq.URL.Host = "127.0.0.1.nip.io:" + badHostReq.URL.Port()
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		resp, err = client.Do(badHostReq)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("allow-host-pattern validator", func(t *testing.T) {
		auth := "allow-host-pattern auth"
		token := "allow-host-pattern secret"
		secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: &InjectProcessorConfig{Token: token}, RequestValidators: []RequestValidator{AllowHostPattern(regexp.MustCompile("^" + appHost + "$"))}}).Seal(sealKey)
		assert.NoError(t, err)

		// allowed host pattern - good
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// allowed host pattern - bad
		badHostReq, err := http.NewRequest(http.MethodPost, "http://127.0.0.1.nip.io:"+appPort, nil)
		assert.NoError(t, err)
		badHostReq.URL.Host = "127.0.0.1.nip.io:" + badHostReq.URL.Port()
		badHostReq, err = http.NewRequest(http.MethodPost, "http://127.0.0.1.nip.io:"+appPort, nil)
		assert.NoError(t, err)
		badHostReq.URL.Host = "127.0.0.1.nip.io:" + badHostReq.URL.Port()
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		resp, err = client.Do(badHostReq)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("dst processor", func(t *testing.T) {
		auth := "trustno1"
		token := "supersecret"
		secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: &InjectProcessorConfig{Token: token, DstProcessor: DstProcessor{AllowedDst: []string{"asdf", "qwer"}}}}).Seal(sealKey)
		assert.NoError(t, err)

		// default dst pulled from allow-list
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Asdf": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// can specify non-normalized allowed value
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, map[string]string{ParamDst: "qWeR"}))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Qwer": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// disallowed dst
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, map[string]string{ParamDst: "zxcv"}))
		assert.NoError(t, err)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("macaroon auth", func(t *testing.T) {
		key := macaroon.NewSigningKey()
		auth := NewMacaroonAuthConfig(key)
		token := "supersecret"
		secret, err := (&Secret{AuthConfig: auth, ProcessorConfig: &InjectProcessorConfig{Token: token}}).Seal(sealKey)
		assert.NoError(t, err)

		// empty macaroon - good
		m, err := auth.Macaroon()
		assert.NoError(t, err)
		client, err := Client(tkzServer.URL, WithAuth(m), WithSecret(secret, nil))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// request matches caveats - good
		m, err = auth.Macaroon(
			tkmac.ConstrainRequestMethod(http.MethodPost),
			tkmac.ConstrainRequestHost(appHost),
			tkmac.ConstrainRequestPath("/foo"),
		)
		assert.NoError(t, err)
		client, err = Client(tkzServer.URL, WithAuth(m), WithSecret(secret, nil))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))

		// method mismatch - bad
		m, err = auth.Macaroon(tkmac.ConstrainRequestMethod(http.MethodGet))
		assert.NoError(t, err)
		client, err = Client(tkzServer.URL, WithAuth(m), WithSecret(secret, nil))
		assert.NoError(t, err)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

		// host mismatch - bad
		m, err = auth.Macaroon(tkmac.ConstrainRequestHost("fly.io"))
		assert.NoError(t, err)
		client, err = Client(tkzServer.URL, WithAuth(m), WithSecret(secret, nil))
		assert.NoError(t, err)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

		// paht mismatch - bad
		m, err = auth.Macaroon(tkmac.ConstrainRequestPath("/bar"))
		assert.NoError(t, err)
		client, err = Client(tkzServer.URL, WithAuth(m), WithSecret(secret, nil))
		assert.NoError(t, err)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	})

	t.Run("fly-src auth", func(t *testing.T) {
		const (
			headerFlySrc          = "Fly-Src"
			headerFlySrcSignature = "Fly-Src-Signature"
		)

		priv := flySrcSignKey(t)

		auth := NewFlySrcAuthConfig(AllowlistFlySrcOrgs("foo"))
		secret, err := (&Secret{AuthConfig: auth, ProcessorConfig: &InjectProcessorConfig{Token: token}}).Seal(sealKey)
		assert.NoError(t, err)

		// Good
		fs := &flysrc.FlySrc{Org: "foo", App: "bar", Instance: "baz", Timestamp: time.Now().Truncate(time.Second)}
		hdrSrc := fs.String()
		hdrSig := fs.Sign(priv)

		assert.NoError(t, err)
		client, err := Client(tkzServer.URL, withHeaders(http.Header{
			headerFlySrc:          []string{hdrSrc},
			headerFlySrcSignature: []string{hdrSig},
		}), WithSecret(secret, nil))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{
				"Authorization":       {fmt.Sprintf("Bearer %s", token)},
				headerFlySrc:          []string{hdrSrc},
				headerFlySrcSignature: []string{hdrSig},
			},
			Body: "",
		}, doEcho(t, client, req))

		// Bad, the same request fails, without panic, if flysrc parser is nil
		parser := tkz.flysrcParser
		tkz.flysrcParser = nil
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
		tkz.flysrcParser = parser

		// Bad org
		fs = &flysrc.FlySrc{Org: "WRONG!", App: "bar", Instance: "baz", Timestamp: time.Now().Truncate(time.Second)}
		hdrSrc = fs.String()
		hdrSig = fs.Sign(priv)

		assert.NoError(t, err)
		client, err = Client(tkzServer.URL, withHeaders(http.Header{
			headerFlySrc:          []string{hdrSrc},
			headerFlySrcSignature: []string{hdrSig},
		}), WithSecret(secret, nil))
		assert.NoError(t, err)

		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

		// Missing signature
		fs = &flysrc.FlySrc{Org: "foo", App: "bar", Instance: "baz", Timestamp: time.Now().Truncate(time.Second)}
		hdrSrc = fs.String()

		assert.NoError(t, err)
		client, err = Client(tkzServer.URL, withHeaders(http.Header{headerFlySrc: []string{hdrSrc}}), WithSecret(secret, nil))
		assert.NoError(t, err)

		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	})

	t.Run("MultiProcessor", func(t *testing.T) {
		auth := "trustno1"
		token1 := "supersecret"
		token2 := "extrasecret"
		pc := &MultiProcessorConfig{
			&InjectProcessorConfig{Token: token1, DstProcessor: DstProcessor{Dst: "A"}},
			&InjectProcessorConfig{Token: token2, DstProcessor: DstProcessor{Dst: "B"}},
		}
		secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: pc}).Seal(sealKey)
		assert.NoError(t, err)

		// no auth
		client, err = Client(tkzServer.URL, WithSecret(secret, nil))
		assert.NoError(t, err)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

		// bad auth
		client, err = Client(tkzServer.URL, WithSecret(secret, nil), WithAuth("bogus"))
		assert.NoError(t, err)
		resp, err = client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

		// happy path
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{
				"A": {fmt.Sprintf("Bearer %s", token1)},
				"B": {fmt.Sprintf("Bearer %s", token2)},
			},
			Body: "",
		}, doEcho(t, client, req))
	})
}

func withHeaders(h http.Header) ClientOption {
	return func(co *clientOptions) {
		if co.headers == nil {
			co.headers = make(http.Header)
		}
		for k, v := range h {
			co.headers[k] = v
		}
	}

}

type echoResponse struct {
	Headers http.Header
	Body    string
}

var echo http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed read", 500)
		return
	}
	r.Header.Del("User-Agent")
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Content-Length")
	r.Header.Del("Connection")
	if err := json.NewEncoder(w).Encode(&echoResponse{Headers: r.Header, Body: string(body)}); err != nil {
		logrus.WithError(err).Panicf("failed writing response")
	}
})

func doEcho(t testing.TB, c *http.Client, r *http.Request) *echoResponse {
	t.Helper()
	resp, err := c.Do(r)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	j := echoResponse{Headers: make(http.Header)}
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&j))
	return &j
}

func hmacSHA256(t testing.TB, key []byte, msg string) []byte {
	hm := hmac.New(sha256.New, key)
	_, err := hm.Write([]byte(msg))
	assert.NoError(t, err)
	return hm.Sum(nil)
}

var (
	_setupFlySrcSignKey sync.Once
	_flySrcSignKey      ed25519.PrivateKey
	_flySrcVerifyKey    ed25519.PublicKey
)

func flySrcSignKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	var err error

	_setupFlySrcSignKey.Do(func() {
		_flySrcVerifyKey, _flySrcSignKey, err = ed25519.GenerateKey(nil)
	})

	assert.NoError(t, err)
	assert.NotZero(t, _flySrcSignKey)
	return _flySrcSignKey
}

func flySrcVerifyKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	_ = flySrcSignKey(t)
	return _flySrcVerifyKey
}

func TestTokenizerHeaders(t *testing.T) {
	appServer := httptest.NewTLSServer(echo)
	defer appServer.Close()

	u, err := url.Parse(appServer.URL)
	assert.NoError(t, err)
	u.Scheme = "http"
	appURL := u.String()

	var (
		pub, priv, _ = box.GenerateKey(rand.Reader)
		sealKey      = hex.EncodeToString(pub[:])
		openKey      = hex.EncodeToString(priv[:])
	)

	UpstreamTrust.AddCert(appServer.Certificate())

	t.Run("default header Proxy-Tokenizer", func(t *testing.T) {
		origHeaders := TokenizerHeaders
		defer func() { TokenizerHeaders = origHeaders }()

		// Set default to only Proxy-Tokenizer
		TokenizerHeaders = []string{"Proxy-Tokenizer"}

		tkz := NewTokenizer(openKey)
		tkzServer := httptest.NewServer(tkz)
		defer tkzServer.Close()

		auth := "trustno1"
		token := "supersecret"
		secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: &InjectProcessorConfig{Token: token}}).Seal(sealKey)
		assert.NoError(t, err)

		// Request with Proxy-Tokenizer header should work
		client, err := Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, appURL, nil)
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))
	})

	t.Run("custom headers with priority", func(t *testing.T) {
		origHeaders := TokenizerHeaders
		defer func() { TokenizerHeaders = origHeaders }()

		// Configure multiple headers in priority order
		TokenizerHeaders = []string{"X-Custom-Auth", "X-Api-Key", "Proxy-Tokenizer"}

		tkz := NewTokenizer(openKey)
		tkzServer := httptest.NewServer(tkz)
		defer tkzServer.Close()

		auth := "trustno1"
		token := "supersecret"
		secret, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: &InjectProcessorConfig{Token: token}}).Seal(sealKey)
		assert.NoError(t, err)

		// Request with X-Custom-Auth header (highest priority) should work
		client, err := Client(tkzServer.URL, WithAuth(auth), withHeaders(http.Header{
			"X-Custom-Auth": {secret},
		}))
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, appURL, nil)
		assert.NoError(t, err)
		resp := doEcho(t, client, req)
		// Should inject the token as Authorization header
		assert.Equal(t, fmt.Sprintf("Bearer %s", token), resp.Headers.Get("Authorization"))
		// X-Custom-Auth is not filtered by default, so it passes through
		assert.True(t, len(resp.Headers.Get("X-Custom-Auth")) > 0)

		// Request with X-Api-Key header (second priority) should work
		client, err = Client(tkzServer.URL, WithAuth(auth), withHeaders(http.Header{
			"X-Api-Key": {secret},
		}))
		assert.NoError(t, err)
		req, err = http.NewRequest(http.MethodGet, appURL, nil)
		assert.NoError(t, err)
		resp = doEcho(t, client, req)
		assert.Equal(t, fmt.Sprintf("Bearer %s", token), resp.Headers.Get("Authorization"))
		assert.True(t, len(resp.Headers.Get("X-Api-Key")) > 0)

		// Request with Proxy-Tokenizer header (lowest priority) should work
		client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(secret, nil))
		assert.NoError(t, err)
		req, err = http.NewRequest(http.MethodGet, appURL, nil)
		assert.NoError(t, err)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", token)}},
			Body:    "",
		}, doEcho(t, client, req))
	})

	t.Run("first matching header takes precedence", func(t *testing.T) {
		origHeaders := TokenizerHeaders
		defer func() { TokenizerHeaders = origHeaders }()

		// Configure multiple headers
		TokenizerHeaders = []string{"X-Custom-Auth", "X-Api-Key"}

		tkz := NewTokenizer(openKey)
		tkzServer := httptest.NewServer(tkz)
		defer tkzServer.Close()

		auth1 := "auth1"
		token1 := "token1"
		secret1, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth1), ProcessorConfig: &InjectProcessorConfig{Token: token1}}).Seal(sealKey)
		assert.NoError(t, err)

		auth2 := "auth2"
		token2 := "token2"
		secret2, err := (&Secret{AuthConfig: NewBearerAuthConfig(auth2), ProcessorConfig: &InjectProcessorConfig{Token: token2}}).Seal(sealKey)
		assert.NoError(t, err)

		// When both headers are present, X-Custom-Auth takes precedence
		client, err := Client(tkzServer.URL, WithAuth(auth1), withHeaders(http.Header{
			"X-Custom-Auth": {secret1},
			"X-Api-Key":     {secret2},
		}))
		assert.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, appURL, nil)
		assert.NoError(t, err)
		// Should use token1 from X-Custom-Auth, not token2 from X-Api-Key
		resp := doEcho(t, client, req)
		assert.Equal(t, fmt.Sprintf("Bearer %s", token1), resp.Headers.Get("Authorization"))
		// Both headers pass through (not filtered by default)
		assert.True(t, len(resp.Headers.Get("X-Custom-Auth")) > 0)
		assert.True(t, len(resp.Headers.Get("X-Api-Key")) > 0)
	})
}
