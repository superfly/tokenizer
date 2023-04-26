package tokenizer

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/sirupsen/logrus"
)

func TestTokenizer(t *testing.T) {
	var (
		s1Key      = "/foo"
		s1Secret   = "trustno1"
		s1Auth     = "myproxysecret"
		s1AuthName = tmpAuthorizer(authorizerFromRawSecret(s1Auth))

		s2Key      = "/bar"
		s2Secret   = "trustno2"
		s2Auth     = "deadbeef"
		s2AuthName = tmpAuthorizer(authorizerFromRawSecret(s2Auth))

		inject     = tmpProcessorFactory(Inject)
		injectHMAC = tmpProcessorFactory(InjectHMAC)
		err        error
	)

	appServer := httptest.NewTLSServer(echo)
	defer appServer.Close()

	tkz := NewTokenizer(StaticSecretStore{
		s1Key: Secret{
			SecretKeyAuthorizer: s1AuthName,
			SecretKeyProcessor:  inject,
			SecretKeySecret:     s1Secret,
		},
		s2Key: Secret{
			SecretKeyAuthorizer: s2AuthName,
			SecretKeyProcessor:  injectHMAC,
			SecretKeySecret:     s2Secret,
			SecretKeyHash:       strconv.FormatInt(int64(crypto.SHA256), 10),
		},
	})
	tkz.ProxyHttpServer.Verbose = true

	tkzServer := httptest.NewTLSServer(tkz)
	defer tkzServer.Close()

	// make client trust proxy
	downstreamTrust.AddCert(tkzServer.Certificate())

	client, err := Client(tkzServer.URL)
	assert.NoError(t, err)

	u, err := url.Parse(appServer.URL)
	assert.NoError(t, err)
	u.Scheme = "http"
	appURL := u.String()

	req, err := http.NewRequest(http.MethodPost, appURL, nil)
	assert.NoError(t, err)

	// TLS error (proxy doesn't trust upstream)
	resp, err := client.Get(appURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	// make proxy trust upstream
	upstreamTrust.AddCert(appServer.Certificate())

	// no proxy auth or secrets (good)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{},
		Body:    "",
	}, doEcho(t, client, req))

	// bad proxy auth doesn't matter if no secrets are used
	client, err = Client(tkzServer.URL, WithAuth("bogus"))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{}, // proxy auth isn't leaked downstream
		Body:    "",
	}, doEcho(t, client, req))

	// secret doesn't exist
	client, err = Client(tkzServer.URL, WithAuth("bogus"), WithSecret("/bad", nil))
	assert.NoError(t, err)
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// no auth
	client, err = Client(tkzServer.URL, WithSecret(s1Key, nil))
	assert.NoError(t, err)
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

	// bad auth
	client, err = Client(tkzServer.URL, WithSecret(s1Key, nil), WithAuth("bogus"))
	assert.NoError(t, err)
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

	// happy path
	client, err = Client(tkzServer.URL, WithAuth(s1Auth), WithSecret(s1Key, nil))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {"trustno1"}},
		Body:    "",
	}, doEcho(t, client, req))

	// Inject dst param
	client, err = Client(tkzServer.URL, WithAuth(s1Auth), WithSecret(s1Key, map[string]string{ParamDst: "Foo"}))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Foo": {"trustno1"}},
		Body:    "",
	}, doEcho(t, client, req))

	// Inject fmt param
	client, err = Client(tkzServer.URL, WithAuth(s1Auth), WithSecret(s1Key, map[string]string{ParamFmt: "Bearer %s"}))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {"Bearer trustno1"}},
		Body:    "",
	}, doEcho(t, client, req))

	// InjectHMAC - sign request body
	client, err = Client(tkzServer.URL, WithAuth(s2Auth), WithSecret(s2Key, nil))
	assert.NoError(t, err)
	req.Body = io.NopCloser(bytes.NewReader([]byte("foo")))
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("%x", hmacSHA256(t, s2Secret, "foo"))}},
		Body:    "foo",
	}, doEcho(t, client, req))

	// InjectHMAC - sign param
	client, err = Client(tkzServer.URL, WithAuth(s2Auth), WithSecret(s2Key, map[string]string{ParamPayload: "my payload"}))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("%x", hmacSHA256(t, s2Secret, "my payload"))}},
		Body:    "",
	}, doEcho(t, client, req))

	// InjectHMAC - dst param
	client, err = Client(tkzServer.URL, WithAuth(s2Auth), WithSecret(s2Key, map[string]string{ParamDst: "Foo"}))
	assert.NoError(t, err)
	req.Body = io.NopCloser(bytes.NewReader([]byte("foo")))
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Foo": {fmt.Sprintf("%x", hmacSHA256(t, s2Secret, "foo"))}},
		Body:    "foo",
	}, doEcho(t, client, req))

	// InjectHMAC - fmt param
	client, err = Client(tkzServer.URL, WithAuth(s2Auth), WithSecret(s2Key, map[string]string{ParamFmt: "%X"}))
	assert.NoError(t, err)
	req.Body = io.NopCloser(bytes.NewReader([]byte("foo")))
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("%X", hmacSHA256(t, s2Secret, "foo"))}},
		Body:    "foo",
	}, doEcho(t, client, req))

	// good auth + bad auth
	client, err = Client(tkzServer.URL, WithAuth(s1Auth), WithSecret(s1Key, nil), WithAuth("bogus"))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {"trustno1"}},
		Body:    "",
	}, doEcho(t, client, req))

	// one good auth, one missing auth
	client, err = Client(tkzServer.URL, WithAuth(s1Auth), WithSecret(s1Key, nil), WithSecret(s2Key, nil))
	assert.NoError(t, err)
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
}

func randomName(prefix string) string {
	rawName := make([]byte, 8)
	io.ReadFull(rand.Reader, rawName)
	return fmt.Sprintf("%s-%x", prefix, rawName)
}

func tmpAuthorizer(a Authorizer) string {
	name := randomName("authorizer")
	RegisterAuthorizer(name, a)
	return name
}

func authorizerFromRawSecret(s string) Authorizer {
	d := sha256.Sum256([]byte(s))
	return sharedSecretAuthorizer(hex.EncodeToString(d[:]))
}

func tmpProcessorFactory(pf RequestProcessorFactory) string {
	name := randomName("processor")
	RegisterProcessor(name, pf)
	return name
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

func hmacSHA256(t testing.TB, key, msg string) []byte {
	hm := hmac.New(sha256.New, []byte(key))
	_, err := hm.Write([]byte(msg))
	assert.NoError(t, err)
	return hm.Sum(nil)
}
