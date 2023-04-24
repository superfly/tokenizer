package tokenizer

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/sirupsen/logrus"
)

func TestTokenizer(t *testing.T) {
	appServer := httptest.NewTLSServer(echo)
	defer appServer.Close()

	var (
		secretSecret  = "trustno1"
		proxySecret   = "myproxysecret"
		authzName     = tmpAuthorizer(authorizerFromRawSecret(proxySecret))
		processorName = tmpProcessorFactory(InjectBearer)
		err           error
		cerr          ClientError
	)

	tkz := NewTokenizer(StaticSecretStore{"/foo": Secret{
		SecretKeyAuthorizer: authzName,
		SecretKeyProcessor:  processorName,
		SecretKeySecret:     secretSecret,
	}})

	// make tkz trust our app server TLS cert
	tkz.ProxyHttpServer.Tr.TLSClientConfig.RootCAs = x509.NewCertPool()
	tkz.ProxyHttpServer.Tr.TLSClientConfig.RootCAs.AddCert(appServer.Certificate())
	tkz.ProxyHttpServer.Verbose = true

	tkzServer := httptest.NewTLSServer(tkz)
	defer tkzServer.Close()

	client := tkzServer.Client()

	client, err = Client(client, WithProxy(tkzServer.URL))
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, appServer.URL, nil)
	assert.NoError(t, err)

	// no proxy auth or secrets
	assert.Equal(t, &echoResponse{
		Headers: http.Header{},
		Body:    "",
	}, doEcho(t, client, req))

	// bad proxy auth doesn't matter if no secrets are used
	client, err = Client(client, WithProxyAuth("bogus"))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{}, // proxy auth isn't leaked downstream
		Body:    "",
	}, doEcho(t, client, req))

	// secret doesn't exist
	badClient, err := Client(client, WithSecret("/bad", nil))
	assert.NoError(t, err)
	_, err = badClient.Do(req)
	assert.True(t, errors.As(err, &cerr))
	assert.Equal(t, http.StatusNotFound, cerr.Status)

	client, err = Client(client, WithSecret("/foo", nil))
	assert.NoError(t, err)
	_, err = client.Do(req)
	assert.True(t, errors.As(err, &cerr))
	assert.Equal(t, http.StatusUnauthorized, cerr.Status)

	// happy path
	client, err = Client(client, WithProxyAuth(proxySecret))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {"Bearer trustno1"}},
		Body:    "",
	}, doEcho(t, client, req))
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
