package tokenizer

import (
	"bufio"
	"bytes"
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
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/sirupsen/logrus"
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

	// t.Log(sealKey)
	// t.Log(openKey)
	// t.Fatal()

	siAuth := "trustno1"
	siToken := "supersecret"
	si, err := (&Secret{AuthConfig: NewBearerAuthConfig(siAuth), ProcessorConfig: &InjectProcessorConfig{siToken}}).Seal(sealKey)
	assert.NoError(t, err)

	sihAuth := "secreter"
	sihKey := []byte("trustno2")
	sih, err := (&Secret{AuthConfig: NewBearerAuthConfig(sihAuth), ProcessorConfig: &InjectHMACProcessorConfig{Key: sihKey, Hash: "sha256"}}).Seal(sealKey)
	assert.NoError(t, err)

	rhAuth := "require-host auth"
	rhToken := "require-host secret"
	srh, err := (&Secret{AuthConfig: NewBearerAuthConfig(rhAuth), ProcessorConfig: &InjectProcessorConfig{rhToken}, RequestValidators: []RequestValidator{AllowHosts(appHost)}}).Seal(sealKey)
	assert.NoError(t, err)

	tkz := NewTokenizer(openKey)
	tkz.ProxyHttpServer.Verbose = true

	tkzServer := httptest.NewServer(tkz)
	defer tkzServer.Close()

	client, err := Client(tkzServer.URL)
	assert.NoError(t, err)

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

	// no auth
	client, err = Client(tkzServer.URL, WithSecret(si, nil))
	assert.NoError(t, err)
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

	// bad auth
	client, err = Client(tkzServer.URL, WithSecret(si, nil), WithAuth("bogus"))
	assert.NoError(t, err)
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

	// happy path
	client, err = Client(tkzServer.URL, WithAuth(siAuth), WithSecret(si, nil))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", siToken)}},
		Body:    "",
	}, doEcho(t, client, req))

	// Inject dst param
	client, err = Client(tkzServer.URL, WithAuth(siAuth), WithSecret(si, map[string]string{ParamDst: "Foo"}))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Foo": {fmt.Sprintf("Bearer %s", siToken)}},
		Body:    "",
	}, doEcho(t, client, req))

	// Inject fmt param
	client, err = Client(tkzServer.URL, WithAuth(siAuth), WithSecret(si, map[string]string{ParamFmt: "Other %s"}))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("Other %s", siToken)}},
		Body:    "",
	}, doEcho(t, client, req))

	// InjectHMAC - sign request body
	client, err = Client(tkzServer.URL, WithAuth(sihAuth), WithSecret(sih, nil))
	assert.NoError(t, err)
	req.Body = io.NopCloser(bytes.NewReader([]byte("foo")))
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %x", hmacSHA256(t, sihKey, "foo"))}},
		Body:    "foo",
	}, doEcho(t, client, req))

	// InjectHMAC - sign param
	client, err = Client(tkzServer.URL, WithAuth(sihAuth), WithSecret(sih, map[string]string{ParamPayload: "my payload"}))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %x", hmacSHA256(t, sihKey, "my payload"))}},
		Body:    "",
	}, doEcho(t, client, req))

	// InjectHMAC - dst param
	client, err = Client(tkzServer.URL, WithAuth(sihAuth), WithSecret(sih, map[string]string{ParamDst: "Foo"}))
	assert.NoError(t, err)
	req.Body = io.NopCloser(bytes.NewReader([]byte("foo")))
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Foo": {fmt.Sprintf("Bearer %x", hmacSHA256(t, sihKey, "foo"))}},
		Body:    "foo",
	}, doEcho(t, client, req))

	// InjectHMAC - fmt param
	client, err = Client(tkzServer.URL, WithAuth(sihAuth), WithSecret(sih, map[string]string{ParamFmt: "%X"}))
	assert.NoError(t, err)
	req.Body = io.NopCloser(bytes.NewReader([]byte("foo")))
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("%X", hmacSHA256(t, sihKey, "foo"))}},
		Body:    "foo",
	}, doEcho(t, client, req))

	// good auth + bad auth
	client, err = Client(tkzServer.URL, WithAuth(siAuth), WithSecret(si, nil), WithAuth("bogus"))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", siToken)}},
		Body:    "",
	}, doEcho(t, client, req))

	// one good auth, one missing auth
	client, err = Client(tkzServer.URL, WithAuth(siAuth), WithSecret(si, nil), WithSecret(sih, nil))
	assert.NoError(t, err)
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

	// allowed hosts - good
	client, err = Client(tkzServer.URL, WithAuth(rhAuth), WithSecret(srh, nil))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", rhToken)}},
		Body:    "",
	}, doEcho(t, client, req))

	// allowed hosts - good
	badHostReq, err := http.NewRequest(http.MethodPost, "http://127.0.0.1.nip.io:"+appPort, nil)
	assert.NoError(t, err)
	badHostReq.URL.Host = "127.0.0.1.nip.io:" + badHostReq.URL.Port()
	client, err = Client(tkzServer.URL, WithAuth(rhAuth), WithSecret(srh, nil))
	assert.NoError(t, err)
	resp, err = client.Do(badHostReq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// CONNECT proxy
	conn, err := net.Dial("tcp", tkzServer.Listener.Addr().String())
	connreader := bufio.NewReader(conn)
	assert.NoError(t, err)
	creq, err := http.NewRequest(http.MethodConnect, appURL, nil)
	assert.NoError(t, err)
	mergeHeader(creq.Header, WithAuth(siAuth))
	mergeHeader(creq.Header, WithSecret(si, nil))
	assert.NoError(t, creq.Write(conn))
	resp, err = http.ReadResponse(connreader, creq)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// request via CONNECT proxy
	client = &http.Client{Transport: &http.Transport{Dial: func(network, addr string) (net.Conn, error) { return conn, nil }}}
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", siToken)}},
		Body:    "",
	}, doEcho(t, client, req))
}

func randomName(prefix string) string {
	rawName := make([]byte, 8)
	io.ReadFull(rand.Reader, rawName)
	return fmt.Sprintf("%s-%x", prefix, rawName)
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
