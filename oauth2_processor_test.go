package tokenizer

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/oauth2"
)

func TestOauth2Processor(t *testing.T) {
	appServer := httptest.NewTLSServer(echo)
	defer appServer.Close()
	upstreamTrust.AddCert(appServer.Certificate())

	u, err := url.Parse(appServer.URL)
	assert.NoError(t, err)
	u.Scheme = "http"
	appURL := u.String()

	var (
		lastToken oauth2.Token
		nextToken *oauth2.Token
	)

	refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&lastToken))
		assert.NoError(t, json.NewEncoder(w).Encode(nextToken))
	}))
	defer refreshServer.Close()

	var (
		pub, priv, _ = box.GenerateKey(rand.Reader)
		sealKey      = hex.EncodeToString(pub[:])
		openKey      = hex.EncodeToString(priv[:])
	)

	auth := "trustno1"
	accessToken := "my-access-token"
	refreshToken := "my-refresh-token"
	expiry := time.Now().Add(time.Hour)

	var (
		token  *oauth2.Token
		pConf  *OAuth2ProcessorConfig
		secret *Secret
		sealed string
	)
	makeSealed := func() {
		token = &oauth2.Token{AccessToken: accessToken, RefreshToken: refreshToken, Expiry: expiry}
		pConf = &OAuth2ProcessorConfig{RefreshURL: refreshServer.URL, Token: token}
		secret = &Secret{AuthConfig: NewBearerAuthConfig(auth), ProcessorConfig: pConf}
		var err error
		sealed, err = secret.Seal(sealKey)
		assert.NoError(t, err)
	}

	tkz := NewTokenizer(openKey)
	tkz.ProxyHttpServer.Verbose = true

	tkzServer := httptest.NewServer(tkz)
	defer tkzServer.Close()

	req, err := http.NewRequest(http.MethodPost, appURL, nil)
	assert.NoError(t, err)

	// happy path with access token that isn't expiring soon
	makeSealed()
	client, err := Client(tkzServer.URL, WithAuth(auth), WithSecret(sealed, nil))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", accessToken)}},
		Body:    "",
	}, doEcho(t, client, req))

	// happy path with token that's expiring soon
	nextAccessToken := "next-access-token"
	nextRefreshToken := "next-refresh-token"
	nextExpiry := time.Now().Add(time.Hour)
	nextToken = &oauth2.Token{AccessToken: nextAccessToken, RefreshToken: nextRefreshToken, Expiry: nextExpiry}

	expiry = time.Now().Add(oauth2RefreshThreshold - 1).UTC()
	makeSealed()
	client, err = Client(tkzServer.URL, WithAuth(auth), WithSecret(sealed, nil))
	assert.NoError(t, err)
	assert.Equal(t, &echoResponse{
		Headers: http.Header{"Authorization": {fmt.Sprintf("Bearer %s", nextAccessToken)}},
		Body:    "",
	}, doEcho(t, client, req))
	assert.Equal(t, *token, lastToken)
}
