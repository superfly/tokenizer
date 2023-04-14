package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

type fakeSecretStore map[string]map[string]string

var _ secretStore = make(fakeSecretStore)

func (fss fakeSecretStore) get(_ context.Context, path string) (map[string]string, error) {
	data, ok := fss[path]
	if !ok {
		return nil, errNotFound
	}
	return data, nil
}

func TestTokenizer(t *testing.T) {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "custom-header=%s", r.Header.Get("custom-header"))
	})
	appServer := httptest.NewTLSServer(app)
	defer appServer.Close()

	ss := fakeSecretStore{
		"/foo": map[string]string{
			dataAuthType: authTypeSecret,
			dataSecret:   "supersecret",
		},
	}

	tkz := newTokenizer(ss)
	tkz.ProxyHttpServer.Tr.TLSClientConfig.RootCAs = x509.NewCertPool()
	tkz.ProxyHttpServer.Tr.TLSClientConfig.RootCAs.AddCert(appServer.Certificate())
	tkz.ProxyHttpServer.Verbose = true

	tkzServer := httptest.NewTLSServer(tkz)
	defer tkzServer.Close()

	baseClient = tkzServer.Client()

	client, err := NewClient(tkzServer.URL, "my secret", map[string]string{"deadbeef": "/foo"})
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, appServer.URL, nil)
	assert.NoError(t, err)
	req.Header.Set("custom-header", "deadbeef")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, []byte("custom-header=supersecret"), body)
}
