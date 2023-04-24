package tokenizer

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type ClientOption func(*http.Transport) error

func WithSecret(key string, params map[string]string) ClientOption {
	hdr := formatHeaderReplace(key, params)
	return func(t *http.Transport) error {
		t.ProxyConnectHeader.Add(headerReplace, hdr)
		return nil
	}
}

func WithProxy(u string) ClientOption {
	return func(t *http.Transport) error {
		baseURL, err := url.Parse(u)
		if err != nil {
			return err
		}

		caURL := baseURL.JoinPath(caPath)
		tmpClient := &http.Client{Transport: t}
		resp, err := tmpClient.Get(caURL.String())
		if err != nil {
			return err
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if t.TLSClientConfig.RootCAs == nil {
			t.TLSClientConfig.RootCAs, err = x509.SystemCertPool()
			if err != nil {
				return err
			}
		} else {
			t.TLSClientConfig.RootCAs = t.TLSClientConfig.RootCAs.Clone()
		}
		if !t.TLSClientConfig.RootCAs.AppendCertsFromPEM(body) {
			return errors.New("no ca certs")
		}

		t.Proxy = http.ProxyURL(baseURL)

		return nil
	}
}

func WithProxyAuth(auth string) ClientOption {
	return func(t *http.Transport) error {
		t.ProxyConnectHeader.Add(headerProxyAuthorization, auth)
		return nil
	}
}

func Client(baseClient *http.Client, opts ...ClientOption) (*http.Client, error) {
	if baseClient == nil {
		baseClient = &http.Client{}
	}

	rt := baseClient.Transport
	if rt == nil {
		rt = &http.Transport{}
	}

	t, ok := rt.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("bad transport: %T", rt)
	}

	t = t.Clone()
	t.ForceAttemptHTTP2 = false

	if t.ProxyConnectHeader == nil {
		t.ProxyConnectHeader = make(http.Header)
	}

	if t.OnProxyConnectResponse == nil {
		t.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
			if res.StatusCode != http.StatusOK {
				if body, err := io.ReadAll(res.Body); err == nil {
					return ClientError{Status: res.StatusCode, Msg: string(body)}
				}
				return ClientError{Status: res.StatusCode}
			}
			return nil
		}
	}

	for _, opt := range opts {
		if err := opt(t); err != nil {
			return nil, err
		}
	}

	return &http.Client{Transport: t}, nil
}

type ClientError struct {
	Status int
	Msg    string
}

func (err ClientError) Error() string {
	var msgStr string
	if err.Msg != "" {
		msgStr = fmt.Sprintf(" msg=%s", err.Msg)
	}
	return fmt.Sprintf("tokenizer client error: status=%d%s", err.Status, msgStr)
}
