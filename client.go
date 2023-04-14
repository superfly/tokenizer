package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

var baseClient *http.Client

func init() {
	baseClient = http.DefaultClient
}

func NewClient(proxyURL string, auth string, tokenToPath map[string]string) (*http.Client, error) {
	baseURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	caURL := baseURL.JoinPath(caPath)
	resp, err := baseClient.Get(caURL.String())
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	baseTransport, isHttpTransport := baseClient.Transport.(*http.Transport)
	if !isHttpTransport {
		return nil, errors.New("bad default transport")
	}

	transport := baseTransport.Clone()
	transport.Proxy = http.ProxyURL(baseURL)
	transport.ProxyConnectHeader = map[string][]string{
		headerAuth: {auth},
	}

	for token, path := range tokenToPath {
		transport.ProxyConnectHeader.Add(headerReplace, fmt.Sprintf("%s=%s", token, path))
	}

	transport.TLSClientConfig.RootCAs = transport.TLSClientConfig.RootCAs.Clone()
	if !transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(body) {
		return nil, errors.New("no ca certs")
	}

	return &http.Client{Transport: transport}, nil
}
