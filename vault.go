package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	vaultAPI "github.com/hashicorp/vault/api"
)

var (
	errNotFound = errors.New("not found")
)

type secretStore interface {
	get(context.Context, string) (map[string]string, error)
}

type vaultSecretStore struct{ *vaultAPI.Client }

var _ secretStore = new(vaultSecretStore)

func (vss *vaultSecretStore) get(ctx context.Context, path string) (map[string]string, error) {
	secret, err := vss.Logical().ReadWithContext(ctx, path)
	switch {
	case errors.Is(err, vaultAPI.ErrSecretNotFound):
		return nil, errNotFound
	case err != nil:
		return nil, fmt.Errorf("vault get: %w", err)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vault get: no data in result")
	}

	result := map[string]string{}

	for k, v := range data {
		result[k] = v.(string)
	}

	return result, nil
}

const (
	vaultInfraURL = "https://[fc01::1]:8200/"
)

func vaultInfraLoginFromEnv() (*vaultSecretStore, error) {
	vaultRole := os.Getenv("VAULT_ROLE")
	if vaultRole == "" {
		return nil, fmt.Errorf("vault infra login: no VAULT_ROLE")
	}

	vaultSecret := os.Getenv("VAULT_SECRET")
	if vaultSecret == "" {
		return nil, fmt.Errorf("vault infra login: no VAULT_SECRET")
	}

	appRole, err := vaultInfraLoginAppRole(vaultRole, vaultSecret)
	if err != nil {
		return nil, err
	}

	return &vaultSecretStore{appRole}, nil
}

func vaultInfraLoginAppRole(role, secret string) (*vaultAPI.Client, error) {
	return vaultLoginAppRole(vaultInfraURL, role, secret)
}

func vaultLoginAppRole(url, role, secret string) (*vaultAPI.Client, error) {
	config := vaultAPI.DefaultConfig()
	config.Address = url

	if strings.Contains(url, "fc01::1") {
		t := *(http.DefaultTransport.(*http.Transport))
		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}

		config.HttpClient = &http.Client{
			Transport: &t,
		}
	}

	client, err := vaultAPI.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("vault approle login: %w", err)
	}

	resp, err := client.Logical().Write("auth/approle/login",
		map[string]interface{}{
			"role_id":   role,
			"secret_id": secret,
		})
	if err != nil {
		return nil, fmt.Errorf("vault approle login: %w", err)
	}

	client.SetToken(resp.Auth.ClientToken)

	return client, nil
}
