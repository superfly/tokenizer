package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

const (
	vaultInfraURL = "https://[fc01::1]:8200/"
)

func vaultInfraLoginFromEnv() (*api.Client, error) {
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

	return appRole, nil
}

func vaultInfraLoginAppRole(role, secret string) (*api.Client, error) {
	return vaultLoginAppRole(vaultInfraURL, role, secret)
}

func vaultLoginAppRole(url, role, secret string) (*api.Client, error) {
	config := api.DefaultConfig()
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

	client, err := api.NewClient(config)
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
