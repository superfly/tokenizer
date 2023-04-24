package tokenizer

import (
	"context"
	"errors"
	"fmt"

	vaultAPI "github.com/hashicorp/vault/api"
)

func VaultSecretStore(client *vaultAPI.Client) SecretStore {
	return &vaultSecretStore{client}
}

type vaultSecretStore struct{ *vaultAPI.Client }

var _ SecretStore = new(vaultSecretStore)

func (vss *vaultSecretStore) get(ctx context.Context, path string) (Secret, error) {
	vaultSecret, err := vss.Logical().ReadWithContext(ctx, path)
	switch {
	case errors.Is(err, vaultAPI.ErrSecretNotFound):
		return nil, ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("vault get: %w", err)
	}

	data, ok := vaultSecret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vault get: no data in result")
	}

	result := map[string]string{}

	for k, v := range data {
		result[k] = v.(string)
	}

	return Secret(result), nil
}
