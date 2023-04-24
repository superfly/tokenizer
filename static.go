package tokenizer

import (
	"context"
)

type StaticSecretStore map[string]Secret

func (sss StaticSecretStore) get(ctx context.Context, path string) (Secret, error) {
	if s, found := sss[path]; !found {
		return nil, ErrNotFound
	} else {
		return s, nil
	}
}
