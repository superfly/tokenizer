package tokenizer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrNotAuthorized = errors.New("not authorized")
	ErrBadRequest    = errors.New("bad request")
)

type SecretStore interface {
	get(context.Context, string) (Secret, error)
}

type Secret map[string]string

const (
	SecretKeyAuthorizer = "authorizer"
	SecretKeyProcessor  = "processor"
	SecretKeySecret     = "secret"
	SecretKeyHash       = "hash"
)

func (s Secret) AuthorizeAccess(r *http.Request) error {
	authzName := s[SecretKeyAuthorizer]
	if authzName == "" {
		return errors.New("secret doesn't specify authorizer type")
	}

	authz := authorizerRegistry[authzName]
	if authz == nil {
		return fmt.Errorf("unrecognized authorizer type: %s", authzName)
	}

	return authz.Authorize(r)
}

func (s Secret) Processor(params map[string]string) (RequestProcessor, error) {
	factoryName := s[SecretKeyProcessor]
	if factoryName == "" {
		return nil, errors.New("secret doesn't specify processor type")
	}

	factory := processorFactoryRegistry[factoryName]
	if factory == nil {
		return nil, fmt.Errorf("unrecognized processor type: %s", factoryName)
	}

	return factory(s, params)
}

func (s Secret) Secret() string {
	return s[SecretKeySecret]
}
