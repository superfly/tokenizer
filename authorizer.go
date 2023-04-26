package tokenizer

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

const headerProxyAuthorization = "Proxy-Authorization"

type Authorizer interface {
	Authorize(*http.Request) error
}

var authorizerRegistry = map[string]Authorizer{}

func RegisterAuthorizer(name string, a Authorizer) {
	if _, dup := authorizerRegistry[name]; dup {
		logrus.Panicf("duplicate authorizer: %s", name)
	}
	authorizerRegistry[name] = a
}

type AuthorizerFunc func(*http.Request) error

func (a AuthorizerFunc) Authorize(r *http.Request) error {
	return a(r)
}

func RegisterSharedSecretAuthorizer(name string, hexSHA256SecretDigest string) {
	RegisterAuthorizer(name, sharedSecretAuthorizer(hexSHA256SecretDigest))
}

func sharedSecretAuthorizer(hexSHA256SecretDigest string) Authorizer {
	digest, err := hex.DecodeString(hexSHA256SecretDigest)
	if err != nil {
		logrus.WithError(err).Panicf("unable to decode hex sha256 secret digest")
	}

	return AuthorizerFunc(func(r *http.Request) error {
		var found bool
		for _, hdr := range r.Header.Values(headerProxyAuthorization) {
			hdrDigest := sha256.Sum256([]byte(hdr))
			if subtle.ConstantTimeCompare(digest, hdrDigest[:]) == 1 {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("%w: bad or missing proxy auth", ErrNotAuthorized)
		}

		return nil
	})
}
