package tokenizer

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

const headerProxyAuthorization = "Proxy-Authorization"

type AuthConfig interface {
	AuthRequest(req *http.Request) error
}

type BearerAuthConfig struct {
	Digest []byte `json:"digest"`
}

func NewBearerAuthConfig(token string) *BearerAuthConfig {
	digest := sha256.Sum256([]byte(token))
	return &BearerAuthConfig{digest[:]}
}

var _ AuthConfig = new(BearerAuthConfig)

func (c *BearerAuthConfig) AuthRequest(req *http.Request) error {
	var found bool

hdrLoop:
	for _, hdr := range req.Header.Values(headerProxyAuthorization) {
		scheme, rest, ok := strings.Cut(hdr, " ")
		if !ok {
			logrus.Warn("missing authorization scheme")
			continue hdrLoop
		}

		switch scheme {
		case "Bearer":
			hdr = rest
		case "Basic":
			raw, err := base64.StdEncoding.DecodeString(rest)
			if err != nil {
				logrus.WithError(err).Warn("bad basic auth encoding")
				continue hdrLoop
			}
			_, pword, ok := strings.Cut(string(raw), ":")
			if !ok {
				logrus.Warn("bad basic auth format")
				continue hdrLoop
			}
			hdr = pword
		default:
			logrus.WithField("scheme", scheme).Warn("bad authorization scheme")
			continue hdrLoop
		}

		hdrDigest := sha256.Sum256([]byte(hdr))
		if subtle.ConstantTimeCompare(c.Digest, hdrDigest[:]) == 1 {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%w: bad or missing proxy auth", ErrNotAuthorized)
	}

	return nil
}
