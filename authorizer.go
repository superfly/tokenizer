package tokenizer

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/bundle"
	tkmac "github.com/superfly/tokenizer/macaroon"
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
	for _, tok := range proxyAuthorizationTokens(req) {
		hdrDigest := sha256.Sum256([]byte(tok))
		if subtle.ConstantTimeCompare(c.Digest, hdrDigest[:]) == 1 {
			return nil
		}
	}

	return fmt.Errorf("%w: bad or missing proxy auth", ErrNotAuthorized)
}

type MacaroonAuthConfig struct {
	Key []byte `json:"key"`
}

func NewMacaroonAuthConfig(key []byte) *MacaroonAuthConfig {
	return &MacaroonAuthConfig{Key: key}
}

var _ AuthConfig = new(MacaroonAuthConfig)

func (c *MacaroonAuthConfig) AuthRequest(req *http.Request) error {
	var (
		expectedKID = tkmac.KeyFingerprint(c.Key)
		log         = logrus.WithField("expected-kid", hex.EncodeToString(expectedKID))
		ctx         = req.Context()
	)

	for _, tok := range proxyAuthorizationTokens(req) {
		bun, err := bundle.ParseBundle(tkmac.Location, tok)
		if err != nil {
			log.WithError(err).Warn("bad macaroon format")
			continue
		}

		if _, err = bun.Verify(ctx, bundle.WithKey(expectedKID, c.Key, nil)); err != nil {
			log.WithError(err).Warn("bad macaroon signature")
			continue
		}

		if err = bun.Validate(&tkmac.Access{Request: req}); err != nil {
			log.WithError(err).Warn("bad macaroon authz")
			continue
		}

		return nil
	}

	return fmt.Errorf("%w: bad or missing proxy auth", ErrNotAuthorized)
}

func (c *MacaroonAuthConfig) Macaroon(caveats ...macaroon.Caveat) (string, error) {
	m, err := macaroon.New(tkmac.KeyFingerprint(c.Key), tkmac.Location, c.Key)
	if err != nil {
		return "", err
	}

	if err := m.Add(caveats...); err != nil {
		return "", err
	}

	mb, err := m.Encode()
	if err != nil {
		return "", err
	}

	return macaroon.ToAuthorizationHeader(mb), nil
}

func proxyAuthorizationTokens(req *http.Request) (ret []string) {
hdrLoop:
	for _, hdr := range req.Header.Values(headerProxyAuthorization) {
		scheme, rest, ok := strings.Cut(hdr, " ")
		if !ok {
			logrus.Warn("missing authorization scheme")
			continue hdrLoop
		}

		switch scheme {
		case "Bearer", "FlyV1":
			ret = append(ret, rest)
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

			ret = append(ret, pword)

			if plainPword, err := url.QueryUnescape(pword); err == nil {
				ret = append(ret, plainPword)
			}
		default:
			logrus.WithField("scheme", scheme).Warn("bad authorization scheme")
		}
	}

	return
}
