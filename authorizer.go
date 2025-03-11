package tokenizer

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/bundle"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/flyio/machinesapi"
	"github.com/superfly/tokenizer/flysrc"
	tkmac "github.com/superfly/tokenizer/macaroon"
	"golang.org/x/exp/slices"
)

const (
	headerProxyAuthorization = "Proxy-Authorization"

	maxFlySrcAge = 30 * time.Second
)

type AuthConfig interface {
	AuthRequest(req *http.Request) error
}

type wireAuth struct {
	BearerAuthConfig        *BearerAuthConfig        `json:"bearer_auth,omitempty"`
	MacaroonAuthConfig      *MacaroonAuthConfig      `json:"macaroon_auth,omitempty"`
	FlyioMacaroonAuthConfig *FlyioMacaroonAuthConfig `json:"flyio_macaroon_auth,omitempty"`
	FlySrcAuthConfig        *FlySrcAuthConfig        `json:"fly_src_auth,omitempty"`
	NoAuthConfig            *NoAuthConfig            `json:"no_auth,omitempty"`
}

func newWireAuth(ac AuthConfig) (wireAuth, error) {
	switch a := ac.(type) {
	case *BearerAuthConfig:
		return wireAuth{BearerAuthConfig: a}, nil
	case *MacaroonAuthConfig:
		return wireAuth{MacaroonAuthConfig: a}, nil
	case *FlyioMacaroonAuthConfig:
		return wireAuth{FlyioMacaroonAuthConfig: a}, nil
	case *FlySrcAuthConfig:
		return wireAuth{FlySrcAuthConfig: a}, nil
	case *NoAuthConfig:
		return wireAuth{NoAuthConfig: a}, nil
	default:
		return wireAuth{}, fmt.Errorf("bad auth config: %T", ac)
	}
}

func (wa *wireAuth) getAuthConfig() (AuthConfig, error) {
	var ac AuthConfig

	var na int
	if wa.BearerAuthConfig != nil {
		na += 1
		ac = wa.BearerAuthConfig
	}
	if wa.MacaroonAuthConfig != nil {
		na += 1
		ac = wa.MacaroonAuthConfig
	}
	if wa.FlyioMacaroonAuthConfig != nil {
		na += 1
		ac = wa.FlyioMacaroonAuthConfig
	}
	if wa.FlySrcAuthConfig != nil {
		na += 1
		ac = wa.FlySrcAuthConfig
	}
	if wa.NoAuthConfig != nil {
		na += 1
		ac = wa.NoAuthConfig
	}
	if na != 1 {
		return nil, errors.New("bad auth config")
	}

	return ac, nil
}

type BearerAuthConfig struct {
	Digest []byte `json:"digest"`
}

func NewBearerAuthConfig(token string) *BearerAuthConfig {
	digest := sha256.Sum256([]byte(token))
	return &BearerAuthConfig{digest[:]}
}

var _ AuthConfig = (*BearerAuthConfig)(nil)

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

var _ AuthConfig = (*MacaroonAuthConfig)(nil)

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

type FlyioMacaroonAuthConfig struct {
	Access flyio.Access `json:"access"`
}

func NewFlyioMacaroonAuthConfig(access *flyio.Access) *FlyioMacaroonAuthConfig {
	return &FlyioMacaroonAuthConfig{Access: *access}
}

var _ AuthConfig = (*FlyioMacaroonAuthConfig)(nil)

func (c *FlyioMacaroonAuthConfig) AuthRequest(req *http.Request) error {
	var ctx = req.Context()

	for _, tok := range proxyAuthorizationTokens(req) {
		bun, err := flyio.ParseBundle(tok)
		if err != nil {
			logrus.WithError(err).Warn("bad macaroon format")
			continue
		}

		if _, err := bun.Verify(ctx, machinesapi.DefaultClient); err != nil {
			logrus.WithError(err).Warn("bad macaroon signature")
			continue
		}

		if err := bun.Validate(&c.Access); err != nil {
			logrus.WithError(err).Warn("bad macaroon authz")
			continue
		}

		return nil
	}

	return fmt.Errorf("%w: bad or missing proxy auth", ErrNotAuthorized)
}

// FlySrcAuthConfig allows permitting access to a secret based on the Fly-Src
// header added to Flycast requests between Fly.io machines/apps/orgs.
// https://community.fly.io/t/fly-src-authenticating-http-requests-between-fly-apps/20566
type FlySrcAuthConfig struct {
	// AllowedOrgs is a list of Fly.io organization slugs that are allowed to
	// use the secret. An empty/missing value means that the `org` portion of
	// the Fly-Src header is not checked.
	AllowedOrgs []string `json:"allowed_orgs"`

	// AllowedApps is a list of Fly.io application slugs that are allowed to use
	// the secret. An empty/missing value means that the `app` portion of the
	// Fly-Src header is not checked.
	AllowedApps []string `json:"allowed_apps"`

	// AllowedInstances is a list of Fly.io instance IDs that are allowed to use
	// the secret. An empty/missing value means that the `instance` portion of
	// the Fly-Src header is not checked.
	AllowedInstances []string `json:"allowed_instances"`
}

type FlySrcOpt func(*FlySrcAuthConfig)

// AllowlistFlySrcOrgs sets the list of allowed Fly.io organization slugs.
func AllowlistFlySrcOrgs(orgs ...string) FlySrcOpt {
	return func(c *FlySrcAuthConfig) {
		c.AllowedOrgs = append(c.AllowedOrgs, orgs...)
	}
}

// AllowlistFlySrcApps sets the list of allowed Fly App names.
func AllowlistFlySrcApps(apps ...string) FlySrcOpt {
	return func(c *FlySrcAuthConfig) {
		c.AllowedApps = append(c.AllowedApps, apps...)
	}
}

// AllowlistFlySrcInstances sets the list of allowed Fly.io instances.
func AllowlistFlySrcInstances(instances ...string) FlySrcOpt {
	return func(c *FlySrcAuthConfig) {
		c.AllowedInstances = append(c.AllowedInstances, instances...)
	}
}

// NewFlySrcAuthConfig creates a new FlySrcAuthConfig with the given options.
func NewFlySrcAuthConfig(opts ...FlySrcOpt) *FlySrcAuthConfig {
	c := new(FlySrcAuthConfig)
	for _, opt := range opts {
		opt(c)
	}

	return c
}

var _ AuthConfig = (*FlySrcAuthConfig)(nil)

func (c *FlySrcAuthConfig) AuthRequest(req *http.Request) error {
	fs, err := flysrc.FromRequest(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}

	if len(c.AllowedOrgs) > 0 && !slices.Contains(c.AllowedOrgs, fs.Org) {
		return fmt.Errorf("%w: org %s not allowed", ErrNotAuthorized, fs.Org)
	}

	if len(c.AllowedApps) > 0 && !slices.Contains(c.AllowedApps, fs.App) {
		return fmt.Errorf("%w: app %s not allowed", ErrNotAuthorized, fs.App)
	}

	if len(c.AllowedInstances) > 0 && !slices.Contains(c.AllowedInstances, fs.Instance) {
		return fmt.Errorf("%w: instance %s not allowed", ErrNotAuthorized, fs.Instance)
	}

	return nil
}

type NoAuthConfig struct{}

var _ AuthConfig = (*NoAuthConfig)(nil)

func (c *NoAuthConfig) AuthRequest(req *http.Request) error {
	return nil
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
