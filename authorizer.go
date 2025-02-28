package tokenizer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/bundle"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/flyio/machinesapi"
	tkmac "github.com/superfly/tokenizer/macaroon"
	"golang.org/x/exp/slices"
)

const (
	headerProxyAuthorization = "Proxy-Authorization"
	headerFlySrc             = "Fly-Src"
	headerFlySrcSignature    = "Fly-Src-Signature"
	flySrcSignatureKeyPath   = "/.fly/fly-src.pub"

	maxFlySrcAge = 30 * time.Second
)

var (
	flySrcSignatureKey = readFlySrcKey(flySrcSignatureKeyPath)
)

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
	fs, err := flySrcFromRequest(req)
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

type flySrc struct {
	Org       string
	App       string
	Instance  string
	Timestamp time.Time
}

func flySrcFromRequest(req *http.Request) (*flySrc, error) {
	srcHdr := req.Header.Get(headerFlySrc)
	if srcHdr == "" {
		return nil, errors.New("missing Fly-Src header")
	}

	sigHdr := req.Header.Get(headerFlySrcSignature)
	if sigHdr == "" {
		return nil, errors.New("missing Fly-Src signature")
	}

	return verifyAndParseFlySrc(srcHdr, sigHdr, flySrcSignatureKey)
}

func verifyAndParseFlySrc(srcHdr, sigHdr string, key ed25519.PublicKey) (*flySrc, error) {
	sig, err := base64.StdEncoding.DecodeString(sigHdr)
	if err != nil {
		return nil, fmt.Errorf("bad Fly-Src signature: %w", err)
	}

	if !ed25519.Verify(key, []byte(srcHdr), sig) {
		return nil, errors.New("bad Fly-Src signature")
	}

	fs, err := parseFlySrc(srcHdr)
	if err != nil {
		return nil, fmt.Errorf("bad Fly-Src header: %w", err)
	}

	if fs.age() > maxFlySrcAge {
		return nil, fmt.Errorf("expired Fly-Src header")
	}

	return fs, nil
}

func parseFlySrc(hdr string) (*flySrc, error) {
	var ret flySrc

	parts := strings.Split(hdr, ";")
	if n := len(parts); n != 4 {
		return nil, fmt.Errorf("malformed Fly-Src header (%d parts)", n)
	}

	for _, part := range parts {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("malformed Fly-Src header (missing =)")
		}

		switch k {
		case "org":
			ret.Org = v
		case "app":
			ret.App = v
		case "instance":
			ret.Instance = v
		case "ts":
			tsi, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("malformed Fly-Src timestamp: %w", err)
			}

			ret.Timestamp = time.Unix(int64(tsi), 0)
		default:
			return nil, fmt.Errorf("malformed Fly-Src header (unknown key: %q)", k)
		}
	}

	if ret.Org == "" || ret.App == "" || ret.Instance == "" || ret.Timestamp.IsZero() {
		return nil, fmt.Errorf("malformed Fly-Src header (missing parts)")
	}

	return &ret, nil
}

func (fs *flySrc) age() time.Duration {
	return time.Since(fs.Timestamp)
}

func readFlySrcKey(path string) ed25519.PublicKey {
	hk, err := os.ReadFile(path)
	if err != nil {
		logrus.WithError(err).Warn("failed to read Fly-Src public key")
		return nil
	}

	if size := len(hk); hex.DecodedLen(size) != ed25519.PublicKeySize {
		logrus.WithField("size", size).Warn("bad Fly-Src public key size")
		return nil
	}

	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	if _, err := hex.Decode(key, hk); err != nil {
		logrus.WithError(err).Warn("bad Fly-Src public key")
		return nil
	}

	return key
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
