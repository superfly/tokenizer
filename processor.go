package tokenizer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/icholy/replace"
	"golang.org/x/exp/slices"
)

const (
	// ParamDst optionally specifies the header that Inject processors should
	// set. Default is Authorization.
	ParamDst = "dst"

	// ParamFmt optionally specifies a format string that Inject processors
	// should use when setting headers. Default is "Bearer %s" for string
	// values and "Bearer %x" for binary values.
	ParamFmt = "fmt"

	// ParamPayload specifies the string that should be signed by InjectHMAC.
	// Defaults to verbatim request body with leading/trailing whitespace
	// removed.
	ParamPayload = "msg"

	// ParamSubtoken optionally specifies which subtoken should be used.
	// Default is SubtokenAccessToken.
	ParamSubtoken = "st"

	// ParamPlaceholder specifies the placeholder pattern to replace in the
	// request body with the token value. Used by InjectBodyProcessor.
	ParamPlaceholder = "placeholder"

	// ParamSubject optionally specifies the subject (user to impersonate)
	// for JWTProcessor. Allows different requests through the same sealed
	// credential to impersonate different users.
	ParamSubject = "sub"

	// ParamScopes optionally specifies the OAuth2 scopes for JWTProcessor.
	// Allows different requests through the same sealed credential to
	// request different scopes.
	ParamScopes = "scopes"
)

const (
	SubtokenAccess  = "access"
	SubtokenRefresh = "refresh"
)

type RequestProcessor func(r *http.Request) error

// SealingContext provides the information a processor needs to create new
// sealed secrets. Only JWTProcessorConfig uses this today - it seals the
// access token into a new InjectProcessorConfig for the caller to reuse.
type SealingContext struct {
	AuthConfig        AuthConfig
	RequestValidators []RequestValidator
	SealKey           *[32]byte
}

type ProcessorConfig interface {
	Processor(params map[string]string, sctx *SealingContext) (RequestProcessor, error)
	StripHazmat() ProcessorConfig
}

// ResponseProcessorConfig is an optional interface for processors that also
// need to transform the HTTP response. The JWT processor uses this to replace
// Google's token response with a sealed access token.
type ResponseProcessorConfig interface {
	ResponseProcessor(params map[string]string, sctx *SealingContext) (func(*http.Response) error, error)
}

type wireProcessor struct {
	InjectProcessorConfig            *InjectProcessorConfig            `json:"inject_processor,omitempty"`
	InjectHMACProcessorConfig        *InjectHMACProcessorConfig        `json:"inject_hmac_processor,omitempty"`
	InjectBodyProcessorConfig        *InjectBodyProcessorConfig        `json:"inject_body_processor,omitempty"`
	OAuthProcessorConfig             *OAuthProcessorConfig             `json:"oauth2_processor,omitempty"`
	OAuthBodyProcessorConfig         *OAuthBodyProcessorConfig         `json:"oauth2_body_processor,omitempty"`
	Sigv4ProcessorConfig             *Sigv4ProcessorConfig             `json:"sigv4_processor,omitempty"`
	JWTProcessorConfig               *JWTProcessorConfig               `json:"jwt_processor,omitempty"`
	ClientCredentialsProcessorConfig *ClientCredentialsProcessorConfig `json:"client_credentials_processor,omitempty"`
	GitHubAppProcessorConfig         *GitHubAppProcessorConfig         `json:"github_app_processor,omitempty"`
	MultiProcessorConfig             *MultiProcessorConfig             `json:"multi_processor,omitempty"`
}

func newWireProcessor(p ProcessorConfig) (wireProcessor, error) {
	switch p := p.(type) {
	case *InjectProcessorConfig:
		return wireProcessor{InjectProcessorConfig: p}, nil
	case *InjectHMACProcessorConfig:
		return wireProcessor{InjectHMACProcessorConfig: p}, nil
	case *InjectBodyProcessorConfig:
		return wireProcessor{InjectBodyProcessorConfig: p}, nil
	case *OAuthProcessorConfig:
		return wireProcessor{OAuthProcessorConfig: p}, nil
	case *OAuthBodyProcessorConfig:
		return wireProcessor{OAuthBodyProcessorConfig: p}, nil
	case *Sigv4ProcessorConfig:
		return wireProcessor{Sigv4ProcessorConfig: p}, nil
	case *JWTProcessorConfig:
		return wireProcessor{JWTProcessorConfig: p}, nil
	case *ClientCredentialsProcessorConfig:
		return wireProcessor{ClientCredentialsProcessorConfig: p}, nil
	case *GitHubAppProcessorConfig:
		return wireProcessor{GitHubAppProcessorConfig: p}, nil
	case *MultiProcessorConfig:
		return wireProcessor{MultiProcessorConfig: p}, nil
	default:
		return wireProcessor{}, errors.New("bad processor config")
	}
}

func (wp *wireProcessor) getProcessorConfig() (ProcessorConfig, error) {
	var p ProcessorConfig

	var np int
	if wp.InjectProcessorConfig != nil {
		np += 1
		p = wp.InjectProcessorConfig
	}
	if wp.InjectHMACProcessorConfig != nil {
		np += 1
		p = wp.InjectHMACProcessorConfig
	}
	if wp.InjectBodyProcessorConfig != nil {
		np += 1
		p = wp.InjectBodyProcessorConfig
	}
	if wp.OAuthProcessorConfig != nil {
		np += 1
		p = wp.OAuthProcessorConfig
	}
	if wp.OAuthBodyProcessorConfig != nil {
		np += 1
		p = wp.OAuthBodyProcessorConfig
	}
	if wp.Sigv4ProcessorConfig != nil {
		np += 1
		p = wp.Sigv4ProcessorConfig
	}
	if wp.JWTProcessorConfig != nil {
		np += 1
		p = wp.JWTProcessorConfig
	}
	if wp.ClientCredentialsProcessorConfig != nil {
		np += 1
		p = wp.ClientCredentialsProcessorConfig
	}
	if wp.GitHubAppProcessorConfig != nil {
		np += 1
		p = wp.GitHubAppProcessorConfig
	}
	if wp.MultiProcessorConfig != nil {
		np += 1
		p = wp.MultiProcessorConfig
	}
	if np != 1 {
		return nil, errors.New("bad processor config")
	}

	return p, nil
}

type InjectProcessorConfig struct {
	Token string `json:"token"`
	FmtProcessor
	DstProcessor
}

var _ ProcessorConfig = new(InjectProcessorConfig)

func (c *InjectProcessorConfig) Processor(params map[string]string, _ *SealingContext) (RequestProcessor, error) {
	if c.Token == "" {
		return nil, errors.New("missing token")
	}

	val, err := c.ApplyFmt(params, false, c.Token)
	if err != nil {
		return nil, err
	}

	return func(r *http.Request) error {
		return c.ApplyDst(params, r, val)
	}, nil
}

func (c *InjectProcessorConfig) StripHazmat() ProcessorConfig {
	// DO NOT PUT HAZMAT INTO FmtProcessor or DstProcessor.
	return &InjectProcessorConfig{
		Token:        redactedStr,
		FmtProcessor: c.FmtProcessor,
		DstProcessor: c.DstProcessor,
	}
}

type InjectHMACProcessorConfig struct {
	Key  []byte `json:"key"`
	Hash string `json:"hash"`
	FmtProcessor
	DstProcessor
}

var _ ProcessorConfig = new(InjectHMACProcessorConfig)

func (c *InjectHMACProcessorConfig) Processor(params map[string]string, _ *SealingContext) (RequestProcessor, error) {
	var h crypto.Hash
	switch c.Hash {
	case "sha256":
		h = crypto.SHA256
	default:
		return nil, fmt.Errorf("unsupported hash function: %s", c.Hash)
	}

	if len(c.Key) == 0 {
		return nil, errors.New("missing hmac key")
	}

	var buf io.Reader
	if p, ok := params[ParamPayload]; ok {
		buf = bytes.NewReader([]byte(p))
	}

	return func(r *http.Request) error {
		hm := hmac.New(h.New, c.Key)

		if buf == nil {
			bbuf := new(bytes.Buffer)
			buf = io.TeeReader(r.Body, bbuf)
			r.Body = io.NopCloser(bbuf)
		}

		if _, err := io.Copy(hm, buf); err != nil {
			return err
		}

		val, err := c.ApplyFmt(params, true, hm.Sum(nil))
		if err != nil {
			return err
		}

		return c.ApplyDst(params, r, val)
	}, nil
}

func (c *InjectHMACProcessorConfig) StripHazmat() ProcessorConfig {
	// DO NOT PUT HAZMAT INTO FmtProcessor or DstProcessor.
	return &InjectHMACProcessorConfig{
		Key:          redactedBase64,
		Hash:         redactedStr,
		FmtProcessor: c.FmtProcessor,
		DstProcessor: c.DstProcessor,
	}
}

type InjectBodyProcessorConfig struct {
	Token       string `json:"token"`
	Placeholder string `json:"placeholder,omitempty"`
}

var _ ProcessorConfig = new(InjectBodyProcessorConfig)

func (c *InjectBodyProcessorConfig) Processor(params map[string]string, _ *SealingContext) (RequestProcessor, error) {
	if c.Token == "" {
		return nil, errors.New("missing token")
	}

	// Get placeholder from params or use config default or fallback
	placeholder := c.Placeholder
	if paramPlaceholder, ok := params[ParamPlaceholder]; ok {
		placeholder = paramPlaceholder
	}
	if placeholder == "" {
		placeholder = "{{ACCESS_TOKEN}}"
	}

	return func(r *http.Request) error {
		if r.Body == nil {
			return nil
		}

		// Use streaming replacement to avoid loading entire body into memory
		chain := replace.Chain(r.Body, replace.String(placeholder, c.Token))

		// Set body to the replacement chain for true streaming with chunked encoding
		// Setting ContentLength to 0 triggers chunked transfer encoding
		r.Body = io.NopCloser(chain)
		r.ContentLength = 0

		return nil
	}, nil
}

func (c *InjectBodyProcessorConfig) StripHazmat() ProcessorConfig {
	return &InjectBodyProcessorConfig{
		Token:       redactedStr,
		Placeholder: c.Placeholder,
	}
}

type OAuthProcessorConfig struct {
	Token *OAuthToken `json:"token"`
}

type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

var _ ProcessorConfig = (*OAuthProcessorConfig)(nil)

func (c *OAuthProcessorConfig) Processor(params map[string]string, _ *SealingContext) (RequestProcessor, error) {
	token := c.Token.AccessToken
	if params[ParamSubtoken] == SubtokenRefresh {
		token = c.Token.RefreshToken
	}

	if token == "" {
		return nil, errors.New("missing token")
	}

	// Check if placeholder parameter is present for body injection
	if placeholder, ok := params[ParamPlaceholder]; ok && placeholder != "" {
		// Inject token into request body by replacing placeholder
		return func(r *http.Request) error {
			if r.Body == nil {
				return nil
			}

			// Use streaming replacement to avoid loading entire body into memory
			chain := replace.Chain(r.Body, replace.String(placeholder, token))

			// Set body to the replacement chain for true streaming with chunked encoding
			// Setting ContentLength to 0 triggers chunked transfer encoding
			r.Body = io.NopCloser(chain)
			r.ContentLength = 0

			return nil
		}, nil
	}

	// Default behavior: inject into Authorization header
	return func(r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+token)
		return nil
	}, nil
}

func (c *OAuthProcessorConfig) StripHazmat() ProcessorConfig {
	return &OAuthProcessorConfig{
		Token: &OAuthToken{
			AccessToken:  redactedStr,
			RefreshToken: redactedStr,
		},
	}
}

type OAuthBodyProcessorConfig struct {
	Token       *OAuthToken `json:"token"`
	Placeholder string      `json:"placeholder,omitempty"`
}

var _ ProcessorConfig = (*OAuthBodyProcessorConfig)(nil)

func (c *OAuthBodyProcessorConfig) Processor(params map[string]string, _ *SealingContext) (RequestProcessor, error) {
	token := c.Token.AccessToken
	if params[ParamSubtoken] == SubtokenRefresh {
		token = c.Token.RefreshToken
	}

	if token == "" {
		return nil, errors.New("missing token")
	}

	// Get placeholder from params or use config default or fallback
	placeholder := c.Placeholder
	if paramPlaceholder, ok := params[ParamPlaceholder]; ok {
		placeholder = paramPlaceholder
	}
	if placeholder == "" {
		placeholder = "{{ACCESS_TOKEN}}"
	}

	return func(r *http.Request) error {
		if r.Body == nil {
			return nil
		}

		// Use streaming replacement to avoid loading entire body into memory
		chain := replace.Chain(r.Body, replace.String(placeholder, token))

		// Set body to the replacement chain for true streaming with chunked encoding
		// Setting ContentLength to 0 triggers chunked transfer encoding
		r.Body = io.NopCloser(chain)
		r.ContentLength = 0

		return nil
	}, nil
}

func (c *OAuthBodyProcessorConfig) StripHazmat() ProcessorConfig {
	return &OAuthBodyProcessorConfig{
		Token: &OAuthToken{
			AccessToken:  redactedStr,
			RefreshToken: redactedStr,
		},
		Placeholder: c.Placeholder,
	}
}

type Sigv4ProcessorConfig struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	NoSwap    bool   `json:"no_swap"` // Bug compat, when false region/service get swapped.
}

var _ ProcessorConfig = (*Sigv4ProcessorConfig)(nil)

func (c *Sigv4ProcessorConfig) Processor(params map[string]string, _ *SealingContext) (RequestProcessor, error) {

	if len(c.AccessKey) == 0 {
		return nil, errors.New("missing access key")
	}
	if len(c.SecretKey) == 0 {
		return nil, errors.New("missing secret key")
	}

	return func(r *http.Request) error {
		// NOTE: Sigv4 has defenses against request forgery and reuse.
		// This does *not* make those guarantees, and likely can not.

		var (
			service string
			region  string
			date    time.Time
			err     error
		)

		// Parse the auth header to get the service, region, and date
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return errors.New("expected request to contain an Authorization header")
		}

		for _, section := range strings.Split(authHeader, " ") {
			section = strings.TrimRight(section, ",")
			keyValuePair := strings.SplitN(section, "=", 2)
			if len(keyValuePair) != 2 {
				continue
			}

			if keyValuePair[0] == "Credential" {
				credParts := strings.Split(keyValuePair[1], "/")
				if len(credParts) != 5 {
					return errors.New("invalid credential in auth header")
				}

				dateStr := credParts[1]
				date, err = time.Parse("20060102", dateStr)
				if err != nil {
					return err
				}

				region = credParts[2]
				service = credParts[3]
				if !c.NoSwap {
					// Bug compat: swap service and region when NoSwap is not set.
					region, service = service, region
				}
				break
			}
		}
		if timestamp := r.Header.Get("X-Amz-Date"); timestamp != "" {
			date, err = time.Parse("20060102T150405Z", timestamp)
			if err != nil {
				return err
			}
		}
		if service == "" || region == "" || date.IsZero() {
			return errors.New("expected valid sigv4 authentication header in request to tokenizer")
		}

		// Strip the Authorization header from the request
		r.Header.Del("Authorization")

		credentials := aws.Credentials{
			AccessKeyID:     c.AccessKey,
			SecretAccessKey: c.SecretKey,
		}

		// HACK: We have to strip the filtered headers *before* the request gets signed,
		//       since sigv4 expects a signature of all the request's headers.
		for _, h := range FilteredHeaders {
			r.Header.Del(h)
		}
		// Remove headers that goproxy will strip out later anyway. Otherwise, the header signature check will fail.
		// https://github.com/elazarl/goproxy/blob/8b0c205063807802a7ac1d75351a90172a9c83fb/proxy.go#L87-L92
		r.Header.Del("Accept-Encoding")
		r.Header.Del("Proxy-Connection")
		r.Header.Del("Proxy-Authenticate")
		r.Header.Del("Proxy-Authorization")

		// Remove standard reverse proxy headers that may be injected by upstream proxies
		// (e.g., fly-proxy). These headers get signed but may be modified by outbound
		// proxies, causing SignatureDoesNotMatch errors.
		r.Header.Del("Via")
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Forwarded-Port")
		r.Header.Del("X-Forwarded-Proto")
		r.Header.Del("X-Forwarded-Ssl")
		r.Header.Del("X-Request-Start")

		signer := v4.NewSigner()
		err = signer.SignHTTP(r.Context(), credentials, r, r.Header.Get("X-Amz-Content-Sha256"), service, region, date)

		return err
	}, nil
}

func (c *Sigv4ProcessorConfig) StripHazmat() ProcessorConfig {
	return &Sigv4ProcessorConfig{
		AccessKey: redactedStr,
		SecretKey: redactedStr,
		NoSwap:    c.NoSwap,
	}
}

const defaultTokenURL = "https://oauth2.googleapis.com/token"

// JWTProcessorConfig signs a JWT using a private key and constructs a token
// exchange request body. Supported key types: RSA (RS256), ECDSA (ES256,
// ES384, ES512), and Ed25519 (EdDSA). The signing algorithm is chosen
// automatically based on the key type.
//
// This processor also transforms the response: it intercepts the token
// endpoint's response, extracts the access token, seals it into a new
// InjectProcessorConfig secret, and replaces the response body with the sealed
// token. This keeps tokenizer completely stateless while ensuring the caller
// never sees any plaintext credential.
//
// The outbound token exchange happens as a normal proxied request - the caller
// sends the request to the token endpoint through tokenizer, and this processor
// builds the POST body (grant_type + signed JWT assertion). The response
// rewriting is the only side effect.
//
// This design follows the industry-standard pattern used by HashiCorp Vault
// and AWS IAM Roles Anywhere, where the proxy performs the full credential
// exchange internally. The alternative (returning the plaintext access token
// to the caller) was rejected because the token could be exfiltrated.
type JWTProcessorConfig struct {
	PrivateKey []byte `json:"private_key"` // PEM-encoded private key (RSA, EC, or Ed25519)
	Email      string `json:"email"`       // Service account email (JWT "iss")
	Subject    string `json:"sub"`         // User to impersonate (domain-wide delegation)
	Scopes     string `json:"scopes"`      // Space-separated OAuth2 scopes
	TokenURL   string `json:"token_url"`   // Token endpoint (default: Google's)
}

// SealedTokenResponse is the response body returned to the caller after a
// successful JWT token exchange. The sealed_token field is an opaque encrypted
// blob containing an InjectProcessorConfig that the caller can use for
// subsequent API requests through tokenizer.
type SealedTokenResponse struct {
	SealedToken string `json:"sealed_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

var _ ProcessorConfig = (*JWTProcessorConfig)(nil)
var _ ResponseProcessorConfig = (*JWTProcessorConfig)(nil)

// parseKey decodes a PEM-encoded private key and returns it as a
// crypto.Signer. Supports RSA (PKCS1 and PKCS8), ECDSA, and Ed25519 keys.
func (c *JWTProcessorConfig) parseKey() (crypto.Signer, error) {
	if len(c.PrivateKey) == 0 {
		return nil, errors.New("missing private key")
	}

	block, _ := pem.Decode(c.PrivateKey)
	if block == nil {
		return nil, errors.New("invalid PEM-encoded private key")
	}

	// Try PKCS1 (RSA-only format) first
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}

	// Try PKCS8 (supports RSA, ECDSA, Ed25519)
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try EC-specific format as last resort
		if ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			return ecKey, nil
		}
		return nil, fmt.Errorf("unsupported private key format: %w", err)
	}

	signer, ok := pkcs8Key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
	}
	return signer, nil
}

// signingMethod returns the JWT signing method appropriate for the given key.
func signingMethod(key crypto.Signer) (jwt.SigningMethod, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return jwt.SigningMethodES256, nil
		case elliptic.P384():
			return jwt.SigningMethodES384, nil
		case elliptic.P521():
			return jwt.SigningMethodES512, nil
		default:
			return nil, fmt.Errorf("unsupported EC curve: %v", k.Curve.Params().Name)
		}
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

func (c *JWTProcessorConfig) tokenURL() string {
	if c.TokenURL != "" {
		return c.TokenURL
	}
	return defaultTokenURL
}

func (c *JWTProcessorConfig) Processor(params map[string]string, _ *SealingContext) (RequestProcessor, error) {
	key, err := c.parseKey()
	if err != nil {
		return nil, err
	}

	method, err := signingMethod(key)
	if err != nil {
		return nil, err
	}

	if c.Email == "" {
		return nil, errors.New("missing email")
	}

	// Resolve subject and scopes, allowing param overrides
	subject := c.Subject
	if s, ok := params[ParamSubject]; ok {
		subject = s
	}

	scopes := c.Scopes
	if s, ok := params[ParamScopes]; ok {
		scopes = s
	}

	tokenURL := c.tokenURL()

	return func(r *http.Request) error {
		now := time.Now()

		claims := jwt.MapClaims{
			"iss":   c.Email,
			"scope": scopes,
			"aud":   tokenURL,
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
		}
		if subject != "" {
			claims["sub"] = subject
		}

		token := jwt.NewWithClaims(method, claims)
		signedJWT, err := token.SignedString(key)
		if err != nil {
			return fmt.Errorf("failed to sign JWT: %w", err)
		}

		// Build the token exchange POST body
		body := url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {signedJWT},
		}.Encode()

		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return nil
	}, nil
}

func (c *JWTProcessorConfig) ResponseProcessor(params map[string]string, sctx *SealingContext) (func(*http.Response) error, error) {
	if sctx == nil {
		return nil, errors.New("JWT response processor requires a sealing context")
	}

	return sealTokenResponse(sctx), nil
}

// sealTokenResponse returns a response processor that reads a token endpoint's
// JSON response, seals the access token into a new InjectProcessorConfig, and
// replaces the response body with a SealedTokenResponse.
func sealTokenResponse(sctx *SealingContext) func(*http.Response) error {
	return func(resp *http.Response) error {
		// Pass through non-OK responses without modification
		if resp.StatusCode != http.StatusOK {
			return nil
		}

		// Parse the token endpoint response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read token response: %w", err)
		}

		var tokenResp struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
			TokenType   string `json:"token_type"`
		}
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			return fmt.Errorf("failed to parse token response: %w", err)
		}

		if tokenResp.AccessToken == "" {
			return errors.New("token response missing access_token")
		}

		// Create a new Secret with InjectProcessorConfig, forwarding auth
		// and validators from the original secret
		newSecret := &Secret{
			AuthConfig:        sctx.AuthConfig,
			ProcessorConfig:   &InjectProcessorConfig{Token: tokenResp.AccessToken},
			RequestValidators: sctx.RequestValidators,
		}

		sealedToken, err := newSecret.sealRaw(sctx.SealKey)
		if err != nil {
			return fmt.Errorf("failed to seal access token: %w", err)
		}

		// Subtract a small buffer from expires_in to account for clock skew
		expiresIn := tokenResp.ExpiresIn
		if expiresIn > 60 {
			expiresIn -= 60
		}

		sealedResp := SealedTokenResponse{
			SealedToken: sealedToken,
			ExpiresIn:   expiresIn,
			TokenType:   "sealed",
		}

		respJSON, err := json.Marshal(sealedResp)
		if err != nil {
			return fmt.Errorf("failed to marshal sealed response: %w", err)
		}

		resp.Body = io.NopCloser(bytes.NewReader(respJSON))
		resp.ContentLength = int64(len(respJSON))
		resp.Header.Set("Content-Type", "application/json")

		return nil
	}
}

func (c *JWTProcessorConfig) StripHazmat() ProcessorConfig {
	return &JWTProcessorConfig{
		PrivateKey: redactedBase64,
		Email:      c.Email,
		Subject:    c.Subject,
		Scopes:     c.Scopes,
		TokenURL:   c.TokenURL,
	}
}

// ClientCredentialsProcessorConfig implements the OAuth2 client_credentials grant
// (RFC 6749 section 4.4). Like JWTProcessorConfig, it performs a token exchange
// and returns a sealed access token - the caller never sees the plaintext secret.
type ClientCredentialsProcessorConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TokenURL     string `json:"token_url"`
	Scopes       string `json:"scopes,omitempty"` // space-separated, optional
}

var _ ProcessorConfig = (*ClientCredentialsProcessorConfig)(nil)
var _ ResponseProcessorConfig = (*ClientCredentialsProcessorConfig)(nil)

func (c *ClientCredentialsProcessorConfig) Processor(params map[string]string, _ *SealingContext) (RequestProcessor, error) {
	if c.ClientID == "" {
		return nil, errors.New("missing client_id")
	}
	if c.ClientSecret == "" {
		return nil, errors.New("missing client_secret")
	}
	if c.TokenURL == "" {
		return nil, errors.New("missing token_url")
	}

	return func(r *http.Request) error {
		vals := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {c.ClientID},
			"client_secret": {c.ClientSecret},
		}
		if c.Scopes != "" {
			vals.Set("scope", c.Scopes)
		}

		body := vals.Encode()
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return nil
	}, nil
}

func (c *ClientCredentialsProcessorConfig) ResponseProcessor(params map[string]string, sctx *SealingContext) (func(*http.Response) error, error) {
	if sctx == nil {
		return nil, errors.New("client_credentials response processor requires a sealing context")
	}

	return sealTokenResponse(sctx), nil
}

func (c *ClientCredentialsProcessorConfig) StripHazmat() ProcessorConfig {
	return &ClientCredentialsProcessorConfig{
		ClientID:     c.ClientID,
		ClientSecret: redactedStr,
		TokenURL:     c.TokenURL,
		Scopes:       c.Scopes,
	}
}

const (
	defaultGitHubAppTokenURL    = "https://api.github.com/app/installations/{installation_id}/access_tokens"
	githubAppHost               = "api.github.com"
	githubAppInstallationIDTmpl = "{installation_id}"
)

// GitHubAppProcessorConfig signs a JWT for a GitHub App and exchanges it for
// an installation access token. GitHub Apps use a bespoke flow (distinct from
// RFC 7523): the JWT is placed in the Authorization header (not a form body),
// the request body is empty, and the installation ID is in the URL path.
// GitHub requires RSA keys signed with RS256; other key types are rejected.
//
// Like JWTProcessorConfig, this processor also transforms the response: it
// parses GitHub's {"token": "ghs_...", "expires_at": "..."} reply, seals the
// installation token into a new InjectProcessorConfig (pinned to
// api.github.com with a `token %s` Authorization format), and replaces the
// response body with a SealedTokenResponse. The private key, the signed JWT,
// and the installation token are never visible to the caller.
type GitHubAppProcessorConfig struct {
	PrivateKey     []byte `json:"private_key"`     // PEM-encoded RSA private key
	AppID          string `json:"app_id"`          // GitHub App ID (JWT "iss")
	InstallationID string `json:"installation_id"` // substituted into TokenURL
	TokenURL       string `json:"token_url"`       // template; default is GitHub's public endpoint
}

var _ ProcessorConfig = (*GitHubAppProcessorConfig)(nil)
var _ ResponseProcessorConfig = (*GitHubAppProcessorConfig)(nil)

func (c *GitHubAppProcessorConfig) tokenURL() string {
	tmpl := c.TokenURL
	if tmpl == "" {
		tmpl = defaultGitHubAppTokenURL
	}
	return strings.ReplaceAll(tmpl, githubAppInstallationIDTmpl, c.InstallationID)
}

func (c *GitHubAppProcessorConfig) Processor(params map[string]string, _ *SealingContext) (RequestProcessor, error) {
	if len(c.PrivateKey) == 0 {
		return nil, errors.New("missing private key")
	}
	if c.AppID == "" {
		return nil, errors.New("missing app_id")
	}
	if c.InstallationID == "" {
		return nil, errors.New("missing installation_id")
	}

	block, _ := pem.Decode(c.PrivateKey)
	if block == nil {
		return nil, errors.New("invalid PEM-encoded private key")
	}

	var rsaKey *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		rsaKey = k
	} else if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			rsaKey = rk
		} else {
			return nil, errors.New("GitHub App requires an RSA private key")
		}
	} else {
		return nil, fmt.Errorf("unsupported private key format: %w", err)
	}

	target, err := url.Parse(c.tokenURL())
	if err != nil {
		return nil, fmt.Errorf("invalid token_url: %w", err)
	}
	if target.Path == "" {
		return nil, errors.New("token_url must include a path")
	}

	return func(r *http.Request) error {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": c.AppID,
			"iat": now.Unix(),
			"exp": now.Add(10 * time.Minute).Unix(),
		}

		signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(rsaKey)
		if err != nil {
			return fmt.Errorf("failed to sign JWT: %w", err)
		}

		r.Header.Set("Authorization", "Bearer "+signed)
		r.Header.Set("Accept", "application/vnd.github+json")
		r.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		r.URL.Path = target.Path
		r.URL.RawPath = target.RawPath

		r.Body = http.NoBody
		r.ContentLength = 0
		r.Header.Del("Content-Type")

		return nil
	}, nil
}

func (c *GitHubAppProcessorConfig) ResponseProcessor(_ map[string]string, sctx *SealingContext) (func(*http.Response) error, error) {
	if sctx == nil {
		return nil, errors.New("github_app response processor requires a sealing context")
	}

	return func(resp *http.Response) error {
		if resp.StatusCode != http.StatusOK {
			return nil
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read token response: %w", err)
		}

		var tokenResp struct {
			Token     string    `json:"token"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			return fmt.Errorf("failed to parse token response: %w", err)
		}

		if tokenResp.Token == "" {
			return errors.New("token response missing token")
		}

		// Installation tokens can only be replayed against api.github.com. Pin
		// the sealed secret even if the outer secret didn't.
		newSecret := &Secret{
			AuthConfig: sctx.AuthConfig,
			ProcessorConfig: &InjectProcessorConfig{
				Token:        tokenResp.Token,
				FmtProcessor: FmtProcessor{Fmt: "token %s"},
			},
			RequestValidators: []RequestValidator{AllowHosts(githubAppHost)},
		}

		sealed, err := newSecret.sealRaw(sctx.SealKey)
		if err != nil {
			return fmt.Errorf("failed to seal installation token: %w", err)
		}

		expiresIn := 3600
		if !tokenResp.ExpiresAt.IsZero() {
			if secs := int(time.Until(tokenResp.ExpiresAt).Seconds()); secs > 0 {
				expiresIn = secs
			}
		}
		if expiresIn > 60 {
			expiresIn -= 60
		}

		sealedResp := SealedTokenResponse{
			SealedToken: sealed,
			ExpiresIn:   expiresIn,
			TokenType:   "sealed",
		}

		respJSON, err := json.Marshal(sealedResp)
		if err != nil {
			return fmt.Errorf("failed to marshal sealed response: %w", err)
		}

		resp.Body = io.NopCloser(bytes.NewReader(respJSON))
		resp.ContentLength = int64(len(respJSON))
		resp.Header.Set("Content-Type", "application/json")

		return nil
	}, nil
}

func (c *GitHubAppProcessorConfig) StripHazmat() ProcessorConfig {
	return &GitHubAppProcessorConfig{
		PrivateKey:     redactedBase64,
		AppID:          c.AppID,
		InstallationID: c.InstallationID,
		TokenURL:       c.TokenURL,
	}
}

type MultiProcessorConfig []ProcessorConfig

var _ ProcessorConfig = new(MultiProcessorConfig)

func (c MultiProcessorConfig) Processor(params map[string]string, sctx *SealingContext) (RequestProcessor, error) {
	var processors []RequestProcessor
	for _, cfg := range c {
		proc, err := cfg.Processor(params, sctx)
		if err != nil {
			return nil, err
		}
		processors = append(processors, proc)
	}

	return func(r *http.Request) error {
		for _, proc := range processors {
			if err := proc(r); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func (c *MultiProcessorConfig) StripHazmat() ProcessorConfig {
	ret := make(MultiProcessorConfig, len(*c))
	for n, p := range *c {
		ret[n] = p.StripHazmat()
	}
	return &ret
}

func (c MultiProcessorConfig) MarshalJSON() ([]byte, error) {
	wps := make([]wireProcessor, 0, len(c))
	for _, p := range c {
		wp, err := newWireProcessor(p)
		if err != nil {
			return nil, err
		}
		wps = append(wps, wp)
	}

	return json.Marshal(wps)
}

func (c *MultiProcessorConfig) UnmarshalJSON(b []byte) error {
	var wps []wireProcessor
	if err := json.Unmarshal(b, &wps); err != nil {
		return err
	}
	if len(wps) == 0 {
		return nil
	}

	for _, wp := range wps {
		cfg, err := wp.getProcessorConfig()
		if err != nil {
			return err
		}
		*c = append(*c, cfg)
	}

	return nil
}

// A helper type to be embedded in RequestProcessors wanting to use the `fmt` config/param.
type FmtProcessor struct {
	Fmt        string   `json:"fmt,omitempty"`
	AllowedFmt []string `json:"allowed_fmt,omitempty"`
}

// Apply the format string from the secret config or parameters. isBinary
// dictates whether %s or %x should be allowed. arg is passed to the sprintf
// call.
func (fp FmtProcessor) ApplyFmt(params map[string]string, isBinary bool, arg any) (string, error) {
	format, hasParam := params[ParamFmt]

	// apply default for param
	switch {
	case hasParam:
		// ok
	case fp.Fmt != "":
		format = fp.Fmt
	case len(fp.AllowedFmt) != 0:
		format = fp.AllowedFmt[0]
	case isBinary:
		format = "Bearer %x"
	default:
		format = "Bearer %s"
	}

	// check if param is allowed
	if fp.Fmt != "" && format != fp.Fmt {
		return "", errors.New("bad fmt")
	}
	if fp.AllowedFmt != nil && !slices.Contains(fp.AllowedFmt, format) {
		return "", errors.New("bad fmt")
	}

	i := strings.IndexRune(format, '%')

	switch i {
	case -1:
		// no format directive
		return "", errors.New("bad fmt")
	case len(format) - 1:
		// last char is %
		return "", errors.New("bad fmt")
	}

	// only permit simple (%s, %x, %X) format directives
	// TODO: implement ruby's %m (base64)
	switch format[i+1] {
	case 'x', 'X':
		if !isBinary {
			return "", errors.New("bad fmt")
		}
	case 's':
		if isBinary {
			return "", errors.New("bad fmt")
		}
	default:
		return "", errors.New("bad fmt")
	}

	// only permit single format directive
	if strings.ContainsRune(format[i+2:], '%') {
		return "", errors.New("bad fmt")
	}

	return fmt.Sprintf(format, arg), nil
}

// A helper type to be embedded in RequestProcessors wanting to use the `dst` config/param.
type DstProcessor struct {
	Dst        string   `json:"dst,omitempty"`
	AllowedDst []string `json:"allowed_dst,omitempty"`
}

// Apply the specified val to the correct destination header in the request.
func (fp DstProcessor) ApplyDst(params map[string]string, r *http.Request, val string) error {
	dst, hasParam := params[ParamDst]

	// apply default for param
	switch {
	case hasParam:
		// ok
	case fp.Dst != "":
		dst = fp.Dst
	case len(fp.AllowedDst) != 0:
		dst = fp.AllowedDst[0]
	default:
		dst = "Authorization"
	}

	dst = textproto.CanonicalMIMEHeaderKey(dst)

	// check if param is allowed
	if fp.Dst != "" && dst != textproto.CanonicalMIMEHeaderKey(fp.Dst) {
		return errors.New("bad dst")
	}
	if fp.AllowedDst != nil {
		var found bool
		for _, a := range fp.AllowedDst {
			if dst == textproto.CanonicalMIMEHeaderKey(a) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("bad dst")
		}
	}

	r.Header.Set(dst, val)

	return nil
}
