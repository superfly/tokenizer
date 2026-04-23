package tokenizer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/nacl/box"
)

func TestFmtProcessor(t *testing.T) {
	p := FmtProcessor{}

	val, err := p.ApplyFmt(map[string]string{}, true, []byte{1, 2, 3})
	assert.NoError(t, err)
	assert.Equal(t, "Bearer 010203", val)

	val, err = p.ApplyFmt(map[string]string{}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "Bearer 123", val)

	val, err = p.ApplyFmt(map[string]string{ParamFmt: "%x"}, true, []byte{1, 2, 3})
	assert.NoError(t, err)
	assert.Equal(t, "010203", val)

	val, err = p.ApplyFmt(map[string]string{ParamFmt: "%X"}, true, []byte{1, 2, 3})
	assert.NoError(t, err)
	assert.Equal(t, "010203", val)

	val, err = p.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "%d"}, false, "123")
	assert.Error(t, err)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "%.3s"}, false, "123")
	assert.Error(t, err)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "%s%s"}, false, "123")
	assert.Error(t, err)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "asdf%"}, false, "123")
	assert.Error(t, err)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "asdf"}, false, "123")
	assert.Error(t, err)

	val, err = FmtProcessor{AllowedFmt: []string{"%s"}}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	_, err = FmtProcessor{AllowedFmt: []string{"x %s"}}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.Error(t, err)

	val, err = FmtProcessor{Fmt: "%s"}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	_, err = FmtProcessor{Fmt: "x %s"}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.Error(t, err)

	val, err = FmtProcessor{Fmt: "%s", AllowedFmt: []string{"%s"}}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	val, err = FmtProcessor{Fmt: "%s", AllowedFmt: []string{"%s"}}.ApplyFmt(map[string]string{}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	_, err = FmtProcessor{Fmt: "%s", AllowedFmt: []string{"x %s"}}.ApplyFmt(map[string]string{}, false, "123")
	assert.Error(t, err)
}

func TestDstProcessor(t *testing.T) {
	assertResult := func(expected string, dp DstProcessor, params map[string]string) {
		t.Helper()

		r := http.Request{Header: make(http.Header)}
		err := dp.ApplyDst(params, &r, "123")
		if expected == "error" {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			buf := new(bytes.Buffer)
			assert.NoError(t, r.Header.Write(buf))
			assert.Equal(t, expected, strings.TrimSpace(buf.String()))
		}
	}

	assertResult("Authorization: 123", DstProcessor{}, map[string]string{})
	assertResult("Authorization: 123", DstProcessor{}, map[string]string{ParamDst: "Authorization"})
	assertResult("Authorization: 123", DstProcessor{}, map[string]string{ParamDst: "AuThOriZaTiOn"})
	assertResult("Foo: 123", DstProcessor{}, map[string]string{ParamDst: "Foo"})
	assertResult("Foo: 123", DstProcessor{Dst: "Foo", AllowedDst: []string{"Foo"}}, map[string]string{ParamDst: "Foo"})
	assertResult("Foo: 123", DstProcessor{Dst: "Foo", AllowedDst: []string{"fOo"}}, map[string]string{ParamDst: "foO"})
	assertResult("Foo: 123", DstProcessor{AllowedDst: []string{"fOo"}}, map[string]string{ParamDst: "foO"})
	assertResult("Foo: 123", DstProcessor{Dst: "Foo"}, map[string]string{ParamDst: "foO"})
	assertResult("Foo: 123", DstProcessor{Dst: "Foo", AllowedDst: []string{"fOo"}}, map[string]string{})
	assertResult("error", DstProcessor{Dst: "Foo", AllowedDst: []string{"Bar"}}, map[string]string{ParamDst: "Foo"})
	assertResult("error", DstProcessor{Dst: "Foo", AllowedDst: []string{"Bar"}}, map[string]string{})
	assertResult("error", DstProcessor{AllowedDst: []string{"Bar"}}, map[string]string{ParamDst: "Foo"})
	assertResult("error", DstProcessor{Dst: "Bar"}, map[string]string{ParamDst: "Foo"})
}

func TestInjectBodyProcessorConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       InjectBodyProcessorConfig
		params       map[string]string
		requestBody  string
		expectedBody string
	}{
		{
			name:         "simple replacement with default placeholder",
			config:       InjectBodyProcessorConfig{Token: "secret-token-123"},
			params:       map[string]string{},
			requestBody:  `{"token": "{{ACCESS_TOKEN}}"}`,
			expectedBody: `{"token": "secret-token-123"}`,
		},
		{
			name:         "multiple occurrences",
			config:       InjectBodyProcessorConfig{Token: "secret-token-123"},
			params:       map[string]string{},
			requestBody:  `{"access": "{{ACCESS_TOKEN}}", "refresh": "{{ACCESS_TOKEN}}"}`,
			expectedBody: `{"access": "secret-token-123", "refresh": "secret-token-123"}`,
		},
		{
			name:         "custom placeholder from params",
			config:       InjectBodyProcessorConfig{Token: "secret-token-123"},
			params:       map[string]string{ParamPlaceholder: "<<TOKEN>>"},
			requestBody:  `{"token": "<<TOKEN>>"}`,
			expectedBody: `{"token": "secret-token-123"}`,
		},
		{
			name:         "custom placeholder from config",
			config:       InjectBodyProcessorConfig{Token: "secret-token-123", Placeholder: "[[TOKEN]]"},
			params:       map[string]string{},
			requestBody:  `{"token": "[[TOKEN]]"}`,
			expectedBody: `{"token": "secret-token-123"}`,
		},
		{
			name:         "param overrides config placeholder",
			config:       InjectBodyProcessorConfig{Token: "secret-token-123", Placeholder: "[[TOKEN]]"},
			params:       map[string]string{ParamPlaceholder: "<<TOKEN>>"},
			requestBody:  `{"token": "<<TOKEN>>"}`,
			expectedBody: `{"token": "secret-token-123"}`,
		},
		{
			name:         "no matches - placeholder not found",
			config:       InjectBodyProcessorConfig{Token: "secret-token-123"},
			params:       map[string]string{},
			requestBody:  `{"token": "different-placeholder"}`,
			expectedBody: `{"token": "different-placeholder"}`,
		},
		{
			name:         "empty body",
			config:       InjectBodyProcessorConfig{Token: "secret-token-123"},
			params:       map[string]string{},
			requestBody:  "",
			expectedBody: "",
		},
		{
			name:         "large body with streaming",
			config:       InjectBodyProcessorConfig{Token: "secret-token-123"},
			params:       map[string]string{},
			requestBody:  strings.Repeat("{{ACCESS_TOKEN}}", 10000),
			expectedBody: strings.Repeat("secret-token-123", 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc, err := tt.config.Processor(tt.params, nil)
			assert.NoError(t, err)

			req := &http.Request{
				Header: make(http.Header),
			}
			if tt.requestBody != "" {
				req.Body = http.NoBody
			}
			if tt.requestBody != "" {
				req.Body = stringToReadCloser(tt.requestBody)
			}

			err = proc(req)
			assert.NoError(t, err)

			if tt.expectedBody == "" && (tt.requestBody == "" || tt.requestBody == "nil") {
				return
			}

			bodyBytes := new(bytes.Buffer)
			_, err = bodyBytes.ReadFrom(req.Body)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, bodyBytes.String())
			// ContentLength is 0 for chunked transfer encoding
			assert.Equal(t, int64(0), req.ContentLength)
		})
	}
}

func TestOAuthProcessorConfigBodyInjection(t *testing.T) {
	tests := []struct {
		name         string
		config       OAuthProcessorConfig
		params       map[string]string
		requestBody  string
		expectedBody string
		checkHeader  bool
	}{
		{
			name: "body injection with placeholder parameter",
			config: OAuthProcessorConfig{
				Token: &OAuthToken{AccessToken: "access-123", RefreshToken: "refresh-456"},
			},
			params:       map[string]string{ParamPlaceholder: "{{ACCESS_TOKEN}}"},
			requestBody:  `{"token": "{{ACCESS_TOKEN}}"}`,
			expectedBody: `{"token": "access-123"}`,
			checkHeader:  false,
		},
		{
			name: "body injection with refresh token",
			config: OAuthProcessorConfig{
				Token: &OAuthToken{AccessToken: "access-123", RefreshToken: "refresh-456"},
			},
			params:       map[string]string{ParamPlaceholder: "{{TOKEN}}", ParamSubtoken: SubtokenRefresh},
			requestBody:  `{"token": "{{TOKEN}}"}`,
			expectedBody: `{"token": "refresh-456"}`,
			checkHeader:  false,
		},
		{
			name: "header injection when no placeholder",
			config: OAuthProcessorConfig{
				Token: &OAuthToken{AccessToken: "access-123"},
			},
			params:      map[string]string{},
			checkHeader: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc, err := tt.config.Processor(tt.params, nil)
			assert.NoError(t, err)

			req := &http.Request{
				Header: make(http.Header),
			}
			if tt.requestBody != "" {
				req.Body = stringToReadCloser(tt.requestBody)
			}

			err = proc(req)
			assert.NoError(t, err)

			if tt.checkHeader {
				// Header injection: verify Authorization header is set and body is unchanged
				assert.Equal(t, "Bearer access-123", req.Header.Get("Authorization"))
				// Body should be unchanged (nil or original)
				if tt.requestBody != "" {
					bodyBytes := new(bytes.Buffer)
					_, err = bodyBytes.ReadFrom(req.Body)
					assert.NoError(t, err)
					assert.Equal(t, tt.requestBody, bodyBytes.String())
				}
			} else {
				// Body injection: verify body is modified and Authorization header is NOT set
				bodyBytes := new(bytes.Buffer)
				_, err = bodyBytes.ReadFrom(req.Body)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, bodyBytes.String())
				// ContentLength is 0 for chunked transfer encoding
				assert.Equal(t, int64(0), req.ContentLength)
				// Authorization header should NOT be set during body injection
				assert.Equal(t, "", req.Header.Get("Authorization"))
			}
		})
	}
}

func TestOAuthBodyProcessorConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       OAuthBodyProcessorConfig
		params       map[string]string
		requestBody  string
		expectedBody string
	}{
		{
			name: "simple replacement with access token",
			config: OAuthBodyProcessorConfig{
				Token: &OAuthToken{AccessToken: "access-123", RefreshToken: "refresh-456"},
			},
			params:       map[string]string{},
			requestBody:  `{"token": "{{ACCESS_TOKEN}}"}`,
			expectedBody: `{"token": "access-123"}`,
		},
		{
			name: "replacement with refresh token",
			config: OAuthBodyProcessorConfig{
				Token: &OAuthToken{AccessToken: "access-123", RefreshToken: "refresh-456"},
			},
			params:       map[string]string{ParamSubtoken: SubtokenRefresh},
			requestBody:  `{"token": "{{ACCESS_TOKEN}}"}`,
			expectedBody: `{"token": "refresh-456"}`,
		},
		{
			name: "custom placeholder from params",
			config: OAuthBodyProcessorConfig{
				Token: &OAuthToken{AccessToken: "access-123"},
			},
			params:       map[string]string{ParamPlaceholder: "<<TOKEN>>"},
			requestBody:  `{"token": "<<TOKEN>>"}`,
			expectedBody: `{"token": "access-123"}`,
		},
		{
			name: "custom placeholder from config",
			config: OAuthBodyProcessorConfig{
				Token:       &OAuthToken{AccessToken: "access-123"},
				Placeholder: "[[TOKEN]]",
			},
			params:       map[string]string{},
			requestBody:  `{"token": "[[TOKEN]]"}`,
			expectedBody: `{"token": "access-123"}`,
		},
		{
			name: "multiple occurrences",
			config: OAuthBodyProcessorConfig{
				Token: &OAuthToken{AccessToken: "access-123"},
			},
			params:       map[string]string{},
			requestBody:  `{"client_id": "id", "client_secret": "secret", "token": "{{ACCESS_TOKEN}}", "token_type_hint": "{{ACCESS_TOKEN}}"}`,
			expectedBody: `{"client_id": "id", "client_secret": "secret", "token": "access-123", "token_type_hint": "access-123"}`,
		},
		{
			name: "nil body",
			config: OAuthBodyProcessorConfig{
				Token: &OAuthToken{AccessToken: "access-123"},
			},
			params:      map[string]string{},
			requestBody: "",
		},
		{
			name: "large body with streaming",
			config: OAuthBodyProcessorConfig{
				Token: &OAuthToken{AccessToken: "access-123"},
			},
			params:       map[string]string{},
			requestBody:  `{"data": "` + strings.Repeat("x", 50000) + `", "token": "{{ACCESS_TOKEN}}"}`,
			expectedBody: `{"data": "` + strings.Repeat("x", 50000) + `", "token": "access-123"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc, err := tt.config.Processor(tt.params, nil)
			assert.NoError(t, err)

			req := &http.Request{
				Header: make(http.Header),
			}
			if tt.requestBody != "" {
				req.Body = stringToReadCloser(tt.requestBody)
			}

			err = proc(req)
			assert.NoError(t, err)

			if tt.requestBody == "" {
				return
			}

			bodyBytes := new(bytes.Buffer)
			_, err = bodyBytes.ReadFrom(req.Body)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, bodyBytes.String())
			// ContentLength is 0 for chunked transfer encoding
			assert.Equal(t, int64(0), req.ContentLength)
		})
	}
}

// Helper function to convert string to io.ReadCloser
func stringToReadCloser(s string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(s))
}

func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, pemBytes
}

func generateTestECKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	assert.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return key, pemBytes
}

func generateTestEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	assert.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return pub, priv, pemBytes
}

func generateTestSealKey(t *testing.T) (sealKey string, pub *[32]byte, priv *[32]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	return hex.EncodeToString(pub[:]), pub, priv
}

func TestJWTProcessorConfig_Processor_BuildsValidJWT(t *testing.T) {
	rsaKey, pemBytes := generateTestRSAKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	// Verify Content-Type is set
	assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))

	// Read the body and parse the form
	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	bodyStr := string(body)

	// Verify grant_type
	assert.Contains(t, bodyStr, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer")

	// Extract the assertion parameter
	var assertion string
	for _, param := range strings.Split(bodyStr, "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) == 2 && kv[0] == "assertion" {
			assertion = kv[1]
		}
	}
	assert.NotEqual(t, "", assertion)

	// Parse and verify the JWT
	token, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		assert.Equal(t, "RS256", token.Method.Alg())
		return &rsaKey.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, "test-sa@my-project.iam.gserviceaccount.com", claims["iss"])
	assert.Equal(t, "https://www.googleapis.com/auth/admin.directory.user", claims["scope"])
	assert.Equal(t, "https://oauth2.googleapis.com/token", claims["aud"])

	// Verify iat and exp are set and exp is ~1 hour after iat
	iat, ok := claims["iat"].(float64)
	assert.True(t, ok)
	exp, ok := claims["exp"].(float64)
	assert.True(t, ok)
	assert.True(t, exp-iat >= 3599 && exp-iat <= 3601)
	assert.True(t, time.Unix(int64(iat), 0).Before(time.Now().Add(time.Minute)))
}

func TestJWTProcessorConfig_Processor_SubjectAndScopesFromParams(t *testing.T) {
	rsaKey, pemBytes := generateTestRSAKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	params := map[string]string{
		ParamSubject: "admin@example.com",
		ParamScopes:  "https://www.googleapis.com/auth/gmail.readonly",
	}

	proc, err := cfg.Processor(params, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	// Extract and parse the JWT from the body
	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	var assertion string
	for _, param := range strings.Split(string(body), "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) == 2 && kv[0] == "assertion" {
			assertion = kv[1]
		}
	}

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		return &rsaKey.PublicKey, nil
	})
	assert.NoError(t, err)
	claims := token.Claims.(jwt.MapClaims)

	// Params should override config
	assert.Equal(t, "admin@example.com", claims["sub"])
	assert.Equal(t, "https://www.googleapis.com/auth/gmail.readonly", claims["scope"])
}

func TestJWTProcessorConfig_Processor_SubjectFromConfig(t *testing.T) {
	rsaKey, pemBytes := generateTestRSAKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Subject:    "default-admin@example.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	var assertion string
	for _, param := range strings.Split(string(body), "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) == 2 && kv[0] == "assertion" {
			assertion = kv[1]
		}
	}

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		return &rsaKey.PublicKey, nil
	})
	assert.NoError(t, err)
	claims := token.Claims.(jwt.MapClaims)
	assert.Equal(t, "default-admin@example.com", claims["sub"])
}

func TestJWTProcessorConfig_Processor_MissingPrivateKey(t *testing.T) {
	cfg := &JWTProcessorConfig{
		Email:    "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:   "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL: "https://oauth2.googleapis.com/token",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestJWTProcessorConfig_Processor_InvalidPrivateKey(t *testing.T) {
	cfg := &JWTProcessorConfig{
		PrivateKey: []byte("not-a-real-key"),
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestJWTProcessorConfig_Processor_MissingEmail(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestJWTProcessorConfig_Processor_DefaultTokenURL(t *testing.T) {
	rsaKey, pemBytes := generateTestRSAKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		// TokenURL intentionally omitted - should default to Google's endpoint
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	var assertion string
	for _, param := range strings.Split(string(body), "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) == 2 && kv[0] == "assertion" {
			assertion = kv[1]
		}
	}

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		return &rsaKey.PublicKey, nil
	})
	assert.NoError(t, err)
	claims := token.Claims.(jwt.MapClaims)
	// Default token URL should be used as the aud claim
	assert.Equal(t, defaultTokenURL, claims["aud"])
}

func TestJWTProcessorConfig_Processor_ECDSAKey(t *testing.T) {
	ecKey, pemBytes := generateTestECKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	var assertion string
	for _, param := range strings.Split(string(body), "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) == 2 && kv[0] == "assertion" {
			assertion = kv[1]
		}
	}
	assert.NotEqual(t, "", assertion)

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		assert.Equal(t, "ES256", token.Method.Alg())
		return &ecKey.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims := token.Claims.(jwt.MapClaims)
	assert.Equal(t, "test-sa@my-project.iam.gserviceaccount.com", claims["iss"])
}

func TestJWTProcessorConfig_Processor_Ed25519Key(t *testing.T) {
	pubKey, _, pemBytes := generateTestEd25519Key(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	var assertion string
	for _, param := range strings.Split(string(body), "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) == 2 && kv[0] == "assertion" {
			assertion = kv[1]
		}
	}
	assert.NotEqual(t, "", assertion)

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		assert.Equal(t, "EdDSA", token.Method.Alg())
		return pubKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims := token.Claims.(jwt.MapClaims)
	assert.Equal(t, "test-sa@my-project.iam.gserviceaccount.com", claims["iss"])
}

func TestJWTProcessorConfig_StripHazmat(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Subject:    "admin@example.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	stripped := cfg.StripHazmat().(*JWTProcessorConfig)

	// Private key should be redacted
	assert.NotEqual(t, pemBytes, stripped.PrivateKey)
	assert.Equal(t, redactedBase64, stripped.PrivateKey)

	// Non-hazmat fields should be preserved
	assert.Equal(t, "test-sa@my-project.iam.gserviceaccount.com", stripped.Email)
	assert.Equal(t, "admin@example.com", stripped.Subject)
	assert.Equal(t, "https://www.googleapis.com/auth/admin.directory.user", stripped.Scopes)
	assert.Equal(t, "https://oauth2.googleapis.com/token", stripped.TokenURL)
}

func TestJWTProcessorConfig_ResponseProcessor_SealsAccessToken(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)
	sealKey, pub, priv := generateTestSealKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	authCfg := NewBearerAuthConfig("trustno1")
	validators := []RequestValidator{AllowHosts("oauth2.googleapis.com", "admin.googleapis.com")}

	ctx := &SealingContext{
		AuthConfig:        authCfg,
		RequestValidators: validators,
		SealKey:           pub,
	}

	respProc, err := cfg.ResponseProcessor(nil, ctx)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, respProc)

	// Simulate Google's token response
	googleResponse := `{"access_token":"ya29.test-access-token","expires_in":3600,"token_type":"Bearer"}`
	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(googleResponse)),
		Header:     make(http.Header),
	}

	err = respProc(resp)
	assert.NoError(t, err)

	// Read the modified response body
	respBody, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	var sealedResp SealedTokenResponse
	err = json.Unmarshal(respBody, &sealedResp)
	assert.NoError(t, err)

	assert.Equal(t, "sealed", sealedResp.TokenType)
	assert.True(t, sealedResp.ExpiresIn > 0 && sealedResp.ExpiresIn <= 3600)
	assert.NotEqual(t, "", sealedResp.SealedToken)

	// Unseal the token and verify it's a valid InjectProcessorConfig
	secret, err := unsealSecret(sealedResp.SealedToken, pub, priv)
	assert.NoError(t, err)

	injector, ok := secret.ProcessorConfig.(*InjectProcessorConfig)
	assert.True(t, ok)
	assert.Equal(t, "ya29.test-access-token", injector.Token)

	// Verify auth config was forwarded
	_ = sealKey // used for sealing
	secretJSON, err := json.Marshal(secret)
	assert.NoError(t, err)
	assert.Contains(t, string(secretJSON), "bearer_auth")

	// Verify allowed hosts were forwarded
	assert.Contains(t, string(secretJSON), "admin.googleapis.com")
	assert.Contains(t, string(secretJSON), "oauth2.googleapis.com")
}

func TestJWTProcessorConfig_ResponseProcessor_NonOKStatus(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)
	_, pub, _ := generateTestSealKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	ctx := &SealingContext{
		AuthConfig:        NewBearerAuthConfig("trustno1"),
		RequestValidators: nil,
		SealKey:           pub,
	}

	respProc, err := cfg.ResponseProcessor(nil, ctx)
	assert.NoError(t, err)

	// Simulate an error response from Google
	resp := &http.Response{
		StatusCode: 400,
		Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`)),
		Header:     make(http.Header),
	}

	// Should pass through error responses without modification
	err = respProc(resp)
	assert.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "invalid_grant")
}

func TestJWTProcessorConfig_ResponseProcessor_NilContext(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	cfg := &JWTProcessorConfig{
		PrivateKey: pemBytes,
		Email:      "test-sa@my-project.iam.gserviceaccount.com",
		Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
		TokenURL:   "https://oauth2.googleapis.com/token",
	}

	// Without a SealingContext, ResponseProcessor should return an error
	_, err := cfg.ResponseProcessor(nil, nil)
	assert.Error(t, err)
}

func TestJWTProcessorConfig_JSONRoundTrip(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	original := &Secret{
		AuthConfig: NewBearerAuthConfig("trustno1"),
		ProcessorConfig: &JWTProcessorConfig{
			PrivateKey: pemBytes,
			Email:      "test-sa@my-project.iam.gserviceaccount.com",
			Subject:    "admin@example.com",
			Scopes:     "https://www.googleapis.com/auth/admin.directory.user",
			TokenURL:   "https://oauth2.googleapis.com/token",
		},
		RequestValidators: []RequestValidator{AllowHosts("oauth2.googleapis.com", "admin.googleapis.com")},
	}

	data, err := json.Marshal(original)
	assert.NoError(t, err)

	// Verify the JSON has the right key
	assert.Contains(t, string(data), "jwt_processor")

	var restored Secret
	err = json.Unmarshal(data, &restored)
	assert.NoError(t, err)

	jwtCfg, ok := restored.ProcessorConfig.(*JWTProcessorConfig)
	assert.True(t, ok)
	assert.Equal(t, pemBytes, jwtCfg.PrivateKey)
	assert.Equal(t, "test-sa@my-project.iam.gserviceaccount.com", jwtCfg.Email)
	assert.Equal(t, "admin@example.com", jwtCfg.Subject)
	assert.Equal(t, "https://www.googleapis.com/auth/admin.directory.user", jwtCfg.Scopes)
	assert.Equal(t, "https://oauth2.googleapis.com/token", jwtCfg.TokenURL)
}

func TestClientCredentialsProcessorConfig_BuildsCorrectBody(t *testing.T) {
	cfg := &ClientCredentialsProcessorConfig{
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
		TokenURL:     "https://api.helpscout.net/v2/oauth2/token",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, cfg.TokenURL, nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))

	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)

	vals, err := url.ParseQuery(string(body))
	assert.NoError(t, err)

	assert.Equal(t, "client_credentials", vals.Get("grant_type"))
	assert.Equal(t, "my-client-id", vals.Get("client_id"))
	assert.Equal(t, "my-client-secret", vals.Get("client_secret"))
}

func TestClientCredentialsProcessorConfig_IncludesScopeWhenSet(t *testing.T) {
	cfg := &ClientCredentialsProcessorConfig{
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
		TokenURL:     "https://api.helpscout.net/v2/oauth2/token",
		Scopes:       "mailbox.read mailbox.write",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, cfg.TokenURL, nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)

	vals, err := url.ParseQuery(string(body))
	assert.NoError(t, err)

	assert.Equal(t, "mailbox.read mailbox.write", vals.Get("scope"))
}

func TestClientCredentialsProcessorConfig_OmitsScopeWhenEmpty(t *testing.T) {
	cfg := &ClientCredentialsProcessorConfig{
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
		TokenURL:     "https://api.helpscout.net/v2/oauth2/token",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, cfg.TokenURL, nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)

	assert.NotContains(t, string(body), "scope=")
}

func TestClientCredentialsProcessorConfig_MissingClientID(t *testing.T) {
	cfg := &ClientCredentialsProcessorConfig{
		ClientSecret: "my-client-secret",
		TokenURL:     "https://api.helpscout.net/v2/oauth2/token",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestClientCredentialsProcessorConfig_MissingClientSecret(t *testing.T) {
	cfg := &ClientCredentialsProcessorConfig{
		ClientID: "my-client-id",
		TokenURL: "https://api.helpscout.net/v2/oauth2/token",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestClientCredentialsProcessorConfig_MissingTokenURL(t *testing.T) {
	cfg := &ClientCredentialsProcessorConfig{
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestClientCredentialsProcessorConfig_StripHazmat(t *testing.T) {
	cfg := &ClientCredentialsProcessorConfig{
		ClientID:     "my-client-id",
		ClientSecret: "super-secret",
		TokenURL:     "https://api.helpscout.net/v2/oauth2/token",
		Scopes:       "mailbox.read",
	}

	stripped := cfg.StripHazmat().(*ClientCredentialsProcessorConfig)

	assert.Equal(t, redactedStr, stripped.ClientSecret)
	assert.Equal(t, "my-client-id", stripped.ClientID)
	assert.Equal(t, "https://api.helpscout.net/v2/oauth2/token", stripped.TokenURL)
	assert.Equal(t, "mailbox.read", stripped.Scopes)
}

func TestClientCredentialsProcessorConfig_ResponseProcessor_SealsAccessToken(t *testing.T) {
	_, pub, priv := generateTestSealKey(t)

	cfg := &ClientCredentialsProcessorConfig{
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
		TokenURL:     "https://api.helpscout.net/v2/oauth2/token",
	}

	ctx := &SealingContext{
		AuthConfig:        NewBearerAuthConfig("trustno1"),
		RequestValidators: []RequestValidator{AllowHosts("api.helpscout.net")},
		SealKey:           pub,
	}

	respProc, err := cfg.ResponseProcessor(nil, ctx)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, respProc)

	tokenResponse := `{"access_token":"hs-access-token-xyz","expires_in":7200,"token_type":"Bearer"}`
	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(tokenResponse)),
		Header:     make(http.Header),
	}

	err = respProc(resp)
	assert.NoError(t, err)

	respBody, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	var sealedResp SealedTokenResponse
	err = json.Unmarshal(respBody, &sealedResp)
	assert.NoError(t, err)

	assert.Equal(t, "sealed", sealedResp.TokenType)
	assert.True(t, sealedResp.ExpiresIn > 0 && sealedResp.ExpiresIn <= 7200)
	assert.NotEqual(t, "", sealedResp.SealedToken)

	secret, err := unsealSecret(sealedResp.SealedToken, pub, priv)
	assert.NoError(t, err)

	injector, ok := secret.ProcessorConfig.(*InjectProcessorConfig)
	assert.True(t, ok)
	assert.Equal(t, "hs-access-token-xyz", injector.Token)
}

func TestClientCredentialsProcessorConfig_ResponseProcessor_NonOKStatus(t *testing.T) {
	_, pub, _ := generateTestSealKey(t)

	cfg := &ClientCredentialsProcessorConfig{
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
		TokenURL:     "https://api.helpscout.net/v2/oauth2/token",
	}

	ctx := &SealingContext{
		AuthConfig: NewBearerAuthConfig("trustno1"),
		SealKey:    pub,
	}

	respProc, err := cfg.ResponseProcessor(nil, ctx)
	assert.NoError(t, err)

	resp := &http.Response{
		StatusCode: 401,
		Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_client"}`)),
		Header:     make(http.Header),
	}

	err = respProc(resp)
	assert.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "invalid_client")
}

func TestClientCredentialsProcessorConfig_ResponseProcessor_NilContext(t *testing.T) {
	cfg := &ClientCredentialsProcessorConfig{
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
		TokenURL:     "https://api.helpscout.net/v2/oauth2/token",
	}

	_, err := cfg.ResponseProcessor(nil, nil)
	assert.Error(t, err)
}

func TestClientCredentialsProcessorConfig_JSONRoundTrip(t *testing.T) {
	original := &Secret{
		AuthConfig: NewBearerAuthConfig("trustno1"),
		ProcessorConfig: &ClientCredentialsProcessorConfig{
			ClientID:     "my-client-id",
			ClientSecret: "my-client-secret",
			TokenURL:     "https://api.helpscout.net/v2/oauth2/token",
			Scopes:       "mailbox.read mailbox.write",
		},
		RequestValidators: []RequestValidator{AllowHosts("api.helpscout.net")},
	}

	data, err := json.Marshal(original)
	assert.NoError(t, err)

	assert.Contains(t, string(data), "client_credentials_processor")

	var restored Secret
	err = json.Unmarshal(data, &restored)
	assert.NoError(t, err)

	ccCfg, ok := restored.ProcessorConfig.(*ClientCredentialsProcessorConfig)
	assert.True(t, ok)
	assert.Equal(t, "my-client-id", ccCfg.ClientID)
	assert.Equal(t, "my-client-secret", ccCfg.ClientSecret)
	assert.Equal(t, "https://api.helpscout.net/v2/oauth2/token", ccCfg.TokenURL)
	assert.Equal(t, "mailbox.read mailbox.write", ccCfg.Scopes)
}

func TestGitHubAppProcessorConfig_Processor_BuildsValidJWT(t *testing.T) {
	rsaKey, pemBytes := generateTestRSAKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		AppID:          "123456",
		InstallationID: "789012",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://api.github.com/", nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	// Verify GitHub-required headers
	authHeader := req.Header.Get("Authorization")
	assert.True(t, strings.HasPrefix(authHeader, "Bearer "))
	assert.Equal(t, "application/vnd.github+json", req.Header.Get("Accept"))
	assert.Equal(t, "2022-11-28", req.Header.Get("X-GitHub-Api-Version"))

	// URL path is rewritten to the installation access_tokens endpoint
	assert.Equal(t, "/app/installations/789012/access_tokens", req.URL.Path)

	// Request body is empty (GitHub requires no body)
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		assert.NoError(t, err)
		assert.Equal(t, 0, len(body))
	}
	assert.Equal(t, int64(0), req.ContentLength)

	// Parse and verify the JWT
	jwtStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(jwtStr, func(token *jwt.Token) (interface{}, error) {
		assert.Equal(t, "RS256", token.Method.Alg())
		return &rsaKey.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, "123456", claims["iss"])

	// exp should be ~10min after iat (GitHub's max)
	iat, ok := claims["iat"].(float64)
	assert.True(t, ok)
	exp, ok := claims["exp"].(float64)
	assert.True(t, ok)
	diff := exp - iat
	assert.True(t, diff >= 599 && diff <= 601)
	assert.True(t, time.Unix(int64(iat), 0).Before(time.Now().Add(time.Minute)))

	// GitHub JWTs must not include aud, scope, or sub
	_, hasAud := claims["aud"]
	assert.False(t, hasAud)
	_, hasScope := claims["scope"]
	assert.False(t, hasScope)
	_, hasSub := claims["sub"]
	assert.False(t, hasSub)
}

func TestGitHubAppProcessorConfig_Processor_CustomTokenURL(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		AppID:          "123456",
		InstallationID: "789012",
		TokenURL:       "https://github.enterprise.example/api/v3/app/installations/{installation_id}/access_tokens",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://github.enterprise.example/", nil)
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	assert.Equal(t, "/api/v3/app/installations/789012/access_tokens", req.URL.Path)
}

func TestGitHubAppProcessorConfig_Processor_MissingPrivateKey(t *testing.T) {
	cfg := &GitHubAppProcessorConfig{
		AppID:          "123456",
		InstallationID: "789012",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestGitHubAppProcessorConfig_Processor_InvalidPrivateKey(t *testing.T) {
	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     []byte("not-a-real-key"),
		AppID:          "123456",
		InstallationID: "789012",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestGitHubAppProcessorConfig_Processor_MissingAppID(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		InstallationID: "789012",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestGitHubAppProcessorConfig_Processor_MissingInstallationID(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey: pemBytes,
		AppID:      "123456",
	}

	_, err := cfg.Processor(nil, nil)
	assert.Error(t, err)
}

func TestGitHubAppProcessorConfig_Processor_RejectsNonRSAKey(t *testing.T) {
	// GitHub Apps require RSA keys (RS256). Reject ECDSA and Ed25519.
	_, ecPEM := generateTestECKey(t)
	cfgEC := &GitHubAppProcessorConfig{
		PrivateKey:     ecPEM,
		AppID:          "123456",
		InstallationID: "789012",
	}
	_, err := cfgEC.Processor(nil, nil)
	assert.Error(t, err)

	_, _, ed25519PEM := generateTestEd25519Key(t)
	cfgEd := &GitHubAppProcessorConfig{
		PrivateKey:     ed25519PEM,
		AppID:          "123456",
		InstallationID: "789012",
	}
	_, err = cfgEd.Processor(nil, nil)
	assert.Error(t, err)
}

func TestGitHubAppProcessorConfig_Processor_ClearsExistingBody(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		AppID:          "123456",
		InstallationID: "789012",
	}

	proc, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://api.github.com/", strings.NewReader("stale body"))
	assert.NoError(t, err)

	err = proc(req)
	assert.NoError(t, err)

	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(body))
	assert.Equal(t, int64(0), req.ContentLength)
}

func TestGitHubAppProcessorConfig_StripHazmat(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		AppID:          "123456",
		InstallationID: "789012",
		TokenURL:       "https://api.github.com/app/installations/{installation_id}/access_tokens",
	}

	stripped := cfg.StripHazmat().(*GitHubAppProcessorConfig)

	assert.NotEqual(t, pemBytes, stripped.PrivateKey)
	assert.Equal(t, redactedBase64, stripped.PrivateKey)

	assert.Equal(t, "123456", stripped.AppID)
	assert.Equal(t, "789012", stripped.InstallationID)
	assert.Equal(t, "https://api.github.com/app/installations/{installation_id}/access_tokens", stripped.TokenURL)
}

func TestGitHubAppProcessorConfig_ResponseProcessor_SealsInstallationToken(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)
	_, pub, priv := generateTestSealKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		AppID:          "123456",
		InstallationID: "789012",
	}

	// Outer secret is authenticated with bearer auth and pinned to api.github.com
	// for the exchange itself. The sealed installation token should also be
	// pinned to api.github.com regardless of what the outer secret allowed.
	ctx := &SealingContext{
		AuthConfig:        NewBearerAuthConfig("trustno1"),
		RequestValidators: []RequestValidator{AllowHosts("api.github.com")},
		SealKey:           pub,
	}

	respProc, err := cfg.ResponseProcessor(nil, ctx)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, respProc)

	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	githubResp := fmt.Sprintf(`{"token":"ghs_installationtokenXYZ","expires_at":%q,"permissions":{"contents":"read"}}`, expiresAt)
	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(githubResp)),
		Header:     make(http.Header),
	}

	err = respProc(resp)
	assert.NoError(t, err)

	respBody, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	var sealedResp SealedTokenResponse
	err = json.Unmarshal(respBody, &sealedResp)
	assert.NoError(t, err)

	assert.Equal(t, "sealed", sealedResp.TokenType)
	assert.True(t, sealedResp.ExpiresIn > 0 && sealedResp.ExpiresIn <= 3600)
	assert.NotEqual(t, "", sealedResp.SealedToken)

	secret, err := unsealSecret(sealedResp.SealedToken, pub, priv)
	assert.NoError(t, err)

	injector, ok := secret.ProcessorConfig.(*InjectProcessorConfig)
	assert.True(t, ok)
	assert.Equal(t, "ghs_installationtokenXYZ", injector.Token)
	// GitHub's legacy auth header uses `token <value>` (still accepted alongside Bearer).
	assert.Equal(t, "token %s", injector.FmtProcessor.Fmt)

	// Auth and host pinning forwarded into the sealed secret
	secretJSON, err := json.Marshal(secret)
	assert.NoError(t, err)
	assert.Contains(t, string(secretJSON), "bearer_auth")
	assert.Contains(t, string(secretJSON), "api.github.com")
}

func TestGitHubAppProcessorConfig_ResponseProcessor_PinsToAPIHostWithoutOuterValidator(t *testing.T) {
	// Even if the outer sealed secret has no host pin, the sealed installation
	// token must be pinned to api.github.com so it can't be replayed elsewhere.
	_, pemBytes := generateTestRSAKey(t)
	_, pub, priv := generateTestSealKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		AppID:          "123456",
		InstallationID: "789012",
	}

	ctx := &SealingContext{
		AuthConfig:        NewBearerAuthConfig("trustno1"),
		RequestValidators: nil,
		SealKey:           pub,
	}

	respProc, err := cfg.ResponseProcessor(nil, ctx)
	assert.NoError(t, err)

	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	githubResp := fmt.Sprintf(`{"token":"ghs_abc","expires_at":%q}`, expiresAt)
	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(githubResp)),
		Header:     make(http.Header),
	}

	err = respProc(resp)
	assert.NoError(t, err)

	var sealedResp SealedTokenResponse
	respBody, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	err = json.Unmarshal(respBody, &sealedResp)
	assert.NoError(t, err)

	secret, err := unsealSecret(sealedResp.SealedToken, pub, priv)
	assert.NoError(t, err)

	secretJSON, err := json.Marshal(secret)
	assert.NoError(t, err)
	assert.Contains(t, string(secretJSON), "api.github.com")
}

func TestGitHubAppProcessorConfig_ResponseProcessor_MissingToken(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)
	_, pub, _ := generateTestSealKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		AppID:          "123456",
		InstallationID: "789012",
	}

	ctx := &SealingContext{
		AuthConfig: NewBearerAuthConfig("trustno1"),
		SealKey:    pub,
	}

	respProc, err := cfg.ResponseProcessor(nil, ctx)
	assert.NoError(t, err)

	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{"not_token":"nope"}`)),
		Header:     make(http.Header),
	}

	err = respProc(resp)
	assert.Error(t, err)
}

func TestGitHubAppProcessorConfig_ResponseProcessor_NonOKStatus(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)
	_, pub, _ := generateTestSealKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		AppID:          "123456",
		InstallationID: "789012",
	}

	ctx := &SealingContext{
		AuthConfig: NewBearerAuthConfig("trustno1"),
		SealKey:    pub,
	}

	respProc, err := cfg.ResponseProcessor(nil, ctx)
	assert.NoError(t, err)

	resp := &http.Response{
		StatusCode: 401,
		Body:       io.NopCloser(strings.NewReader(`{"message":"Bad credentials"}`)),
		Header:     make(http.Header),
	}

	err = respProc(resp)
	assert.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "Bad credentials")
}

func TestGitHubAppProcessorConfig_ResponseProcessor_NilContext(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	cfg := &GitHubAppProcessorConfig{
		PrivateKey:     pemBytes,
		AppID:          "123456",
		InstallationID: "789012",
	}

	_, err := cfg.ResponseProcessor(nil, nil)
	assert.Error(t, err)
}

func TestGitHubAppProcessorConfig_JSONRoundTrip(t *testing.T) {
	_, pemBytes := generateTestRSAKey(t)

	original := &Secret{
		AuthConfig: NewBearerAuthConfig("trustno1"),
		ProcessorConfig: &GitHubAppProcessorConfig{
			PrivateKey:     pemBytes,
			AppID:          "123456",
			InstallationID: "789012",
			TokenURL:       "https://api.github.com/app/installations/{installation_id}/access_tokens",
		},
		RequestValidators: []RequestValidator{AllowHosts("api.github.com")},
	}

	data, err := json.Marshal(original)
	assert.NoError(t, err)

	assert.Contains(t, string(data), "github_app_processor")

	var restored Secret
	err = json.Unmarshal(data, &restored)
	assert.NoError(t, err)

	ghCfg, ok := restored.ProcessorConfig.(*GitHubAppProcessorConfig)
	assert.True(t, ok)
	assert.Equal(t, pemBytes, ghCfg.PrivateKey)
	assert.Equal(t, "123456", ghCfg.AppID)
	assert.Equal(t, "789012", ghCfg.InstallationID)
	assert.Equal(t, "https://api.github.com/app/installations/{installation_id}/access_tokens", ghCfg.TokenURL)
}

// unsealSecret is a test helper that decrypts a sealed secret.
func unsealSecret(sealed string, pub *[32]byte, priv *[32]byte) (*Secret, error) {
	ctSecret, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, err
	}

	jsonSecret, ok := box.OpenAnonymous(nil, ctSecret, pub, priv)
	if !ok {
		return nil, fmt.Errorf("failed to unseal")
	}

	secret := new(Secret)
	if err := json.Unmarshal(jsonSecret, secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func TestSigv4Processor(t *testing.T) {
	parseAuthHeader := func(s string) (string, string, string, string) {
		// AWS4-HMAC-SHA256 Credential=AccessKey/20260304/service/region/aws4_request, SignedHeaders=host;x-amz-date, Signature=674b77f7c09adf9becb2eb1c70183bb4e828330063b8b1577dfc64001074ea3d
		var accessKey, dateStr, region, service string
		words := strings.Split(strings.TrimPrefix(s, "AWS4-HMAC-SHA256 "), ", ")
		for _, word := range words {
			kv := strings.SplitN(word, "=", 2)
			if len(kv) == 2 {
				if kv[0] == "Credential" {
					parts := strings.Split(kv[1], "/")
					if len(parts) == 5 {
						accessKey = parts[0]
						dateStr = parts[1]
						region = parts[2]
						service = parts[3]
					}
				}
			}
		}
		return accessKey, dateStr, region, service
	}

	// Build our base request and Verify that we're parsing out the fields in the correct order...
	r, err := http.NewRequest(http.MethodGet, "https://www.test.com/path", http.NoBody)
	assert.NoError(t, err)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AccessKey/20260304/region/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=792ff6fc18a10db6bc1ae6a8f9ffb0caf1432da8d2008e33203a9a0434cd9127")
	akey, d, reg, svc := parseAuthHeader(r.Header.Get("Authorization"))
	assert.Equal(t, akey, "AccessKey")
	assert.Equal(t, d, "20260304")
	assert.Equal(t, reg, "region")
	assert.Equal(t, svc, "service")

	// The processor will swap region/service when NoSwap is false for bug compat.
	cfgSwap := &Sigv4ProcessorConfig{"AccessKey", "SecretKey", false}
	processSwap, err := cfgSwap.Processor(nil, nil)
	assert.NoError(t, err)

	req := r.Clone(context.Background())
	//fmt.Printf("Before: (swap) %v\n", req.Header.Get("Authorization"))
	err = processSwap(req)
	assert.NoError(t, err)
	//fmt.Printf("After: (swap)  %v\n", req.Header.Get("Authorization"))
	akey, d, reg, svc = parseAuthHeader(req.Header.Get("Authorization"))
	assert.Equal(t, akey, "AccessKey")
	assert.Equal(t, d, "20260304")
	assert.Equal(t, reg, "service") // swapped!
	assert.Equal(t, svc, "region")  // swapped!

	// The processor will not swap region/service when NoSwap is true.
	cfg := &Sigv4ProcessorConfig{"AccessKey", "SecretKey", true}
	process, err := cfg.Processor(nil, nil)
	assert.NoError(t, err)

	req = r.Clone(context.Background())
	//fmt.Printf("Before: (noswap) %v\n", req.Header.Get("Authorization"))
	err = process(req)
	assert.NoError(t, err)
	//fmt.Printf("After:  (noswap) %v\n", req.Header.Get("Authorization"))
	akey, d, reg, svc = parseAuthHeader(req.Header.Get("Authorization"))
	assert.Equal(t, akey, "AccessKey")
	assert.Equal(t, d, "20260304")
	assert.Equal(t, reg, "region")
	assert.Equal(t, svc, "service")
}
