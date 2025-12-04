package tokenizer

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
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
			proc, err := tt.config.Processor(tt.params)
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
			assert.Equal(t, int64(len(tt.expectedBody)), req.ContentLength)
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
			proc, err := tt.config.Processor(tt.params)
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
				assert.Equal(t, int64(len(tt.expectedBody)), req.ContentLength)
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
			proc, err := tt.config.Processor(tt.params)
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
			assert.Equal(t, int64(len(tt.expectedBody)), req.ContentLength)
		})
	}
}

// Helper function to convert string to io.ReadCloser
func stringToReadCloser(s string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(s))
}
