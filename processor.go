package tokenizer

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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

	// ParamDelimiter specifies the delimiter to replace in the request body
	// with the token value. Used by InjectBodyProcessor.
	ParamDelimiter = "delimiter"
)

const (
	SubtokenAccess  = "access"
	SubtokenRefresh = "refresh"
)

type RequestProcessor func(r *http.Request) error

type ProcessorConfig interface {
	Processor(map[string]string) (RequestProcessor, error)
	StripHazmat() ProcessorConfig
}

type wireProcessor struct {
	InjectProcessorConfig     *InjectProcessorConfig     `json:"inject_processor,omitempty"`
	InjectHMACProcessorConfig *InjectHMACProcessorConfig `json:"inject_hmac_processor,omitempty"`
	InjectBodyProcessorConfig *InjectBodyProcessorConfig `json:"inject_body_processor,omitempty"`
	OAuthProcessorConfig      *OAuthProcessorConfig      `json:"oauth2_processor,omitempty"`
	OAuthBodyProcessorConfig  *OAuthBodyProcessorConfig  `json:"oauth2_body_processor,omitempty"`
	Sigv4ProcessorConfig      *Sigv4ProcessorConfig      `json:"sigv4_processor,omitempty"`
	MultiProcessorConfig      *MultiProcessorConfig      `json:"multi_processor,omitempty"`
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

func (c *InjectProcessorConfig) Processor(params map[string]string) (RequestProcessor, error) {
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

func (c *InjectHMACProcessorConfig) Processor(params map[string]string) (RequestProcessor, error) {
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
	Token     string `json:"token"`
	Delimiter string `json:"delimiter,omitempty"`
}

var _ ProcessorConfig = new(InjectBodyProcessorConfig)

func (c *InjectBodyProcessorConfig) Processor(params map[string]string) (RequestProcessor, error) {
	if c.Token == "" {
		return nil, errors.New("missing token")
	}

	// Get delimiter from params or use config default or fallback
	delimiter := c.Delimiter
	if paramDelim, ok := params[ParamDelimiter]; ok {
		delimiter = paramDelim
	}
	if delimiter == "" {
		delimiter = "{{ACCESS_TOKEN}}"
	}

	return func(r *http.Request) error {
		// Read the entire request body
		if r.Body == nil {
			return nil
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		r.Body.Close()

		// Replace delimiter with token
		bodyStr := string(bodyBytes)
		newBody := strings.ReplaceAll(bodyStr, delimiter, c.Token)

		// Set the new body
		r.Body = io.NopCloser(strings.NewReader(newBody))
		r.ContentLength = int64(len(newBody))

		return nil
	}, nil
}

func (c *InjectBodyProcessorConfig) StripHazmat() ProcessorConfig {
	return &InjectBodyProcessorConfig{
		Token:     redactedStr,
		Delimiter: c.Delimiter,
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

func (c *OAuthProcessorConfig) Processor(params map[string]string) (RequestProcessor, error) {
	token := c.Token.AccessToken
	if params[ParamSubtoken] == SubtokenRefresh {
		token = c.Token.RefreshToken
	}

	if token == "" {
		return nil, errors.New("missing token")
	}

	// Check if delimiter parameter is present for body injection
	if delimiter, ok := params[ParamDelimiter]; ok && delimiter != "" {
		// Inject token into request body by replacing delimiter
		return func(r *http.Request) error {
			if r.Body == nil {
				return nil
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				return fmt.Errorf("failed to read request body: %w", err)
			}
			r.Body.Close()

			// Replace delimiter with token
			bodyStr := string(bodyBytes)
			newBody := strings.ReplaceAll(bodyStr, delimiter, token)

			// Set the new body
			r.Body = io.NopCloser(strings.NewReader(newBody))
			r.ContentLength = int64(len(newBody))

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
	Token     *OAuthToken `json:"token"`
	Delimiter string      `json:"delimiter,omitempty"`
}

var _ ProcessorConfig = (*OAuthBodyProcessorConfig)(nil)

func (c *OAuthBodyProcessorConfig) Processor(params map[string]string) (RequestProcessor, error) {
	token := c.Token.AccessToken
	if params[ParamSubtoken] == SubtokenRefresh {
		token = c.Token.RefreshToken
	}

	if token == "" {
		return nil, errors.New("missing token")
	}

	// Get delimiter from params or use config default or fallback
	delimiter := c.Delimiter
	if paramDelim, ok := params[ParamDelimiter]; ok {
		delimiter = paramDelim
	}
	if delimiter == "" {
		delimiter = "{{ACCESS_TOKEN}}"
	}

	return func(r *http.Request) error {
		// Read the entire request body
		if r.Body == nil {
			return nil
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		r.Body.Close()

		// Replace delimiter with token
		bodyStr := string(bodyBytes)
		newBody := strings.ReplaceAll(bodyStr, delimiter, token)

		// Set the new body
		r.Body = io.NopCloser(strings.NewReader(newBody))
		r.ContentLength = int64(len(newBody))

		return nil
	}, nil
}

func (c *OAuthBodyProcessorConfig) StripHazmat() ProcessorConfig {
	return &OAuthBodyProcessorConfig{
		Token: &OAuthToken{
			AccessToken:  redactedStr,
			RefreshToken: redactedStr,
		},
		Delimiter: c.Delimiter,
	}
}

type Sigv4ProcessorConfig struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

var _ ProcessorConfig = (*Sigv4ProcessorConfig)(nil)

func (c *Sigv4ProcessorConfig) Processor(params map[string]string) (RequestProcessor, error) {

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

				service = credParts[2]
				region = credParts[3]
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

		signer := v4.NewSigner()
		err = signer.SignHTTP(r.Context(), credentials, r, r.Header.Get("X-Amz-Content-Sha256"), service, region, date)

		return err
	}, nil
}

func (c *Sigv4ProcessorConfig) StripHazmat() ProcessorConfig {
	return &Sigv4ProcessorConfig{
		AccessKey: redactedStr,
		SecretKey: redactedStr,
	}
}

type MultiProcessorConfig []ProcessorConfig

var _ ProcessorConfig = new(MultiProcessorConfig)

func (c MultiProcessorConfig) Processor(params map[string]string) (RequestProcessor, error) {
	var processors []RequestProcessor
	for _, cfg := range c {
		proc, err := cfg.Processor(params)
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
