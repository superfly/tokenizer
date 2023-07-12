package tokenizer

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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
)

const (
	SubtokenAccess  = "access"
	SubtokenRefresh = "refresh"
)

type RequestProcessor func(r *http.Request) error

type ProcessorConfig interface {
	Processor(map[string]string) (RequestProcessor, error)
}

type InjectProcessorConfig struct {
	Token string `json:"token"`
}

var _ ProcessorConfig = new(InjectProcessorConfig)

func (c *InjectProcessorConfig) Processor(params map[string]string) (RequestProcessor, error) {
	if c.Token == "" {
		return nil, errors.New("missing token")
	}

	val, err := applyParamFmt(params[ParamFmt], false, c.Token)
	if err != nil {
		return nil, err
	}

	return func(r *http.Request) error {
		applyParamDst(r, params[ParamDst], val)
		return nil
	}, nil
}

func (c *InjectProcessorConfig) Updated() bool { return false }

type InjectHMACProcessorConfig struct {
	Key  []byte `json:"key"`
	Hash string `json:"hash"`
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

		val, err := applyParamFmt(params[ParamFmt], true, hm.Sum(nil))
		if err != nil {
			return err
		}

		applyParamDst(r, params[ParamDst], val)

		return nil
	}, nil
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

	val, err := applyParamFmt(params[ParamFmt], false, token)
	if err != nil {
		return nil, err
	}

	return func(r *http.Request) error {
		applyParamDst(r, params[ParamDst], val)
		return nil
	}, nil
}

func applyParamDst(r *http.Request, dst string, value string) {
	if dst == "" {
		dst = "Authorization"
	}
	r.Header.Set(dst, value)
}

func applyParamFmt(format string, isBinary bool, arg any) (string, error) {
	switch {
	case format != "":
	case isBinary:
		format = "Bearer %x"
	default:
		format = "Bearer %s"
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
	switch format[i+1] {
	case 'x', 'X', 's':
	default:
		return "", errors.New("bad fmt")
	}

	// only permit single format directive
	if strings.ContainsRune(format[i+2:], '%') {
		return "", errors.New("bad fmt")
	}

	return fmt.Sprintf(format, arg), nil
}
