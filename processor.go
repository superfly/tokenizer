package tokenizer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	"github.com/superfly/httpsig"
)

const (
	// ParamDst optionally specifies the header that Inject processors should
	// set. Default is Authorization.
	ParamDst = "dst"

	// ParamFmt optionally specifies a format string that Inject processors
	// should use when setting headers. Default is "%s" for Inject and "%x" for
	// InjectHMAC.
	ParamFmt = "fmt"

	// ParamPayload specifies the string that should be signed by InjectHMAC.
	// Defaults to verbatim request body with leading/trailing whitespace
	// removed.
	ParamPayload = "msg"
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
	f := "Bearer %s"
	if p, ok := params[ParamFmt]; ok {
		f = p
	}
	if !strings.Contains(f, "%s") || strings.Count(f, "%") != 1 {
		return nil, errors.New("bad fmt")
	}

	dst := "Authorization"
	if p, ok := params[ParamDst]; ok {
		dst = p
	}

	token := c.Token
	if token == "" {
		return nil, errors.New("missing token")
	}

	return func(r *http.Request) error {
		r.Header.Set(dst, fmt.Sprintf(f, token))
		return nil
	}, nil
}

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

	f := "Bearer %x"
	if p, ok := params[ParamFmt]; ok {
		f = p
	}
	if strings.Count(f, "%") != 1 {
		return nil, errors.New("bad fmt")
	}

	dst := "Authorization"
	if p, ok := params[ParamDst]; ok {
		dst = p
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

		r.Header.Set(dst, fmt.Sprintf(f, hm.Sum(nil)))

		return nil
	}, nil
}

type InjectHttpsigProcessorConfig struct {
	Key []byte `json:"key"`
}

var _ ProcessorConfig = new(InjectHMACProcessorConfig)

func (c *InjectHttpsigProcessorConfig) Processor(params map[string]string) (RequestProcessor, error) {

	if len(c.Key) == 0 {
		return nil, errors.New("missing signing key")
	}

	// Prepare a signature-input
	si := &httpsig.SignatureInput{
		ID:      "signature",
		KeyID:   string(c.Key),
		Headers: []string{"@created", "@request-target", "content-length"},
		Created: uint64(time.Now().Unix()),
		Nonce:   uniuri.NewLen(32),
	}

	return func(r *http.Request) error {
		signer := httpsig.NewSigner(httpsig.AlgorithmHMACSHA256, func(ctx context.Context, kid string) (interface{}, error) {
			return kid, nil
		})

		sig, err := signer.Sign(context.Background(), si, r)
		if err != nil {
			return err
		}
		signSet := &httpsig.SignatureSet{}
		signSet.Add(si.ID, sig)

		// Assign to request headers.
		r.Header.Set("Signature-Input", si.String())
		r.Header.Set("Signature", signSet.String())

		return nil
	}, nil
}
