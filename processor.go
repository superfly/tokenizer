package tokenizer

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/sirupsen/logrus"
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

func parseHeaderReplace(hdr string) (string, map[string]string, error) {
	secretKey, paramJSON, _ := strings.Cut(hdr, ";")

	secretKey = strings.TrimFunc(secretKey, unicode.IsSpace)
	paramJSON = strings.TrimFunc(paramJSON, unicode.IsSpace)

	if secretKey == "" {
		return "", nil, fmt.Errorf("%w: bad replace header", ErrBadRequest)
	}

	processorParams := make(map[string]string)
	if paramJSON != "" {
		if err := json.Unmarshal([]byte(paramJSON), &processorParams); err != nil {
			return "", nil, fmt.Errorf("%w: %w", ErrBadRequest, err)
		}
	}

	return secretKey, processorParams, nil
}

func formatHeaderReplace(secretKey string, processorParams map[string]string) string {
	hdr := secretKey

	if len(processorParams) > 0 {
		paramJSON, _ := json.Marshal(processorParams)
		hdr = fmt.Sprintf("%s; %s", hdr, paramJSON)
	}

	return hdr
}

type RequestProcessorFactory func(Secret, map[string]string) (RequestProcessor, error)

type RequestProcessor func(r *http.Request) error

var processorFactoryRegistry = map[string]RequestProcessorFactory{}

func RegisterProcessor(name string, factory RequestProcessorFactory) {
	if _, dup := processorFactoryRegistry[name]; dup {
		logrus.Panicf("duplicate processor: %s", name)
	}
	processorFactoryRegistry[name] = factory
}

// Inject injects the secret into the specified header. To make this processor
// available under the "inject" name, import the
// github.com/superfly/processors/inject package.
var Inject RequestProcessorFactory = func(s Secret, params map[string]string) (RequestProcessor, error) {
	f := "%s"
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

	secret := s[SecretKeySecret]
	if secret == "" {
		return nil, errors.New("missing secret")
	}

	return func(r *http.Request) error {
		r.Header.Set(dst, fmt.Sprintf(f, secret))
		return nil
	}, nil
}

// InjectHMAC injects the secret into the specified header. To make this processor
// available under the "inject-hmac" name, import the
// github.com/superfly/processors/inject-hmac package.
var InjectHMAC RequestProcessorFactory = func(s Secret, params map[string]string) (RequestProcessor, error) {
	hi, err := strconv.ParseInt(s[SecretKeyHash], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad hash id: %w", err)
	}
	h := crypto.Hash(hi)
	if !h.Available() {
		return nil, fmt.Errorf("hash %s not imported", h)
	}

	f := "%x"
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

	signKey := s[SecretKeySecret]
	if signKey == "" {
		return nil, errors.New("missing secret")
	}

	return func(r *http.Request) error {
		hm := hmac.New(h.New, []byte(signKey))

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
