package tokenizer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/sirupsen/logrus"
)

func parseHeaderReplace(hdr string) (string, map[string]string, error) {
	secretKey, paramJSON, _ := strings.Cut(hdr, ";")

	secretKey = strings.TrimFunc(secretKey, unicode.IsSpace)
	paramJSON = strings.TrimFunc(paramJSON, unicode.IsSpace)

	if secretKey == "" {
		return "", nil, errors.New("bad replace header")
	}

	processorParams := make(map[string]string)
	if paramJSON != "" {
		if err := json.Unmarshal([]byte(paramJSON), &processorParams); err != nil {
			return "", nil, err
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

// InjectBearer injects the secret into the Authorization header with the Bearer scheme.
// To make this processor available under the "inject-bearer" name, import the
// github.com/superfly/processors/inject-bearer package.
func InjectBearer(s Secret, params map[string]string) (RequestProcessor, error) {
	var (
		token = s.Secret()
		hdr   = fmt.Sprintf("Bearer %s", token)
	)
	if token == "" {
		return nil, errors.New("missing secret")
	}

	return func(r *http.Request) error {
		r.Header.Set("Authorization", hdr)
		return nil
	}, nil
}
