package tokenizer

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/nacl/box"
)

var (
	ErrNotAuthorized = errors.New("not authorized")
	ErrBadRequest    = errors.New("bad request")
	ErrInternal      = errors.New("internal proxy error")
)

type Secret struct {
	AuthConfig
	ProcessorConfig
	RequestValidators []RequestValidator
}

func (s *Secret) Seal(sealKey string) (string, error) {
	pubBytes, err := hex.DecodeString(sealKey)
	if err != nil {
		return "", err
	}
	if len(pubBytes) != 32 {
		return "", fmt.Errorf("bad public key size: %d", len(pubBytes))
	}

	return s.sealRaw((*[32]byte)(pubBytes))
}

func (s *Secret) sealRaw(key *[32]byte) (string, error) {
	sj, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	sct, err := box.SealAnonymous(nil, sj, key, nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sct), nil
}

func (s *Secret) StripHazmat() *Secret {
	return &Secret{
		AuthConfig:        s.AuthConfig.StripHazmat(),
		ProcessorConfig:   s.ProcessorConfig,
		RequestValidators: s.RequestValidators,
	}
}

func (s *Secret) StripHazmatString() string {
	bs, _ := json.Marshal(s.StripHazmat())
	return string(bs)
}

type wireSecret struct {
	wireProcessor
	wireAuth
	AllowHosts       []string `json:"allowed_hosts,omitempty"`
	AllowHostPattern string   `json:"allowed_host_pattern,omitempty"`
}

func (s *Secret) MarshalJSON() ([]byte, error) {
	var (
		ws  wireSecret
		err error
	)

	if ws.wireAuth, err = newWireAuth(s.AuthConfig); err != nil {
		return nil, err
	}

	if ws.wireProcessor, err = newWireProcessor(s.ProcessorConfig); err != nil {
		return nil, err
	}

	for _, v := range s.RequestValidators {
		switch tv := v.(type) {
		case allowedHosts:
			if ws.AllowHosts != nil {
				return nil, errors.New("cannot have multiple AllowedHosts validators")
			}
			ws.AllowHosts = tv.slice()
		case *allowedHostPattern:
			ws.AllowHostPattern = (*regexp.Regexp)(tv).String()
		default:
			return nil, errors.New("unknown request validator type")
		}
	}

	return json.Marshal(ws)
}

func (s *Secret) UnmarshalJSON(b []byte) error {
	var (
		ws  wireSecret
		err error
	)

	if err := json.Unmarshal(b, &ws); err != nil {
		return err
	}

	if s.ProcessorConfig, err = ws.wireProcessor.getProcessorConfig(); err != nil {
		return err
	}

	if s.AuthConfig, err = ws.wireAuth.getAuthConfig(); err != nil {
		return err
	}

	if ws.AllowHosts != nil {
		s.RequestValidators = append(s.RequestValidators, AllowHosts(ws.AllowHosts...))
	}

	if ws.AllowHostPattern != "" {
		re, err := regexp.Compile(ws.AllowHostPattern)
		if err != nil {
			return err
		}
		s.RequestValidators = append(s.RequestValidators, AllowHostPattern(re))
	}

	return nil
}
