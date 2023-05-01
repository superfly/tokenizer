package tokenizer

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

var (
	ErrNotAuthorized = errors.New("not authorized")
	ErrBadRequest    = errors.New("bad request")
)

type Secret struct {
	AuthConfig
	ProcessorConfig
}

func (s *Secret) Seal(sealKey string) (string, error) {
	pubBytes, err := hex.DecodeString(sealKey)
	if err != nil {
		return "", err
	}
	if len(pubBytes) != 32 {
		return "", fmt.Errorf("bad public key size: %d", len(pubBytes))
	}

	sj, err := json.Marshal(s)
	if err != nil {
		return "", nil
	}

	sct, err := box.SealAnonymous(nil, sj, (*[32]byte)(pubBytes), nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sct), nil
}

type wireSecret struct {
	*InjectProcessorConfig     `json:"inject_processor,omitempty"`
	*InjectHMACProcessorConfig `json:"inject_hmac_processor,omitempty"`
	*BearerAuthConfig          `json:"bearer_auth,omitempty"`
}

func (s *Secret) MarshalJSON() ([]byte, error) {
	ws := wireSecret{}

	switch a := s.AuthConfig.(type) {
	case *BearerAuthConfig:
		ws.BearerAuthConfig = a
	default:
		return nil, errors.New("bad auth config")
	}

	switch p := s.ProcessorConfig.(type) {
	case *InjectProcessorConfig:
		ws.InjectProcessorConfig = p
	case *InjectHMACProcessorConfig:
		ws.InjectHMACProcessorConfig = p
	default:
		return nil, errors.New("bad processor config")
	}

	return json.Marshal(ws)
}

func (s *Secret) UnmarshalJSON(b []byte) error {
	ws := wireSecret{}
	if err := json.Unmarshal(b, &ws); err != nil {
		return err
	}

	var np int
	if ws.InjectProcessorConfig != nil {
		np += 1
		s.ProcessorConfig = ws.InjectProcessorConfig
	}
	if ws.InjectHMACProcessorConfig != nil {
		np += 1
		s.ProcessorConfig = ws.InjectHMACProcessorConfig
	}
	if np != 1 {
		return errors.New("bad processor config")
	}

	var na int
	if ws.BearerAuthConfig != nil {
		na += 1
		s.AuthConfig = ws.BearerAuthConfig
	}
	if na != 1 {
		return errors.New("bad auth config")
	}

	return nil
}
