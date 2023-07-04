package tokenizer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const (
	// how close to expiry before we refresh a token
	oauth2RefreshThreshold = 10 * time.Second
)

type OAuth2ProcessorConfig struct {
	RefreshURL string        `json:"refresh_url"`
	Token      *oauth2.Token `json:"token"`
	updated    bool
}

var _ ProcessorConfig = (*OAuth2ProcessorConfig)(nil)

func (c *OAuth2ProcessorConfig) RequestProcessor(params map[string]string) (RequestProcessor, error) {
	return func(r *http.Request) error {
		if time.Until(c.Token.Expiry) < oauth2RefreshThreshold {
			j, err := json.Marshal(c.Token)
			if err != nil {
				return fmt.Errorf("oauth2: encode token: %w", err)
			}

			resp, err := http.Post(c.RefreshURL, "application/json", bytes.NewReader(j))
			if err != nil {
				return fmt.Errorf("oauth2: refresh request: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("oauth2: bad refresh response: %d", resp.StatusCode)
			}

			newTok := new(oauth2.Token)
			if err := json.NewDecoder(resp.Body).Decode(newTok); err != nil {
				return fmt.Errorf("oauth2: decode refresh: %w", err)
			}

			c.Token = newTok
			c.updated = true
		}

		c.Token.SetAuthHeader(r)

		return nil
	}, nil
}

func (c *OAuth2ProcessorConfig) Updated() bool {
	return c.updated
}
