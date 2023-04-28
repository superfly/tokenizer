package tokenizer

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestSecretJSON(t *testing.T) {
	s := &Secret{
		ProcessorConfig: &InjectProcessorConfig{
			Token: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		},
		AuthConfig: &BearerAuthConfig{
			Digest: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		},
	}
	sj, err := json.Marshal(s)
	assert.NoError(t, err)

	t.Log(string(sj))

	s2 := new(Secret)
	assert.NoError(t, json.Unmarshal(sj, s2))
	assert.Equal(t, s, s2)
}
