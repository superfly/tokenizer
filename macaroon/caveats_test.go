package macaroon

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
)

func TestCaveatSerialization(t *testing.T) {
	cs := macaroon.NewCaveatSet(
		ConstrainRequestHost("a"),
		ConstrainRequestMethod("b"),
		ConstrainRequestPath("c"),
	)

	b, err := json.Marshal(cs)
	assert.NoError(t, err)

	cs2 := macaroon.NewCaveatSet()
	err = json.Unmarshal(b, cs2)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)

	b, err = cs.MarshalMsgpack()
	assert.NoError(t, err)
	cs2, err = macaroon.DecodeCaveats(b)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)
}
