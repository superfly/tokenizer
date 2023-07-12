package tokenizer

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestApplyFmt(t *testing.T) {
	val, err := applyParamFmt("", true, []byte{1, 2, 3})
	assert.NoError(t, err)
	assert.Equal(t, "Bearer 010203", val)

	val, err = applyParamFmt("", false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "Bearer 123", val)

	val, err = applyParamFmt("%x", true, []byte{1, 2, 3})
	assert.NoError(t, err)
	assert.Equal(t, "010203", val)

	val, err = applyParamFmt("%X", true, []byte{1, 2, 3})
	assert.NoError(t, err)
	assert.Equal(t, "010203", val)

	val, err = applyParamFmt("%s", false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	_, err = applyParamFmt("%d", false, "123")
	assert.Error(t, err)

	_, err = applyParamFmt("%.3s", false, "123")
	assert.Error(t, err)

	_, err = applyParamFmt("%s%s", false, "123")
	assert.Error(t, err)

	_, err = applyParamFmt("asdf%", false, "123")
	assert.Error(t, err)

	_, err = applyParamFmt("asdf", false, "123")
	assert.Error(t, err)
}
