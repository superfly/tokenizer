package flysrc

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestVerifyAndParseFlySrc(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	// good
	p := &Parsed{"foo", "bar", "baz", time.Now().Truncate(time.Second)}
	fs2, err := verifyAndParseFlySrc(p.String(), p.Sign(priv), pub)
	assert.NoError(t, err)
	assert.Equal(t, p, fs2)

	// expired
	p = &Parsed{"foo", "bar", "baz", time.Now().Add(-time.Hour).Truncate(time.Second)}
	_, err = verifyAndParseFlySrc(p.String(), p.Sign(priv), pub)
	assert.Error(t, err)

	// bad signature
	p = &Parsed{"foo", "bar", "baz", time.Now().Truncate(time.Second)}
	sig := (&Parsed{"other", "bar", "baz", time.Now().Truncate(time.Second)}).Sign(priv)
	_, err = verifyAndParseFlySrc(p.String(), sig, pub)
	assert.Error(t, err)

	// missing fields
	p = &Parsed{"", "bar", "baz", time.Now().Truncate(time.Second)}
	_, err = verifyAndParseFlySrc(p.String(), p.Sign(priv), pub)
	assert.Error(t, err)

	p = &Parsed{"foo", "", "baz", time.Now().Truncate(time.Second)}
	_, err = verifyAndParseFlySrc(p.String(), p.Sign(priv), pub)
	assert.Error(t, err)

	p = &Parsed{"foo", "bar", "", time.Now().Truncate(time.Second)}
	_, err = verifyAndParseFlySrc(p.String(), p.Sign(priv), pub)
	assert.Error(t, err)

	p = &Parsed{"foo", "bar", "baz", time.Time{}}
	_, err = verifyAndParseFlySrc(p.String(), p.Sign(priv), pub)
	assert.Error(t, err)

	// totally bogus
	_, err = verifyAndParseFlySrc("hello world!", sig, pub)
	assert.Error(t, err)
}

func TestReadFlySrcKey(t *testing.T) {
	var (
		path   = filepath.Join(t.TempDir(), "k.pub")
		keyHex = "93e9adb1615a6ce6238a13c264e7c8ba8f8b7a53717e86bb34fce3b80d45f1e5"
		key    = []byte{147, 233, 173, 177, 97, 90, 108, 230, 35, 138, 19, 194, 100, 231, 200, 186, 143, 139, 122, 83, 113, 126, 134, 187, 52, 252, 227, 184, 13, 69, 241, 229}
	)

	assert.NoError(t, os.WriteFile(path, []byte(keyHex), 0644))
	assert.Equal(t, key, readFlySrcKey(path))
}
