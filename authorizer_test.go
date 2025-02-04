package tokenizer

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestVerifyAndParseFlySrc(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	// good
	fs := &flySrc{"foo", "bar", "baz", time.Now().Truncate(time.Second)}
	fs2, err := verifyAndParseFlySrc(fs.String(), fs.sign(priv), pub)
	assert.NoError(t, err)
	assert.Equal(t, fs, fs2)

	// expired
	fs = &flySrc{"foo", "bar", "baz", time.Now().Add(-time.Hour).Truncate(time.Second)}
	_, err = verifyAndParseFlySrc(fs.String(), fs.sign(priv), pub)
	assert.Error(t, err)

	// bad signature
	fs = &flySrc{"foo", "bar", "baz", time.Now().Truncate(time.Second)}
	sig := (&flySrc{"other", "bar", "baz", time.Now().Truncate(time.Second)}).sign(priv)
	_, err = verifyAndParseFlySrc(fs.String(), sig, pub)
	assert.Error(t, err)

	// missing fields
	fs = &flySrc{"", "bar", "baz", time.Now().Truncate(time.Second)}
	_, err = verifyAndParseFlySrc(fs.String(), fs.sign(priv), pub)
	assert.Error(t, err)

	fs = &flySrc{"foo", "", "baz", time.Now().Truncate(time.Second)}
	_, err = verifyAndParseFlySrc(fs.String(), fs.sign(priv), pub)
	assert.Error(t, err)

	fs = &flySrc{"foo", "bar", "", time.Now().Truncate(time.Second)}
	_, err = verifyAndParseFlySrc(fs.String(), fs.sign(priv), pub)
	assert.Error(t, err)

	fs = &flySrc{"foo", "bar", "baz", time.Time{}}
	_, err = verifyAndParseFlySrc(fs.String(), fs.sign(priv), pub)
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

func (fs *flySrc) String() string {
	return fmt.Sprintf("instance=%s;app=%s;org=%s;ts=%d", fs.Instance, fs.App, fs.Org, fs.Timestamp.Unix())
}

func (fs *flySrc) sign(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(fs.String())))
}

var (
	_setupTestFlySrcKeyOnce    sync.Once
	_flySrcSignaturePrivateKey ed25519.PrivateKey
)

func flySrcSignaturePrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	var err error

	_setupTestFlySrcKeyOnce.Do(func() {
		flySrcSignatureKey, _flySrcSignaturePrivateKey, err = ed25519.GenerateKey(nil)
	})

	assert.NoError(t, err)
	assert.NotZero(t, _flySrcSignaturePrivateKey)
	return _flySrcSignaturePrivateKey
}
