package tokenizer

import (
	"errors"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestSplitDialFunc(t *testing.T) {
	for _, tc := range []struct{ name, addr, err string }{
		{"https port", "example.com:443", "proxied request must be HTTP"},
		{"ipv6 literal https port", "[::1]:443", "proxied request must be HTTP"},
		{"empty host", ":80", "without host"},
		{"empty ipv6 host", "[]:80", "without host"},
		{"empty address", "", "without host"},
	} {
		_, err := dialFunc(nil, true)("tcp", tc.addr)
		assert.True(t, errors.Is(err, ErrBadRequest), "got %v", err)
		assert.Contains(t, err.Error(), tc.err)
	}
}

func TestSplitHostOptionalPort(t *testing.T) {
	for _, tc := range []struct{ hostport, host, port, err string }{
		{"host:443", "host", "443", ""},
		{"host:80", "host", "80", ""},
		{"host:", "host", "80", ""},
		{"host", "host", "80", ""},
		{"127.0.0.1:443", "127.0.0.1", "443", ""},
		{"127.0.0.1:80", "127.0.0.1", "80", ""},
		{"127.0.0.1:", "127.0.0.1", "80", ""},
		{"127.0.0.1", "127.0.0.1", "80", ""},
		{"[::1]:443", "::1", "443", ""},
		{"[::1]:80", "::1", "80", ""},
		{"[::1]:", "::1", "80", ""},
		{"[::1]", "::1", "80", ""},

		{"127.0.0.1::443", "", "", "too many colons in address"},
		{"[::1]::443", "", "", "too many colons in address"},

		{"[::1", "", "", "missing ']'"},
		{"[::1] :443", "", "", "extra data"},
		{"[::1]443", "", "", "extra data"},
	} {
		host, port, err := SplitHostOptionalPort(tc.hostport, "80")
		t.Logf("testing %v got %v,%v,%v\n", tc, host, port, err)
		if tc.err == "" {
			assert.NoError(t, err)
			assert.Equal(t, host, tc.host)
			assert.Equal(t, port, tc.port)
		} else {
			assert.Error(t, err)
			assert.Zero(t, host)
			assert.Zero(t, port)
			assert.Contains(t, err.Error(), tc.err)
		}
	}
}
