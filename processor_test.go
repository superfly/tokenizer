package tokenizer

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestFmtProcessor(t *testing.T) {
	p := FmtProcessor{}

	val, err := p.ApplyFmt(map[string]string{}, true, []byte{1, 2, 3})
	assert.NoError(t, err)
	assert.Equal(t, "Bearer 010203", val)

	val, err = p.ApplyFmt(map[string]string{}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "Bearer 123", val)

	val, err = p.ApplyFmt(map[string]string{ParamFmt: "%x"}, true, []byte{1, 2, 3})
	assert.NoError(t, err)
	assert.Equal(t, "010203", val)

	val, err = p.ApplyFmt(map[string]string{ParamFmt: "%X"}, true, []byte{1, 2, 3})
	assert.NoError(t, err)
	assert.Equal(t, "010203", val)

	val, err = p.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "%d"}, false, "123")
	assert.Error(t, err)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "%.3s"}, false, "123")
	assert.Error(t, err)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "%s%s"}, false, "123")
	assert.Error(t, err)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "asdf%"}, false, "123")
	assert.Error(t, err)

	_, err = p.ApplyFmt(map[string]string{ParamFmt: "asdf"}, false, "123")
	assert.Error(t, err)

	val, err = FmtProcessor{AllowedFmt: []string{"%s"}}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	_, err = FmtProcessor{AllowedFmt: []string{"x %s"}}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.Error(t, err)

	val, err = FmtProcessor{Fmt: "%s"}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	_, err = FmtProcessor{Fmt: "x %s"}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.Error(t, err)

	val, err = FmtProcessor{Fmt: "%s", AllowedFmt: []string{"%s"}}.ApplyFmt(map[string]string{ParamFmt: "%s"}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	val, err = FmtProcessor{Fmt: "%s", AllowedFmt: []string{"%s"}}.ApplyFmt(map[string]string{}, false, "123")
	assert.NoError(t, err)
	assert.Equal(t, "123", val)

	_, err = FmtProcessor{Fmt: "%s", AllowedFmt: []string{"x %s"}}.ApplyFmt(map[string]string{}, false, "123")
	assert.Error(t, err)
}

func TestDstProcessor(t *testing.T) {
	assertResult := func(expected string, dp DstProcessor, params map[string]string) {
		t.Helper()

		r := http.Request{Header: make(http.Header)}
		err := dp.ApplyDst(params, &r, "123")
		if expected == "error" {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			buf := new(bytes.Buffer)
			assert.NoError(t, r.Header.Write(buf))
			assert.Equal(t, expected, strings.TrimSpace(buf.String()))
		}
	}

	assertResult("Authorization: 123", DstProcessor{}, map[string]string{})
	assertResult("Authorization: 123", DstProcessor{}, map[string]string{ParamDst: "Authorization"})
	assertResult("Authorization: 123", DstProcessor{}, map[string]string{ParamDst: "AuThOriZaTiOn"})
	assertResult("Foo: 123", DstProcessor{}, map[string]string{ParamDst: "Foo"})
	assertResult("Foo: 123", DstProcessor{Dst: "Foo", AllowedDst: []string{"Foo"}}, map[string]string{ParamDst: "Foo"})
	assertResult("Foo: 123", DstProcessor{Dst: "Foo", AllowedDst: []string{"fOo"}}, map[string]string{ParamDst: "foO"})
	assertResult("Foo: 123", DstProcessor{AllowedDst: []string{"fOo"}}, map[string]string{ParamDst: "foO"})
	assertResult("Foo: 123", DstProcessor{Dst: "Foo"}, map[string]string{ParamDst: "foO"})
	assertResult("Foo: 123", DstProcessor{Dst: "Foo", AllowedDst: []string{"fOo"}}, map[string]string{})
	assertResult("error", DstProcessor{Dst: "Foo", AllowedDst: []string{"Bar"}}, map[string]string{ParamDst: "Foo"})
	assertResult("error", DstProcessor{Dst: "Foo", AllowedDst: []string{"Bar"}}, map[string]string{})
	assertResult("error", DstProcessor{AllowedDst: []string{"Bar"}}, map[string]string{ParamDst: "Foo"})
	assertResult("error", DstProcessor{Dst: "Bar"}, map[string]string{ParamDst: "Foo"})
}
