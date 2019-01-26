package digest

import (
	"testing"

	"github.com/gregoryv/asserter"
)

func Test_parsing_wwwAuth(t *testing.T) {
	assert := asserter.New(t)
	for _, txt := range []string{
		`Digest realm="x", nonce="y", algorithm=SHA3_384, qop="auth"`,
		`Basic realm="x", nonce="y", algorithm=SHA256, qop="auth"`,
		``,
	} {
		err := NewAuth("", "").Parse(txt)
		t.Log(err)
		assert(err != nil).Errorf("%s should fail", txt)
	}
}

func TestFindVal(t *testing.T) {
	cases := []struct {
		wwwAuth, name, exp string
	}{
		{`Digest realm="val"`, "realm", "val"},
		{`realm=val`, "realm", "val"},
		{`nonce=the-nonce, realm=val`, "realm", "val"},
		{`nonce=the-nonce, realm=val, more="here"`, "realm", "val"},
		{`blah`, "realm", ""},
	}

	for _, c := range cases {
		val := findVal(c.wwwAuth, c.name)
		if c.exp != val {
			t.Errorf("Expected %q got %q", c.exp, val)
		}
	}
}

func TestParseValues(t *testing.T) {
	exp := make(map[string]string)
	exp["realm"] = "val"
	exp["nonce"] = "the-nonce"

	res := parseValues(`nonce="the-nonce", realm=val, blah`)
	for k, v := range exp {
		if res[k] != v {
			t.Errorf("Expect %s=%s, got %s", k, v, res[k])
		}
	}
}
