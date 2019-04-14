package digest

import (
	"fmt"
	"strings"
	"testing"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
	_ "golang.org/x/crypto/md4"
	_ "golang.org/x/crypto/ripemd160"
	_ "golang.org/x/crypto/sha3"

	"github.com/gregoryv/asserter"
)

func Test_parsing_wwwAuth(t *testing.T) {
	assert := asserter.New(t)
	unsupported := []string{
		`Basic realm="x", nonce="y", algorithm=SHA256, qop="auth"`,
		`Digest realm="x", nonce="y", algorithm=FUNKYSTUFF, qop="auth"`,
		``,
	}
	for _, txt := range unsupported {
		err := NewAuth("", "").Parse(txt)
		assert(err != nil).Errorf("%s should fail", txt)
	}

	supportedAlgorithms := []string{"MD4",
		"MD5",
		"SHA1",
		"SHA224",
		"SHA256",
		"SHA384",
		"SHA512",
		"RIPEMD160",
		"SHA3_224",
		"SHA3_256",
		"SHA3_384",
		"SHA3_512",
		"SHA512_224",
		"SHA512_256",
	}
	format := `Digest realm="x", nonce="y", algorithm=%s, qop="auth"`
	for _, alg := range supportedAlgorithms {
		txt := fmt.Sprintf(format, alg)
		err := NewAuth("", "").Parse(txt)
		assert(err == nil).Errorf("%s should be ok: %s", txt, err)
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

func TestAuth_Header_without_qop(t *testing.T) {
	txt := `Digest realm="x", nonce="y", algorithm=MD5`
	auth := NewAuth("", "")
	auth.Parse(txt)
	got := auth.Header("GET", "http://example.com")
	if strings.Index(got, "qop=") != -1 {
		t.Errorf("Found qop=... in %s", got)
	}
}
