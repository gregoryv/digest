package digest

import "testing"

func Test_parseHash(t *testing.T) {
	cases := []string{
		"MD4", "MD5",
		"SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
		"RIPEMD160",
		"SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512",
		"SHA512_224", "SHA512_256",
		"SHA-256", // seen in the wild
	}
	for _, v := range cases {
		if h := parseHash(v); !h.Available() {
			t.Errorf("unkown hash %q", v)
		}
	}
}
