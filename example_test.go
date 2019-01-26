package digest

import (
	"fmt"
	"net/http"
	"strings"
)

// Example is the same as described on wikipedia at
// https://en.wikipedia.org/wiki/Digest_access_authentication
func ExampleAuth_Header() {
	wwwAuth := fmt.Sprintf(
		"Digest %s=%q, %s=%q, %s=%q, %s=%s, %s=%q",
		"realm", "testrealm@host.com",
		"nonce", "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		"algorithm", "MD5",
		"qop", "auth",
		"opaque", "5ccc069c403ebaf9f0171e9517f40e41")
	auth := NewAuth("Mufasa", "Circle Of Life")
	err := auth.Parse(wwwAuth)
	if err != nil {
		// cannot use digest
	}

	auth.cnonce = "0a4f113b"
	hdr := auth.Header("GET", "/dir/index.html")
	fmt.Println(strings.Replace(hdr, ", ", ",\n", -1))
	//output:
	// Digest username="Mufasa",
	// realm="testrealm@host.com",
	// nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
	// uri="/dir/index.html",
	// qop=auth,
	// nc=00000001,
	// cnonce="0a4f113b",
	// response="6629fae49393a05397450978507c4ef1",
	// opaque="5ccc069c403ebaf9f0171e9517f40e41"
}

func ExampleAuth_Authorize() {
	auth := NewAuth("john.doe", "secret")
	req, _ := http.NewRequest("GET", "/", nil)
	auth.Authorize(req)
	//output:
}
