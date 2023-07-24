/* Package provides header generator for digest authentication.

The Auth object can be reused for subsequent requests.

Example:

    req, _ := http.NewRequest("GET", "/", nil)
    resp, _ := http.DefaultClient.Do(req)
    if resp.StatusCode == http.StatusUnauthorized {
        auth := NewAuth("john.doe", "secret")
        err := auth.Parse(resp.Header.Get("www-authenticate"))
        if err != nil {
            // cannot authenticate using this package
        }
        auth.Authorize(req)
    }
    resp, _ := http.DefaultClient.Do(req)

    // and for the next request just authorize it before sending
    auth.Authorize(req2)
*/
package digest

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
)

func NewAuth(username, pwd string) *Auth {
	return &Auth{
		username: username,
		pwd:      pwd,
		nc:       1,
		cnonce:   newNonce(),
		hash:     crypto.MD5,
	}
}

type Auth struct {
	method, uri, username, pwd        string
	realm, nonce, qop, cnonce, opaque string
	nc                                int32
	hash                              crypto.Hash
}

// SetHash to use during authorization. Auth.Parse tries to guess it
// from the algorithm but when that fails you override it.
func (a *Auth) SetHash(v crypto.Hash) {
	a.hash = v
}


// Authorize sets the Authorization header on the given request.
// Also each call updates nc by one.
func (auth *Auth) Authorize(req *http.Request) {
	atomic.AddInt32(&auth.nc, 1)
	req.Header.Set("Authorization", auth.Header(req.Method, req.URL.Path))
}

// Parse parses the WWW-Authenticate header value. Once correctly
// parsed use the Authorize func to set the response header on a
// subsequent request.
func (auth *Auth) Parse(authHeader string) error {
	i := strings.Index(authHeader, " ")
	if i == -1 {
		return fmt.Errorf("Bad authHeader string")
	}
	cred := authHeader[:i]
	if cred != "Digest" {
		return fmt.Errorf("Unknown authentication method: %s", cred)
	}
	params := parseValues(authHeader[i:])
	alg := params["algorithm"]

	auth.hash = parseHash(alg)
	if !auth.hash.Available() {
		return fmt.Errorf("Unknown algorithm: %s", alg)
	}

	auth.nonce = params["nonce"]
	auth.realm = params["realm"]
	auth.opaque = params["opaque"]
	auth.qop = params["qop"]
	return nil
}

func (auth *Auth) Header(method, uri string) string {
	auth.method = method
	auth.uri = uri

	f := make([]string, 0)
	f = append(f, fmt.Sprintf("username=%q", auth.username))
	f = append(f, fmt.Sprintf("realm=%q", auth.realm))
	f = append(f, fmt.Sprintf("nonce=%q", auth.nonce))
	f = append(f, fmt.Sprintf("uri=%q", auth.uri))
	if auth.useQualityOfProtection() {
		f = append(f, fmt.Sprintf("qop=%s", auth.qop))
	}
	f = append(f, fmt.Sprintf("nc=%08v", auth.nc))
	if auth.useQualityOfProtection() {
		f = append(f, fmt.Sprintf("cnonce=%q", auth.cnonce))
	}
	f = append(f, fmt.Sprintf("response=%q", auth.response()))
	if auth.opaque != "" {
		f = append(f, fmt.Sprintf("opaque=%q", auth.opaque))
	}
	return "Digest " + strings.Join(f, ", ")
}

// Described in https://tools.ietf.org/html/rfc2617#page-12
func (auth *Auth) useQualityOfProtection() bool {
	return auth.qop != ""
}

func (auth *Auth) response() string {
	h := auth.hash.New()
	fmt.Fprintf(h, "%s:%s:%s", auth.username, auth.realm, auth.pwd)
	ha1 := fmt.Sprintf("%x", h.Sum(nil))
	h.Reset()

	fmt.Fprintf(h, "%s:%s", auth.method, auth.uri)
	ha2 := fmt.Sprintf("%x", h.Sum(nil))
	h.Reset()

	fmt.Fprintf(h, "%s:%s:%08v:%s:%s:%s",
		ha1, auth.nonce, auth.nc, auth.cnonce, auth.qop, ha2)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func newNonce() string {
	const size = 8
	buff := make([]byte, size)
	io.ReadFull(rand.Reader, buff)
	return fmt.Sprintf("%x", buff)[:size*2]
}

func parseValues(authHeader string) (res map[string]string) {
	res = make(map[string]string)
	for _, v := range strings.Split(authHeader, ",") {
		v = strings.TrimSpace(v)
		i := strings.Index(v, "=")
		if i == -1 {
			// error
			continue
		}
		name := v[:i]
		res[name] = findVal(v, name)
	}
	return
}

func findVal(authHeader, name string) (val string) {
	i := strings.Index(authHeader, name)
	if i == -1 {
		return ""
	}
	i = i + len(name) + 1
	end := strings.Index(authHeader[i:], ",")
	if end == -1 {
		val = authHeader[i:]
	} else {
		val = authHeader[i : i+end]
	}
	return strings.Trim(val, `"`)
}
