package digest

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func NewAuth(username, pwd string) *Auth {
	return &Auth{
		username: username,
		pwd:      pwd,
		nc:       1,
		cnonce:   newNonce(),
	}
}

type Auth struct {
	method, uri, username, pwd        string
	realm, nonce, qop, cnonce, opaque string
	nc                                int
}

func (da *Auth) Authorize(req *http.Request) {
	da.nc++
	req.Header.Set("Authorization", da.Header(req.Method, req.URL.Path))
}

func (da *Auth) Parse(authHeader string) error {
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
	if alg != "MD5" {
		return fmt.Errorf("Unknown algorithm %q", alg)
	}
	da.nonce = params["nonce"]
	da.realm = params["realm"]
	da.opaque = params["opaque"]
	da.qop = params["qop"]
	return nil
}

func (da *Auth) Header(method, uri string) string {
	da.method = method
	da.uri = uri
	qVar := ""
	if da.opaque != "" {
		qVar = fmt.Sprintf(", opaque=%q", da.opaque)
	}
	return fmt.Sprintf(
		"Digest %s=%q, %s=%q, %s=%q, %s=%q, %s=%s, %s=%08v, %s=%q, %s=%q%s",
		"username", da.username,
		"realm", da.realm,
		"nonce", da.nonce,
		"uri", da.uri,
		"qop", da.qop,
		"nc", da.nc,
		"cnonce", da.cnonce,
		"response", da.response(), qVar)
}

func (da *Auth) response() string {
	ha1 := md5f("%s:%s:%s", da.username, da.realm, da.pwd)
	ha2 := md5f("%s:%s", da.method, da.uri)
	return md5f("%s:%s:%08v:%s:%s:%s",
		ha1, da.nonce, da.nc, da.cnonce, da.qop, ha2)
}

func md5f(tmpl string, args ...interface{}) string {
	h := md5.New()
	fmt.Fprintf(h, tmpl, args...)
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
