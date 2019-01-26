package digest

import (
	"crypto"
	"strings"
)

func parseHash(alg string) (h crypto.Hash) {
	alg = strings.ToUpper(alg)
	switch alg {
	case "MD4":
		h = crypto.MD4
	case "MD5":
		h = crypto.MD5
	case "SHA1":
		h = crypto.SHA1
	case "SHA224":
		h = crypto.SHA224
	case "SHA256":
		h = crypto.SHA256
	case "SHA384":
		h = crypto.SHA384
	case "SHA512":
		h = crypto.SHA512
	case "RIPEMD160":
		h = crypto.RIPEMD160
	case "SHA3_224":
		h = crypto.SHA3_224
	case "SHA3_256":
		h = crypto.SHA3_256
	case "SHA3_384":
		h = crypto.SHA3_384
	case "SHA3_512":
		h = crypto.SHA3_512
	case "SHA512_224":
		h = crypto.SHA512_224
	case "SHA512_256":
		h = crypto.SHA512_256
		/* According to crypto docs these should be available via
		           golang.org/x/crypto/blake2b, though it doesn't seem to work
			case "BLAKE2s_256":
				h = crypto.BLAKE2s_256
			case "BLAKE2b_256":
				h = crypto.BLAKE2b_256
			case "BLAKE2b_384":
				h = crypto.BLAKE2b_384
			case "BLAKE2b_512":
				h = crypto.BLAKE2b_512*/
	}
	return
}
