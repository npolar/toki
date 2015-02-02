package toki

import (
	"crypto"
)

const (
	HS256 = Algorithm{
		Name:      "HS256",
		Singature: crypto.SHA256,
	}

	HS384 = Algorithm{
		Name:      "HS384",
		Singature: crypto.SHA384,
	}

	HS512 = Algorithm{
		Name:      "HS512",
		Singature: crypto.SHA512,
	}
)

type Algorithm struct {
	Name      string      // Algorithm name as specified in the JWA definition: https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
	Singature crypto.Hash // Algorithm to be used when creating a JWS Object
	Crypto    crypto.Hash // Algorithm to be used when generating a JWE Object
}
