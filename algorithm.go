package toki

import (
	"crypto"
)

type Algorithm struct {
	Name      string      // Algorithm name as specified in the JWA definition: https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
	Singature crypto.Hash // Algorithm to be used when creating a JWS Object
	Crypto    crypto.Hash // Algorithm to be used when generating a JWE Object
}

// Define the supported SHA2 Algorithms used in the JWS

func HS256() *Algorithm {
	return &Algorithm{
		Name:      "HS256",
		Singature: crypto.SHA256,
	}
}

func HS384() *Algorithm {
	return &Algorithm{
		Name:      "HS384",
		Singature: crypto.SHA384,
	}
}

func HS512() *Algorithm {
	return &Algorithm{
		Name:      "HS512",
		Singature: crypto.SHA512,
	}
}
