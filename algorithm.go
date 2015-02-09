package toki

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
)

type Algorithm struct {
	Name          string      // Algorithm name as specified in the JWA definition: https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
	SingatureHash crypto.Hash // Algorithm to be used when creating a JWS Object
	CryptoHash    crypto.Hash // Algorithm to be used when generating a JWE Object
}

// Define the supported SHA2 Algorithms used in the JWS

func HS256() *Algorithm {
	return &Algorithm{
		Name:          "HS256",
		SingatureHash: crypto.SHA256,
	}
}

func HS384() *Algorithm {
	return &Algorithm{
		Name:          "HS384",
		SingatureHash: crypto.SHA384,
	}
}

func HS512() *Algorithm {
	return &Algorithm{
		Name:          "HS512",
		SingatureHash: crypto.SHA512,
	}
}

// Hmac produces a signature Hmac based of the algorithm's SignatureHash
func (alg *Algorithm) Hmac(key string, data string) []byte {
	mac := hmac.New(alg.SingatureHash.New, []byte(key))
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// Base64Hmac generates a URLEncoded base64 string using the Hmac method
func (alg *Algorithm) Base64Hmac(key string, data string) string {
	mac := alg.Hmac(key, data)
	base64Mac := base64.URLEncoding.EncodeToString(mac)
	return StripBase64Padding(base64Mac)
}
