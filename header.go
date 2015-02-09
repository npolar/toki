package toki

import (
	"encoding/base64"
	"encoding/json"
)

// Define a new struct for the JWT JOSE header. field definitions can be found here:
// https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40#section-4.1
type Header struct {
	TokenType   string `json:"typ,omitempty"` // Private: Determined by the algorithm (not settable from outside)
	Algorithm   string `json:"alg,omitempty"` // Private: Determined by the algorithm (not settable from outside)
	Encryption  string `json:"enc,omitempty"` // Private: Determined by the algorithm (not settable from outside)
	Compression string `json:"zip,omitempty"`
	KeyId       string `json:"kid,omitempty"`
}

func NewHeader() *Header {
	return &Header{
		TokenType: "JWT",
		Algorithm: "HS256",
	}
}

// JsonHeader encodes the Header struct into a json []byte.
func (header *Header) Json() ([]byte, error) {
	return json.Marshal(header)
}

// Base64Header generates a URLencoded base64 string from the JsonHeader.
// See (header *Header)JsonHeader for details on the json encoding.
// See token.go for RemoveBase64Padding(string) details.
func (header *Header) Base64() (string, error) {
	headerJson, err := header.Json()
	encodedString := base64.URLEncoding.EncodeToString(headerJson)
	return StripBase64Padding(encodedString), err
}
