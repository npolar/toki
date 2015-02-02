package toki

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Define a new struct for the JWT JOSE header. field definitions can be found here:
// https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40#section-4.1
type Header struct {
	Typ string
	Alg string
	Enc string
	Zip string
	Kid string
}

// JsonHeader encodes the Header struct into a json []byte.
func (header *Header) JsonHeader() ([]byte, error) {
	raw, err := json.Marshal(header)
	return raw, err
}

// Base64Header generates a URLencoded base64 string from the JsonHeader.
// See (header *Header)JsonHeader for details on the json encoding.
// See token.go for RemoveBase64Padding(string) details.
func (header *Header) Base64Header() (string, error) {
	headerJson, err := header.JsonHeader()
	encodedString := base64.URLEncoding.EncodeToString(headerJson)
	return StripBase64Padding(encodedString), err
}
