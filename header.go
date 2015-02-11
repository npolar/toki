package toki

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Define a new struct for the JWT JOSE header. field definitions can be found here:
// https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40#section-4.1
type Header struct {
	Typ string `json:"typ,omitempty"` // Token Type [Determined by the algorithm] - OPTIONAL
	Alg string `json:"alg,omitempty"` // Token Alg [Determined by the algorithm] - REQUIRED
	Enc string `json:"enc,omitempty"` // Token Encryption [Determined by the algorithm] - OPTIONAL
	Zip string `json:"zip,omitempty"` // Compression used on the token - OPTIONAL
	Kid string `json:"kid,omitempty"` // Unique token ID - OPTIONAL
}

// NewHeader creates a header object with the default algorithm settings
func NewHeader() *Header {
	return &Header{
		Typ: "JWT",
		Alg: "HS256",
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

func (header *Header) Parse(jose string) error {
	var decoded Header

	if err := json.Unmarshal([]byte(jose), &decoded); err != nil {
		return err
	}

	if err := decoded.Valid(); err != nil {
		return err
	}

	header = &decoded

	return nil
}

func (header *Header) Valid() error {
	if header.Alg == "" {
		return errors.New("[Invalid Jose Header] Missing required field: alg")
	}

	return nil
}

// @TODO Add checks for the supported types so we can bail on corrupted header contents
//func (header *Header) ValidType(typ string) bool {
//
//}
//
//func (header *Header) ValidAlg(alg string) bool {
//
//}
//
//// ValidEncryption checks if the encryption name
//// matches one of the types defined by the JWA spec
//// https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-5
//func (header *Header) ValidEncryption(enc string) bool {
//
//}
