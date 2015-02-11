package toki

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Info about claims vocabulary within JWT can be found here: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#Claims
type Claims struct {
	Content map[string]interface{}
}

// NewClaims initializes the claims struct.
func NewClaims() *Claims {
	var defaults = make(map[string]interface{})
	defaults["iat"] = time.Now().UTC().Unix()
	return &Claims{
		Content: defaults,
	}
}

// Json casts the claims struct to a json encoded byte slice
func (claims *Claims) Json() ([]byte, error) {
	return json.Marshal(claims.Content)
}

// Base64 calls json and then converts the byte slice to a base64 string without padding
func (claims *Claims) Base64() (string, error) {
	jsonClaims, err := claims.Json()
	base64String := base64.URLEncoding.EncodeToString(jsonClaims)
	return StripBase64Padding(base64String), err
}

func (claims *Claims) Parse(claim string) error {
	var raw = make(map[string]interface{})
	decoder := json.NewDecoder(bytes.NewBufferString(claim))
	decoder.UseNumber() // Make sure ints are decoded correctly

	if err := decoder.Decode(&raw); err != nil {
		return errors.New("[Invalid Claims] Decoding " + err.Error()) // Return any decoding errors to the caller
	}

	claims.Content = raw

	return nil // Everything is OK!
}
