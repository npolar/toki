package toki

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Info about claims vocabulary within JWT can be found here: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#Claims
type Claims struct {
	Aud     string                 `json:"aud,omitempty"`     // Specifies the audience the JWT is meant for
	Content map[string]interface{} `json:"content,omitempty"` // Additional content outside the official claims vocabulary
	Exp     int64                  `json:"exp,omitempty"`     // Time until the token expires (seconds since the Unix epoch)
	Iat     int64                  `json:"iat,omitempty"`     // Time the token was issued (seconds since Unix epoch)
	Iss     string                 `json:"iss,omitempty"`     // Identity of the issuer: eg. server ID (optional)
	Jti     string                 `json:"jti,omitempty"`     // Unique ID for the token (optional)
	Nbf     int64                  `json:"nbf,omitempty"`     // Token is not valid before (seconds since the Unix epoch)
	Sub     string                 `json:"sub,omitempty"`     // Contains info about the subject of the JWT
}

// NewClaims initializes the claims struct.
func NewClaims() *Claims {
	return &Claims{
		Iat: time.Now().UTC().Unix(),
	}
}

// Json casts the claims struct to a json encoded byte slice
func (claims *Claims) Json() ([]byte, error) {
	return json.Marshal(claims)
}

// Base64 calls json and then converts the byte slice to a base64 string without padding
func (claims *Claims) Base64() (string, error) {
	jsonClaims, err := claims.Json()
	base64String := base64.URLEncoding.EncodeToString(jsonClaims)
	return StripBase64Padding(base64String), err
}

func (claims *Claims) Parse(claim string) error {
	if err := json.Unmarshal([]byte(claim), claims); err != nil {
		return errors.New("[Invalid Claims] Decoding " + err.Error()) // Return any decoding errors to the caller
	}

	return nil // Everything is OK!
}
