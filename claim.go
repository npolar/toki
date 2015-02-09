package toki

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// Info about claims vocabulary within JWT can be found here: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#Claims
type Claims struct {
	Audience  string                 `json:"aud,omitempty"`     // Specifies the audience the JWT is meant for
	ExpiresAt int64                  `json:"exp,omitempty"`     // Time until the token expires (seconds since the Unix epoch)
	IssuedAt  int64                  `json:"iat,omitempty"`     // Time the token was issued (seconds since Unix epoch)
	Issuer    string                 `json:"is,omitempty"`      // Identity of the issuer: eg. server ID (optional)
	NotBefore int64                  `json:"nbf,omitempty"`     // Token is not valid before (seconds since the Unix epoch)
	TokenID   string                 `json:"jti,omitempty"`     // Unique ID for the token (optional)
	Payload   map[string]interface{} `json:"payload,omitempty"` // Additional Payload outside the official claims vocabulary
	Subject   string                 `json:"sub,omitempty"`     // Contains info about the subject of the JWT
}

// NewClaims initializes the claims struct.
func NewClaims() *Claims {
	return &Claims{
		IssuedAt: time.Now().UTC().Unix(),
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
