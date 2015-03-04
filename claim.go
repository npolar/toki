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
	return &Claims{
		Content: make(map[string]interface{}),
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

	// @TODO wrap validation checks in a validator
	if expired, err := claims.TokenExpired(); expired {
		return err
	}

	if active, err := claims.TokenActive(); !active {
		return err
	}

	return nil // Everything is OK!
}

func (claims *Claims) TokenExpired() (bool, error) {
	if claims.Content["exp"] != nil {
		expiredTime, _ := claims.Content["exp"].(json.Number).Int64()
		now := time.Now().UTC().Unix()

		if expiredTime < now {
			return true, errors.New("[Invalid token] Token has expired!")
		}
	}
	return false, nil
}

func (claims *Claims) TokenActive() (bool, error) {
	if claims.Content["nbf"] != nil {
		activationTime, _ := claims.Content["nbf"].(json.Number).Int64()
		now := time.Now().UTC().Unix()

		if activationTime > now {
			return false, errors.New("[Invalid token] Token not usable before: " + time.Unix(activationTime, 0).String())
		}
	}
	return true, nil
}
