package toki

import (
	"errors"
	"strings"
)

type JsonWebToken struct {
	Jose           *Header    // Info @ toki/header.go
	Claim          *Claims    // Info @ toki/claims.go
	Signature      string     // The signature HMAC of the base64 encoded header.claim
	TokenAlgorithm *Algorithm // Specifies the algorithm used by the token
}

func NewJsonWebToken() *JsonWebToken {
	return &JsonWebToken{
		Jose:           NewHeader(), // Set the default header to match the default algorithm
		TokenAlgorithm: HS256(),     // Use the HS256 algorithm by default
		Claim:          NewClaims(), // Initialize the body with a new claims object
	}
}

// UpdateTokenHeader uses SigningAlg and EncryptionAlg to update the tokenType and algorithm
// settings of the header so it matches the specified TokenAlgorithm.
func (jwt *JsonWebToken) UpdateTokenHeader() {
	// When the TokenAlgorithm specifies crypto we have a JWE token.
	if jwt.TokenAlgorithm.CryptoHash.Available() {
		jwt.Jose.TokenType = "JWE"
		jwt.Jose.Algorithm = jwt.TokenAlgorithm.Name
	} else {
		jwt.Jose.TokenType = "JWT"
		jwt.Jose.Algorithm = jwt.TokenAlgorithm.Name
	}
}

// Sign uses the tokens header and claims contents to generate a signature for the token.
func (jwt *JsonWebToken) Sign(secret string) error {
	jwt.UpdateTokenHeader() // Update the header to match any overriden values

	if content, err := jwt.JoseClaimString(); err == nil {
		base64Hmac := jwt.TokenAlgorithm.Base64Hmac(secret, content)
		jwt.Signature = StripBase64Padding(base64Hmac)
	} else {
		return err
	}

	return nil
}

// String combines Content String and the result from a S returns the full JWT string
func (jwt *JsonWebToken) String() (string, error) {
	if jwt.Signature != "" {
		content, err := jwt.JoseClaimString()

		if err != nil {
			return "", err
		}

		return content + "." + jwt.Signature, err
	} else {
		// Optionally set the header to unsecure and don't use a secret to sign!
		return "", errors.New("Missing signature! Sign the token before calling string")
	}
}

// JoseClaimString joins the base64 of the Jose header and claim with a dot
func (jwt *JsonWebToken) JoseClaimString() (string, error) {
	encodedClaims, err := jwt.Claim.Base64()
	encodedHeader, err := jwt.Jose.Base64()

	// If one of both generates an error return a blank string with the error.
	// Since the err var is re-used the last error will bleed through first.
	if err != nil {
		return "", err
	}

	return encodedHeader + "." + encodedClaims, err
}

// StripBase64Padding strips the base64 padding char (=) from the provided content string.
// This function is provided because JWTs don't allow padding chars in the token body.
func StripBase64Padding(content string) string {
	return strings.TrimRight(content, "=")
}
