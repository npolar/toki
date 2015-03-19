package toki

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
)

// @TODO add a JoseClaim string attr for signing of externally generated json
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
		jwt.Jose.Typ = "JWE"
		jwt.Jose.Alg = jwt.TokenAlgorithm.Name
	} else {
		jwt.Jose.Typ = "JWT"
		jwt.Jose.Alg = jwt.TokenAlgorithm.Name
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

func (jwt *JsonWebToken) CalculateSignature(secret string) (string, error) {
	jwt.UpdateTokenHeader() // Update the header to match any overriden values

	if jwt.TokenAlgorithm.Name == "none" {
		return "", nil
	}

	if content, err := jwt.JoseClaimString(); err == nil {
		base64Hmac := jwt.TokenAlgorithm.Base64Hmac(secret, content)
		return StripBase64Padding(base64Hmac), nil
	} else {
		return "", err
	}
}

// Sign uses the tokens header and claims contents to generate a signature for the token.
func (jwt *JsonWebToken) Sign(secret string) error {
	if signature, err := jwt.CalculateSignature(secret); err == nil {
		jwt.Signature = StripBase64Padding(signature)
		return nil
	} else {
		return err
	}
}

// String combines Content String and the result from a S returns the full JWT string
func (jwt *JsonWebToken) String() (string, error) {
	content, err := jwt.JoseClaimString()

	if err != nil {
		return "", err
	}

	return content + "." + jwt.Signature, err
}

// Parse is used to decode and split an externally provided token.
// Token contents will then be loaded in the relevant attributes and
// can be used for validation purposes
func (jwt *JsonWebToken) Parse(token string) error {
	if jwt.ValidTokenString(token) {
		var jose, claim string
		var err error

		// Split the string into the respective parts
		tokenSegments := strings.Split(token, ".")

		if jose, err = DecodeNonPaddedBase64(tokenSegments[0]); err != nil {
			return err
		}

		if err = jwt.Jose.Parse(jose); err != nil {
			return err
		}

		// User the parsed header info to set the TokenAlgoritm
		jwt.DetermineTokenAlgorithm()

		if claim, err = DecodeNonPaddedBase64(tokenSegments[1]); err != nil {
			return err
		}

		if err = jwt.Claim.Parse(claim); err != nil {
			return err
		}

		jwt.Signature = tokenSegments[2]

		return nil
	} else {
		return errors.New("Invalid token format! Input: " + token)
	}
}

// @TODO figure out secret recovery. Should be a mechanism based on the token content and/or memcache obj
func (jwt *JsonWebToken) Valid(secret string) (bool, error) {
	if signature, err := jwt.CalculateSignature(secret); err == nil {
		if jwt.Signature == signature {
			return true, nil
		} else {
			return false, errors.New("[Invalid Token] Signature mismatch.")
		}
	} else {
		return false, err
	}
}

func (jwt *JsonWebToken) DetermineTokenAlgorithm() {
	switch jwt.Jose.Alg {
	case "none":
		jwt.TokenAlgorithm = NoAlg()
	case "HS256":
		jwt.TokenAlgorithm = HS256()
	case "HS384":
		jwt.TokenAlgorithm = HS384()
	case "HS512":
		jwt.TokenAlgorithm = HS512()
	}
}

// ValidTokenString checks if the full token string follows the spec.
// Checks if the token uses URLEncodedBase64 (http://tools.ietf.org/html/rfc4648#section-5)
// and doesn't use any base64 padding tokens (=) at the end of the segments
func (jwt *JsonWebToken) ValidTokenString(token string) bool {
	tokenRxp := regexp.MustCompile("^[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+$")
	return tokenRxp.MatchString(token)
}

// StripBase64Padding strips the base64 padding char (=) from the provided content string.
// This function is provided because JWTs don't allow padding chars in the token body.
func StripBase64Padding(content string) string {
	return strings.TrimRight(content, "=")
}

func DecodeNonPaddedBase64(base64String string) (string, error) {
	// Check if the string has the propper length. If not we add the required padding
	base64String = PadBase64(base64String)

	content, err := base64.URLEncoding.DecodeString(base64String)
	return string(content), err
}

func PadBase64(nonPaddedBase64 string) string {
	if remainder := len(nonPaddedBase64) % 4; remainder != 0 {
		nonPaddedBase64 = nonPaddedBase64 + "="
		nonPaddedBase64 = PadBase64(nonPaddedBase64)
	}

	return nonPaddedBase64
}
