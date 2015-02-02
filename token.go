package toki

type JsonWebToken struct {
	TokenAlgorithm *Algorithm // Specifies the algorithm used by the token
	String         string     // Contains the full JWT object as a string
}

func NewJsonWebToken() *JsonWebToken {
	return &JsonWebToken{
		TokenAlgorithm: HS256, // Use the HS256 algorithm by default
	}
}

// GenerateHeader reads the contents of the SigningAlg and EncryptionAlg keys and
// generates a JWT/JWE compliant JOSE header. Function returns a pointer to a the
// toki Header type offering additional encoding options.
func (jwt *JsonWebToken) GenerateHeader() *Header {
	var header = &Header

	// When the TokenAlgorithm doesn't specify Crypto it means you have a JWT.
	// When crypto is present then you have a JWE enabled token
	if jwt.TokenAlgorithm.Crypto == nil {
		header.Typ = "JWT"
		header.Alg = jwt.TokenAlgorithm.Name
	} else {
		header.Typ = "JWE"
		header.Alg = jwt.TokenAlgorithm.Name
	}

	return header
}

// StripBase64Padding strips the base64 padding char (=) from the provided content string.
// This function is provided because JWTs don't allow padding chars in the token body.
func StripBase64Padding(content string) string {
	return strings.TrimRight(content, "=")
}
