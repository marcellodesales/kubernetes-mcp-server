package bootstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// VerifyPKCES256 checks that verifier matches the given S256 code challenge.
func VerifyPKCES256(codeChallenge, codeVerifier string) error {
	if codeChallenge == "" {
		return errors.New("code_challenge is required")
	}
	if !isValidCodeVerifier(codeVerifier) {
		return errors.New("invalid code_verifier")
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	if expected != codeChallenge {
		return fmt.Errorf("pkce verification failed")
	}
	return nil
}

// S256Challenge computes the S256 code challenge for a verifier.
func S256Challenge(codeVerifier string) (string, error) {
	if !isValidCodeVerifier(codeVerifier) {
		return "", errors.New("invalid code_verifier")
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// isValidCodeVerifier applies RFC 7636 character and length requirements.
//
// code_verifier MUST be between 43 and 128 characters, and contain only
// unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~".
func isValidCodeVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z':
			continue
		case c >= 'A' && c <= 'Z':
			continue
		case c >= '0' && c <= '9':
			continue
		case c == '-' || c == '.' || c == '_' || c == '~':
			continue
		default:
			return false
		}
	}
	return true
}
