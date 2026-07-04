package bootstrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// sealKeyBytes is the required key length for AES-256.
	sealKeyBytes = 32
	// nonceSize is the GCM nonce size. cipher.AEAD.NonceSize() is also 12 for GCM,
	// but we keep this constant explicit since tokens embed the nonce.
	nonceSize = 12
)

type Sealer struct {
	gcm       cipher.AEAD
	rand      io.Reader
	aadPrefix string
}

func NewSealer(key []byte, aadPrefix string) (*Sealer, error) {
	if len(key) != sealKeyBytes {
		return nil, fmt.Errorf("invalid sealer key length %d (expected %d)", len(key), sealKeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM: %w", err)
	}
	if gcm.NonceSize() != nonceSize {
		return nil, fmt.Errorf("unexpected AES-GCM nonce size %d (expected %d)", gcm.NonceSize(), nonceSize)
	}
	return &Sealer{gcm: gcm, rand: rand.Reader, aadPrefix: aadPrefix}, nil
}

func (s *Sealer) aad(tokenType string) []byte {
	// AAD binds the token to this server module and token type.
	return []byte(s.aadPrefix + ":" + tokenType)
}

func (s *Sealer) Seal(tokenType string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token payload: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(s.rand, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := s.gcm.Seal(nil, nonce, plain, s.aad(tokenType))
	buf := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Sealer) Unseal(tokenType, token string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("invalid token encoding: %w", err)
	}
	if len(raw) < nonceSize {
		return errors.New("invalid token: too short")
	}
	nonce := raw[:nonceSize]
	ciphertext := raw[nonceSize:]
	plain, err := s.gcm.Open(nil, nonce, ciphertext, s.aad(tokenType))
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}
	if err := json.Unmarshal(plain, out); err != nil {
		return fmt.Errorf("invalid token payload: %w", err)
	}
	return nil
}

func ParseSealerKeyBase64URL(key string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid MCP_AUTH_SECRET encoding (expected base64url): %w", err)
	}
	if len(b) != sealKeyBytes {
		return nil, fmt.Errorf("invalid MCP_AUTH_SECRET length %d (expected %d bytes)", len(b), sealKeyBytes)
	}
	return b, nil
}
