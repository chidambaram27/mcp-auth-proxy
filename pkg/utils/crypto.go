package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Purposes for keys derived from the master secret (AUTH_HMAC_SECRET). Each
// use gets its own key so that one key is never used for two algorithms.
const (
	KeyPurposeCookieAuth     = "mcp-auth-proxy cookie-auth v1"
	KeyPurposeCookieEncrypt  = "mcp-auth-proxy cookie-encrypt v1"
	KeyPurposeUpstreamTokens = "mcp-auth-proxy upstream-token-encrypt v1"
)

// DeriveKey derives a 32-byte key for purpose from the master secret (HKDF-SHA256).
func DeriveKey(secret []byte, purpose string) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret must not be empty")
	}
	return hkdf.Key(sha256.New, secret, nil, purpose, 32)
}

// Sealer encrypts small values (AES-256-GCM) for storage.
type Sealer struct {
	aead cipher.AEAD
}

func NewSealer(key []byte) (*Sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext and binds it to associatedData (e.g. the user ID).
func (s *Sealer) Seal(plaintext, associatedData string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, []byte(plaintext), []byte(associatedData))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func (s *Sealer) Open(sealed, associatedData string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("invalid sealed value: %w", err)
	}
	if len(raw) < s.aead.NonceSize() {
		return "", errors.New("invalid sealed value")
	}
	plain, err := s.aead.Open(nil, raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():], []byte(associatedData))
	if err != nil {
		return "", errors.New("failed to decrypt sealed value")
	}
	return string(plain), nil
}
