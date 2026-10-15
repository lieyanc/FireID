// Package secretbox seals small secrets with AES-256-GCM under the master key.
// It is used for values that must be recoverable at runtime — TOTP shared
// secrets and JWT signing keys — as opposed to values that are only ever
// compared, such as passwords and OAuth client secrets, which are hashed.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrInvalid is returned when a ciphertext cannot be opened with the given key:
// wrong key, truncated value, or tampering.
var ErrInvalid = errors.New("secretbox: ciphertext is not authentic")

// Box seals and opens values with one key.
type Box struct {
	aead cipher.AEAD
}

// New builds a Box from a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secretbox: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext and returns it base64url-encoded with the random
// nonce prepended. Empty plaintext stays empty, so callers can store "" to mean
// "no secret".
func (b *Box) Seal(plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretbox: read nonce: %w", err)
	}
	out := b.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// SealString is Seal for text.
func (b *Box) SealString(plaintext string) (string, error) {
	return b.Seal([]byte(plaintext))
}

// Open reverses Seal. An empty input is not an error; it returns nil.
func (b *Box) Open(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("secretbox: decode: %w", err)
	}
	if len(raw) < b.aead.NonceSize()+b.aead.Overhead() {
		return nil, ErrInvalid
	}
	nonce, ciphertext := raw[:b.aead.NonceSize()], raw[b.aead.NonceSize():]
	plaintext, err := b.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrInvalid
	}
	return plaintext, nil
}

// OpenString is Open for text.
func (b *Box) OpenString(encoded string) (string, error) {
	plaintext, err := b.Open(encoded)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
