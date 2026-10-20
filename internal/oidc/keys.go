package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lieyanc/FireID/internal/store"
)

// EnsureSigningKey creates the first signing key when none exists. It runs at
// start-up so request handling never generates keys, and two instances racing
// on an empty database settle on one key.
func (s *Storage) EnsureSigningKey(ctx context.Context) error {
	if _, err := s.store.CurrentSigningKey(); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("read current signing key: %w", err)
	}
	alg := jose.SignatureAlgorithm(s.settings.SigningAlgorithm)
	priv, err := generatePrivateKey(alg)
	if err != nil {
		return err
	}
	kid, err := randomKID()
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privEnc, err := s.box.Seal(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}
	pubJSON, err := json.Marshal(jose.JSONWebKey{
		Key:       priv.Public(),
		KeyID:     kid,
		Algorithm: string(alg),
		Use:       "sig",
	})
	if err != nil {
		return fmt.Errorf("marshal public jwk: %w", err)
	}
	err = s.store.InsertCurrentSigningKey(kid, string(alg), privEnc, string(pubJSON))
	if errors.Is(err, store.ErrConflict) {
		return nil
	}
	return err
}

func generatePrivateKey(alg jose.SignatureAlgorithm) (crypto.Signer, error) {
	switch alg {
	case jose.ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.RS256:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", alg)
	}
}

// SigningKey implements op.AuthStorage.
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	row, err := s.store.CurrentSigningKey()
	if err != nil {
		return nil, fmt.Errorf("read current signing key: %w", err)
	}
	return s.parseSigningKey(row)
}

// SignatureAlgorithms implements op.AuthStorage: the algorithms of the keys
// that are published, which is what a verifier may meet. A changed
// oidc.signingAlgorithm applies to the next key, not to the current one.
func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	rows, err := s.store.PublishedSigningKeys()
	if err != nil {
		return nil, err
	}
	var algs []jose.SignatureAlgorithm
	for _, r := range rows {
		alg := jose.SignatureAlgorithm(r.Alg)
		if !containsAlg(algs, alg) {
			algs = append(algs, alg)
		}
	}
	if len(algs) == 0 {
		algs = append(algs, jose.SignatureAlgorithm(s.settings.SigningAlgorithm))
	}
	return algs, nil
}

func containsAlg(algs []jose.SignatureAlgorithm, alg jose.SignatureAlgorithm) bool {
	for _, a := range algs {
		if a == alg {
			return true
		}
	}
	return false
}

// KeySet implements op.AuthStorage. It reads only the public JWKs: the
// private halves are never decrypted to serve /keys.
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	rows, err := s.store.PublishedSigningKeys()
	if err != nil {
		return nil, fmt.Errorf("query key set: %w", err)
	}
	keys := make([]op.Key, 0, len(rows))
	for _, r := range rows {
		var jwk jose.JSONWebKey
		if err := json.Unmarshal([]byte(r.PublicJWK), &jwk); err != nil {
			return nil, fmt.Errorf("unmarshal public jwk %s: %w", r.KID, err)
		}
		if !jwk.IsPublic() {
			return nil, fmt.Errorf("stored jwk %s is not a public key", r.KID)
		}
		keys = append(keys, &publicKey{kid: r.KID, alg: jose.SignatureAlgorithm(r.Alg), key: jwk.Key})
	}
	return keys, nil
}

// GetKeyByIDAndClientID implements op.OPStorage. It serves private_key_jwt
// client authentication, which is not offered.
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, errors.New("client keys are not supported")
}

// parseSigningKey decrypts the private key of a stored row.
func (s *Storage) parseSigningKey(row *store.SigningKey) (op.SigningKey, error) {
	privPEM, err := s.box.Open(row.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key %s: %w", row.KID, err)
	}
	priv, err := parsePEMPrivateKey(privPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", row.KID, err)
	}
	return &signingKey{kid: row.KID, alg: jose.SignatureAlgorithm(row.Alg), priv: priv}, nil
}

// signingKey implements op.SigningKey. It holds the private key and is only
// handed to the signer.
type signingKey struct {
	kid  string
	alg  jose.SignatureAlgorithm
	priv crypto.PrivateKey
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return k.alg }
func (k *signingKey) Key() any                                    { return k.priv }
func (k *signingKey) ID() string                                  { return k.kid }

// publicKey implements op.Key, which is what /keys publishes. It is a separate
// type from signingKey so a private key cannot end up in the JWKS by mistake.
type publicKey struct {
	kid string
	alg jose.SignatureAlgorithm
	key any
}

func (k *publicKey) ID() string                         { return k.kid }
func (k *publicKey) Algorithm() jose.SignatureAlgorithm { return k.alg }
func (k *publicKey) Use() string                        { return "sig" }
func (k *publicKey) Key() any                           { return k.key }

// parsePEMPrivateKey reads a PKCS #8 block, or the SEC 1 form an early build
// wrote for ECDSA keys.
func parsePEMPrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
}

// randomKID returns a random key ID.
func randomKID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate key id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
