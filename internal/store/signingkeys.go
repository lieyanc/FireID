package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SigningKey is a stored token-signing key. The private half is sealed with
// the master key; the store never sees it in the clear.
type SigningKey struct {
	ID            int64
	KID           string
	Alg           string
	PrivateKeyEnc string
	PublicJWK     string
	CreatedAt     time.Time
	ActivatedAt   time.Time
	RetiredAt     time.Time
	IsCurrent     bool
}

const signingKeyColumns = `id, kid, alg, private_key_enc, public_jwk, created_at, activated_at, retired_at, is_current`

func scanSigningKey(row interface{ Scan(...any) error }) (*SigningKey, error) {
	var k SigningKey
	var createdAt, activatedAt, retiredAt string
	var current int
	if err := row.Scan(&k.ID, &k.KID, &k.Alg, &k.PrivateKeyEnc, &k.PublicJWK,
		&createdAt, &activatedAt, &retiredAt, &current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	k.CreatedAt = parseTime(createdAt)
	k.ActivatedAt = parseTime(activatedAt)
	k.RetiredAt = parseTime(retiredAt)
	k.IsCurrent = current == 1
	return &k, nil
}

// CurrentSigningKey returns the key new tokens are signed with.
func (s *Store) CurrentSigningKey() (*SigningKey, error) {
	return scanSigningKey(s.db.QueryRow(`SELECT ` + signingKeyColumns + ` FROM signing_keys WHERE is_current = 1`))
}

// PublishedSigningKeys returns every key that verifiers should still accept,
// newest first. A key stays published after it stops being current so that
// tokens signed just before a rotation keep verifying.
func (s *Store) PublishedSigningKeys() ([]*SigningKey, error) {
	rows, err := s.db.Query(`SELECT ` + signingKeyColumns + ` FROM signing_keys
		WHERE retired_at = '' ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// InsertCurrentSigningKey stores a key as the current one when no current key
// exists yet. When another process got there first it returns ErrConflict and
// the caller should read the winner back.
func (s *Store) InsertCurrentSigningKey(kid, alg, privateKeyEnc, publicJWK string) error {
	return s.inTx(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM signing_keys WHERE is_current = 1`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrConflict
		}
		now := s.nowText()
		_, err := tx.Exec(`INSERT INTO signing_keys
			(kid, alg, private_key_enc, public_jwk, created_at, activated_at, is_current)
			VALUES (?, ?, ?, ?, ?, ?, 1)`, kid, alg, privateKeyEnc, publicJWK, now, now)
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	})
}

// ListSigningKeys returns every stored key, retired ones included, newest
// first.
func (s *Store) ListSigningKeys() ([]*SigningKey, error) {
	rows, err := s.db.Query(`SELECT ` + signingKeyColumns + ` FROM signing_keys ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}
	defer rows.Close()
	var out []*SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RotateSigningKey makes a new key current. The previous current key stays
// published, so tokens it signed keep verifying until it is retired.
func (s *Store) RotateSigningKey(kid, alg, privateKeyEnc, publicJWK string) error {
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE signing_keys SET is_current = 0 WHERE is_current = 1`); err != nil {
			return fmt.Errorf("demote current key: %w", err)
		}
		now := s.nowText()
		_, err := tx.Exec(`INSERT INTO signing_keys
			(kid, alg, private_key_enc, public_jwk, created_at, activated_at, is_current)
			VALUES (?, ?, ?, ?, ?, ?, 1)`, kid, alg, privateKeyEnc, publicJWK, now, now)
		if isUniqueViolation(err) {
			return ErrConflict
		}
		if err != nil {
			return fmt.Errorf("insert signing key: %w", err)
		}
		return nil
	})
}

// RetireSigningKey stops publishing a key, after which tokens it signed no
// longer verify. The current key cannot be retired; retiring a retired key is
// a no-op.
func (s *Store) RetireSigningKey(kid string) error {
	k, err := scanSigningKey(s.db.QueryRow(`SELECT `+signingKeyColumns+` FROM signing_keys WHERE kid = ?`, kid))
	if err != nil {
		return err
	}
	if k.IsCurrent {
		return fmt.Errorf("%w: the current signing key cannot be retired; rotate first", ErrInvalid)
	}
	if !k.RetiredAt.IsZero() {
		return nil
	}
	_, err = s.db.Exec(`UPDATE signing_keys SET retired_at = ? WHERE id = ? AND is_current = 0`, s.nowText(), k.ID)
	if err != nil {
		return fmt.Errorf("retire signing key: %w", err)
	}
	return nil
}
