package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Errors returned when a refresh token cannot be redeemed. They are separate
// values because the caller decides whether the client gets invalid_grant or
// the family is revoked (which happens here, in the store).
var (
	// ErrRefreshRevoked means the token was revoked, for example by signing out
	// or by an earlier replay.
	ErrRefreshRevoked = errors.New("refresh token revoked")
	// ErrRefreshReplayed means a token that had already been rotated was
	// presented again. The whole family has been revoked by the time this is
	// returned.
	ErrRefreshReplayed = errors.New("refresh token replayed")
	// ErrRefreshExpired means the token's lifetime has passed.
	ErrRefreshExpired = errors.New("refresh token expired")
)

// RefreshToken represents a refresh token and its family chain.
type RefreshToken struct {
	ID            int64
	TokenHash     string
	AppID         int64
	UserID        int64
	FamilyID      string
	Scope         string
	Resource      string
	AuthRequestID string
	AuthTime      time.Time
	AMR           string
	ACR           string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RotatedAt     time.Time
	RevokedAt     time.Time
	RevokedReason string
}

// RefreshTokenSpec is what a new refresh token needs. The expiry is computed
// from TTL against the store clock.
type RefreshTokenSpec struct {
	AppID         int64
	UserID        int64
	Scope         string
	Resource      string
	AuthRequestID string
	AuthTime      time.Time
	AMR           string
	ACR           string
	TTL           time.Duration
}

// CreateRefreshToken inserts a new refresh token with a fresh family ID.
func (s *Store) CreateRefreshToken(token string, spec RefreshTokenSpec) (*RefreshToken, error) {
	familyID, err := randomTokenID(16)
	if err != nil {
		return nil, fmt.Errorf("generate family ID: %w", err)
	}
	return s.createRefreshTokenWithFamily(token, familyID, spec)
}

// RotateRefreshToken redeems oldToken and issues newToken in the same family.
// The old row is marked rotated inside the same transaction that inserts the
// new one, so a crash cannot leave a token both live and recorded as used.
//
// Presenting an already-rotated token is a replay: the caller's family is
// revoked and ErrRefreshReplayed is returned.
func (s *Store) RotateRefreshToken(oldToken, newToken string, ttl time.Duration) (*RefreshToken, error) {
	oldHash := HashToken(oldToken)
	var created *RefreshToken
	var replayedFamily string
	err := s.inTx(func(tx *sql.Tx) error {
		var (
			old                  RefreshToken
			createdAt, expiresAt string
			rotatedAt, revokedAt string
			authTime             string
		)
		err := tx.QueryRow(`SELECT id, app_id, user_id, family_id, scope, resource,
			auth_request_id, auth_time, amr, acr, created_at, expires_at, rotated_at, revoked_at, revoked_reason
			FROM refresh_tokens WHERE token_hash = ?`, oldHash).Scan(
			&old.ID, &old.AppID, &old.UserID, &old.FamilyID, &old.Scope, &old.Resource,
			&old.AuthRequestID, &authTime, &old.AMR, &old.ACR,
			&createdAt, &expiresAt, &rotatedAt, &revokedAt, &old.RevokedReason,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		old.CreatedAt = parseTime(createdAt)
		old.ExpiresAt = parseTime(expiresAt)
		old.RotatedAt = parseTime(rotatedAt)
		old.RevokedAt = parseTime(revokedAt)
		old.AuthTime = parseTime(authTime)

		switch {
		case !old.RevokedAt.IsZero():
			return ErrRefreshRevoked
		case !old.RotatedAt.IsZero():
			// Replay: a token that was already exchanged came back. Everything
			// descended from it may be in the wrong hands.
			replayedFamily = old.FamilyID
			return ErrRefreshReplayed
		case !s.now().Before(old.ExpiresAt):
			return ErrRefreshExpired
		}

		res, err := tx.Exec(`UPDATE refresh_tokens SET rotated_at = ?
			WHERE id = ? AND rotated_at = '' AND revoked_at = ''`, s.nowText(), old.ID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			// Another request rotated it first; this one is the replay.
			replayedFamily = old.FamilyID
			return ErrRefreshReplayed
		}

		created, err = insertRefreshTokenTx(tx, newToken, old.FamilyID, RefreshTokenSpec{
			AppID:         old.AppID,
			UserID:        old.UserID,
			Scope:         old.Scope,
			Resource:      old.Resource,
			AuthRequestID: old.AuthRequestID,
			AuthTime:      old.AuthTime,
			AMR:           old.AMR,
			ACR:           old.ACR,
			TTL:           ttl,
		}, s.now())
		return err
	})
	if replayedFamily != "" {
		// Revoked outside the transaction above, which rolls back on the
		// replay error and would take the revocation with it.
		if rerr := s.RevokeRefreshTokenFamily(replayedFamily, "replay_detected"); rerr != nil {
			return nil, fmt.Errorf("revoke family after replay: %w", rerr)
		}
	}
	if err != nil {
		return nil, err
	}
	return created, nil
}

// RefreshTokenByToken retrieves a refresh token by its plaintext value.
func (s *Store) RefreshTokenByToken(token string) (*RefreshToken, error) {
	hash := HashToken(token)
	const q = `SELECT id, app_id, user_id, family_id, scope, resource,
		auth_request_id, auth_time, amr, acr, created_at, expires_at,
		rotated_at, revoked_at, revoked_reason
		FROM refresh_tokens WHERE token_hash = ?`
	rt := &RefreshToken{TokenHash: hash}
	var createdAt, expiresAt, rotatedAt, revokedAt, authTime string
	err := s.db.QueryRow(q, hash).Scan(
		&rt.ID, &rt.AppID, &rt.UserID, &rt.FamilyID, &rt.Scope, &rt.Resource,
		&rt.AuthRequestID, &authTime, &rt.AMR, &rt.ACR,
		&createdAt, &expiresAt, &rotatedAt, &revokedAt, &rt.RevokedReason,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rt.CreatedAt = parseTime(createdAt)
	rt.ExpiresAt = parseTime(expiresAt)
	rt.RotatedAt = parseTime(rotatedAt)
	rt.RevokedAt = parseTime(revokedAt)
	rt.AuthTime = parseTime(authTime)
	return rt, nil
}

// RefreshTokenByID retrieves a refresh token by its database ID.
func (s *Store) RefreshTokenByID(id int64) (*RefreshToken, error) {
	const q = `SELECT token_hash, app_id, user_id, family_id, scope, resource,
		auth_request_id, auth_time, amr, acr, created_at, expires_at,
		rotated_at, revoked_at, revoked_reason
		FROM refresh_tokens WHERE id = ?`
	rt := &RefreshToken{ID: id}
	var createdAt, expiresAt, rotatedAt, revokedAt, authTime string
	err := s.db.QueryRow(q, id).Scan(
		&rt.TokenHash, &rt.AppID, &rt.UserID, &rt.FamilyID, &rt.Scope, &rt.Resource,
		&rt.AuthRequestID, &authTime, &rt.AMR, &rt.ACR,
		&createdAt, &expiresAt, &rotatedAt, &revokedAt, &rt.RevokedReason,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rt.CreatedAt = parseTime(createdAt)
	rt.ExpiresAt = parseTime(expiresAt)
	rt.RotatedAt = parseTime(rotatedAt)
	rt.RevokedAt = parseTime(revokedAt)
	rt.AuthTime = parseTime(authTime)
	return rt, nil
}

// RevokeRefreshToken marks a single token as revoked.
func (s *Store) RevokeRefreshToken(tokenHash, reason string) error {
	const q = `UPDATE refresh_tokens SET revoked_at = ?, revoked_reason = ?
		WHERE token_hash = ? AND revoked_at = ''`
	_, err := s.db.Exec(q, s.nowText(), reason, tokenHash)
	return err
}

// RevokeRefreshTokenFamily revokes all live tokens in a family.
func (s *Store) RevokeRefreshTokenFamily(familyID, reason string) error {
	const q = `UPDATE refresh_tokens SET revoked_at = ?, revoked_reason = ?
		WHERE family_id = ? AND revoked_at = ''`
	_, err := s.db.Exec(q, s.nowText(), reason, familyID)
	return err
}

// RevokeRefreshTokensByAuthRequest revokes every token issued from one
// authorization request. It is the replay response for an authorization code.
func (s *Store) RevokeRefreshTokensByAuthRequest(authRequestID string) error {
	const q = `UPDATE refresh_tokens SET revoked_at = ?, revoked_reason = 'code_replayed'
		WHERE auth_request_id = ? AND revoked_at = ''`
	_, err := s.db.Exec(q, s.nowText(), authRequestID)
	return err
}

// RevokeUserRefreshTokens revokes all refresh tokens for a user.
func (s *Store) RevokeUserRefreshTokens(userID int64, reason string) error {
	const q = `UPDATE refresh_tokens SET revoked_at = ?, revoked_reason = ?
		WHERE user_id = ? AND revoked_at = ''`
	_, err := s.db.Exec(q, s.nowText(), reason, userID)
	return err
}

// RevokeAllRefreshTokens revokes all refresh tokens for a user+app pair
// (RP-initiated logout).
func (s *Store) RevokeAllRefreshTokens(userID, appID int64, reason string) error {
	const q = `UPDATE refresh_tokens SET revoked_at = ?, revoked_reason = ?
		WHERE user_id = ? AND app_id = ? AND revoked_at = ''`
	_, err := s.db.Exec(q, s.nowText(), reason, userID, appID)
	return err
}

// DeleteExpiredRefreshTokens removes tokens that can no longer be exchanged.
func (s *Store) DeleteExpiredRefreshTokens() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM refresh_tokens WHERE expires_at <= ?`, s.nowText())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// createRefreshTokenWithFamily is the shared insert path outside a transaction.
func (s *Store) createRefreshTokenWithFamily(token, familyID string, spec RefreshTokenSpec) (*RefreshToken, error) {
	var created *RefreshToken
	err := s.inTx(func(tx *sql.Tx) error {
		var err error
		created, err = insertRefreshTokenTx(tx, token, familyID, spec, s.now())
		return err
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func insertRefreshTokenTx(tx *sql.Tx, token, familyID string, spec RefreshTokenSpec, now time.Time) (*RefreshToken, error) {
	hash := HashToken(token)
	expiresAt := now.Add(spec.TTL)
	const q = `INSERT INTO refresh_tokens
		(token_hash, app_id, user_id, family_id, scope, resource, auth_request_id,
		 auth_time, amr, acr, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := tx.Exec(q, hash, spec.AppID, spec.UserID, familyID, spec.Scope, spec.Resource,
		spec.AuthRequestID, formatTime(spec.AuthTime), spec.AMR, spec.ACR,
		formatTime(now), formatTime(expiresAt))
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &RefreshToken{
		ID:            id,
		TokenHash:     hash,
		AppID:         spec.AppID,
		UserID:        spec.UserID,
		FamilyID:      familyID,
		Scope:         spec.Scope,
		Resource:      spec.Resource,
		AuthRequestID: spec.AuthRequestID,
		AuthTime:      spec.AuthTime,
		AMR:           spec.AMR,
		ACR:           spec.ACR,
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
	}, nil
}

// randomTokenID generates a URL-safe random ID for tokens.
func randomTokenID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
