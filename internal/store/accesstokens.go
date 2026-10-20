package store

import (
	"database/sql"
	"errors"
	"time"
)

// AccessToken is the server-side record behind an opaque access token. The
// token itself is an encrypted "id:subject" value; this row is what makes
// expiry, scope and revocation knowable without trusting the ciphertext alone.
type AccessToken struct {
	TokenID       string
	AppID         int64
	UserID        int64
	Scope         string
	AuthRequestID string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     time.Time
}

// CreateAccessToken records a freshly minted access token and returns its
// expiry. The caller has already generated the token ID.
func (s *Store) CreateAccessToken(tokenID string, appID, userID int64, scope, authRequestID string, ttl time.Duration) (time.Time, error) {
	now := s.now()
	expiresAt := now.Add(ttl)
	const q = `INSERT INTO access_tokens
		(token_id, app_id, user_id, scope, auth_request_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(q, tokenID, appID, userID, scope, authRequestID, formatTime(now), formatTime(expiresAt))
	if err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

// AccessTokenByID returns a live access token, or ErrNotFound when it is
// unknown, expired or revoked. Callers treat all three as "not active".
func (s *Store) AccessTokenByID(tokenID string) (*AccessToken, error) {
	const q = `SELECT app_id, user_id, scope, auth_request_id, created_at, expires_at, revoked_at
		FROM access_tokens WHERE token_id = ?`
	var (
		at                   AccessToken
		createdAt, expiresAt string
		revokedAt            string
	)
	err := s.db.QueryRow(q, tokenID).Scan(
		&at.AppID, &at.UserID, &at.Scope, &at.AuthRequestID, &createdAt, &expiresAt, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	at.TokenID = tokenID
	at.CreatedAt = parseTime(createdAt)
	at.ExpiresAt = parseTime(expiresAt)
	at.RevokedAt = parseTime(revokedAt)
	if !at.RevokedAt.IsZero() {
		return nil, ErrNotFound
	}
	if !at.ExpiresAt.IsZero() && !s.now().Before(at.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &at, nil
}

// RevokeAccessToken marks one access token revoked.
func (s *Store) RevokeAccessToken(tokenID string) error {
	const q = `UPDATE access_tokens SET revoked_at = ? WHERE token_id = ? AND revoked_at = ''`
	_, err := s.db.Exec(q, s.nowText(), tokenID)
	return err
}

// RevokeAccessTokensByAuthRequest revokes everything issued from one
// authorization request, used when the code is replayed.
func (s *Store) RevokeAccessTokensByAuthRequest(authRequestID string) error {
	const q = `UPDATE access_tokens SET revoked_at = ?
		WHERE auth_request_id = ? AND revoked_at = ''`
	_, err := s.db.Exec(q, s.nowText(), authRequestID)
	return err
}

// RevokeAccessTokensForUserApp revokes the access tokens a user holds for one
// app, used on RP-initiated logout.
func (s *Store) RevokeAccessTokensForUserApp(userID, appID int64) error {
	const q = `UPDATE access_tokens SET revoked_at = ?
		WHERE user_id = ? AND app_id = ? AND revoked_at = ''`
	_, err := s.db.Exec(q, s.nowText(), userID, appID)
	return err
}

// DeleteExpiredAccessTokens removes rows past their lifetime. Revoked rows are
// kept until they expire so introspection can still say they are inactive.
func (s *Store) DeleteExpiredAccessTokens() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM access_tokens WHERE expires_at <= ?`, s.nowText())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
