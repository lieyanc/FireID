package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// AuthRequestTTL bounds how long an authorization request stays pending. A
// request is created by the authorize endpoint and approved by the login page;
// anything older than this is a stale tab or an abandoned flow.
const AuthRequestTTL = 15 * time.Minute

// AuthRequest is the server-side record of an OAuth authorization request.
type AuthRequest struct {
	ID                  string
	AppID               int64
	UserID              sql.NullInt64 // NULL until user approves
	RedirectURI         string
	Scope               string
	Nonce               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	AuthTime            time.Time
	AMR                 string
	ACR                 string
	SID                 string
	// Prompt is the space-separated prompt parameter.
	Prompt string
	// MaxAge is the max_age parameter in seconds, or -1 when the client did
	// not send one.
	MaxAge int64
	// ACRValues is the space-separated acr_values parameter.
	ACRValues string
	ExpiresAt time.Time
}

// CreateAuthRequest inserts a new authorization request. The caller supplies
// the ID; a zero ExpiresAt is filled in from AuthRequestTTL.
func (s *Store) CreateAuthRequest(ar *AuthRequest) error {
	if ar.ID == "" {
		id, err := randomID(32)
		if err != nil {
			return fmt.Errorf("generate auth request ID: %w", err)
		}
		ar.ID = id
	}
	now := s.now()
	if ar.ExpiresAt.IsZero() {
		ar.ExpiresAt = now.Add(AuthRequestTTL)
	}
	const q = `INSERT INTO auth_requests
		(id, app_id, user_id, redirect_uri, scope, nonce, state,
		 code_challenge, code_challenge_method, resource, auth_time, amr, acr, sid,
		 prompt, max_age, acr_values, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(q,
		ar.ID, ar.AppID, ar.UserID, ar.RedirectURI, ar.Scope, ar.Nonce, ar.State,
		ar.CodeChallenge, ar.CodeChallengeMethod, ar.Resource,
		formatTime(ar.AuthTime), ar.AMR, ar.ACR, ar.SID,
		ar.Prompt, ar.MaxAge, ar.ACRValues,
		formatTime(ar.ExpiresAt),
	)
	return err
}

// AuthRequestByID retrieves a pending authorization request. Expired requests
// are reported as missing, so every caller behaves the same way.
func (s *Store) AuthRequestByID(id string) (*AuthRequest, error) {
	const q = `SELECT app_id, user_id, redirect_uri, scope, nonce, state,
		code_challenge, code_challenge_method, resource, auth_time, amr, acr, sid,
		prompt, max_age, acr_values, expires_at
		FROM auth_requests WHERE id = ?`
	ar := &AuthRequest{ID: id}
	var authTime, expiresAt string
	err := s.db.QueryRow(q, id).Scan(
		&ar.AppID, &ar.UserID, &ar.RedirectURI, &ar.Scope, &ar.Nonce, &ar.State,
		&ar.CodeChallenge, &ar.CodeChallengeMethod, &ar.Resource,
		&authTime, &ar.AMR, &ar.ACR, &ar.SID,
		&ar.Prompt, &ar.MaxAge, &ar.ACRValues, &expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ar.AuthTime = parseTime(authTime)
	ar.ExpiresAt = parseTime(expiresAt)
	if !ar.ExpiresAt.IsZero() && !s.now().Before(ar.ExpiresAt) {
		return nil, ErrNotFound
	}
	return ar, nil
}

// ApproveAuthRequest records that the user signed in and permitted the request.
// The update only applies to a request that still exists and has not expired;
// a stale request reports ErrNotFound rather than being resurrected.
func (s *Store) ApproveAuthRequest(id string, userID int64, authTime time.Time, amr, acr, sid string) error {
	const q = `UPDATE auth_requests
		SET user_id = ?, auth_time = ?, amr = ?, acr = ?, sid = ?
		WHERE id = ? AND expires_at > ?`
	res, err := s.db.Exec(q, userID, formatTime(authTime), amr, acr, sid, id, s.nowText())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAuthRequest removes an authorization request by ID.
func (s *Store) DeleteAuthRequest(id string) error {
	const q = `DELETE FROM auth_requests WHERE id = ?`
	_, err := s.db.Exec(q, id)
	return err
}

// AuthCode is a consumed or unconsumed authorization code.
type AuthCode struct {
	CodeHash            string
	AuthRequestID       string
	AppID               int64
	UserID              int64
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	AuthTime            time.Time
	AMR                 string
	ACR                 string
	SID                 string
	ExpiresAt           time.Time
	ConsumedAt          time.Time
}

// SaveAuthCode issues a code for an approved request. Only an approved,
// unexpired request can produce a code, and the row copies every field the
// token endpoint will need after the request itself is deleted.
func (s *Store) SaveAuthCode(authRequestID, code string, ttl time.Duration) error {
	return s.inTx(func(tx *sql.Tx) error {
		var (
			ar                  AuthRequest
			userID              sql.NullInt64
			authTime, expiresAt string
		)
		err := tx.QueryRow(`SELECT app_id, user_id, redirect_uri, scope, nonce,
			code_challenge, code_challenge_method, resource, auth_time, amr, acr, sid, expires_at
			FROM auth_requests WHERE id = ?`, authRequestID).Scan(
			&ar.AppID, &userID, &ar.RedirectURI, &ar.Scope, &ar.Nonce,
			&ar.CodeChallenge, &ar.CodeChallengeMethod, &ar.Resource,
			&authTime, &ar.AMR, &ar.ACR, &ar.SID, &expiresAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !userID.Valid || userID.Int64 == 0 {
			return fmt.Errorf("cannot issue a code for an unapproved request")
		}
		ar.AuthTime = parseTime(authTime)
		if exp := parseTime(expiresAt); !exp.IsZero() && !s.now().Before(exp) {
			return ErrNotFound
		}
		// One request yields one code. Reloading the callback must not mint a
		// second, independently redeemable code for the same approval.
		var issued int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM auth_codes WHERE auth_request_id = ?`,
			authRequestID).Scan(&issued); err != nil {
			return err
		}
		if issued > 0 {
			return ErrConsumed
		}

		const q = `INSERT INTO auth_codes
			(code_hash, auth_request_id, app_id, user_id, redirect_uri, scope, nonce,
			 code_challenge, code_challenge_method, resource, auth_time, amr, acr, sid, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err = tx.Exec(q,
			HashToken(code), authRequestID, ar.AppID, userID.Int64, ar.RedirectURI, ar.Scope, ar.Nonce,
			ar.CodeChallenge, ar.CodeChallengeMethod, ar.Resource,
			formatTime(ar.AuthTime), ar.AMR, ar.ACR, ar.SID,
			formatTime(s.now().Add(ttl)),
		)
		return err
	})
}

// ConsumeAuthCode redeems a code exactly once and returns the request it was
// issued from. The code is marked consumed before the caller finishes
// validating the exchange, so a failure (wrong verifier, wrong client) cannot
// be retried; a second redemption of the same code is treated as a replay and
// revokes every token that was minted from it.
func (s *Store) ConsumeAuthCode(code string) (*AuthCode, error) {
	hash := HashToken(code)
	var ac AuthCode
	var replay bool
	err := s.inTx(func(tx *sql.Tx) error {
		var authTime, expiresAt, consumedAt string
		err := tx.QueryRow(`SELECT auth_request_id, app_id, user_id, redirect_uri, scope, nonce,
			code_challenge, code_challenge_method, resource, auth_time, amr, acr, sid,
			expires_at, consumed_at
			FROM auth_codes WHERE code_hash = ?`, hash).Scan(
			&ac.AuthRequestID, &ac.AppID, &ac.UserID, &ac.RedirectURI, &ac.Scope, &ac.Nonce,
			&ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.Resource,
			&authTime, &ac.AMR, &ac.ACR, &ac.SID, &expiresAt, &consumedAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ac.CodeHash = hash
		ac.AuthTime = parseTime(authTime)
		ac.ExpiresAt = parseTime(expiresAt)
		ac.ConsumedAt = parseTime(consumedAt)

		if !ac.ConsumedAt.IsZero() {
			replay = true
			return ErrConsumed
		}
		if !ac.ExpiresAt.IsZero() && !s.now().Before(ac.ExpiresAt) {
			return ErrNotFound
		}

		res, err := tx.Exec(`UPDATE auth_codes SET consumed_at = ? WHERE code_hash = ? AND consumed_at = ''`,
			s.nowText(), hash)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			// Another request won the race; this one is the replay.
			replay = true
			return ErrConsumed
		}
		return nil
	})
	if errors.Is(err, ErrConsumed) && replay && ac.AuthRequestID != "" {
		// A code must not be redeemable twice. Everything issued from it is
		// assumed compromised, which is what RFC 9700 section 4.1.2 asks for.
		// The revocation is best-effort: the caller is told the grant is invalid
		// either way.
		_ = s.RevokeRefreshTokensByAuthRequest(ac.AuthRequestID)
		_ = s.RevokeAccessTokensByAuthRequest(ac.AuthRequestID)
	}
	if err != nil {
		return nil, err
	}
	return &ac, nil
}

// DeleteExpiredAuthRequests removes pending requests that were never approved.
func (s *Store) DeleteExpiredAuthRequests() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM auth_requests WHERE expires_at <= ?`, s.nowText())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteExpiredAuthCodes removes codes past their lifetime, consumed or not.
func (s *Store) DeleteExpiredAuthCodes() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM auth_codes WHERE expires_at <= ?`, s.nowText())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// randomID generates a URL-safe base64 ID of the given byte length.
func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
