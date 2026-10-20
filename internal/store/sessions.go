package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Session is a signed-in browser session. The opaque token is never stored: the
// row holds only its SHA-256, so a database leak does not hand over live
// sessions.
type Session struct {
	ID         int64
	UserID     int64
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	IP         string
	UserAgent  string
	// AMR lists the authentication methods used, strongest last: for example
	// "pwd otp" or "webauthn".
	AMR string
	ACR string
	// SessionGen is the account's generation at creation time. A session whose
	// generation no longer matches the account is rejected, which is how a
	// password change signs everyone out.
	SessionGen int64
	RevokedAt  time.Time
}

// NewSessionToken returns a fresh opaque session token and its hash.
func NewSessionToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken returns the stored form of an opaque value. Everything that is
// compared or looked up server-side is hashed this way.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyTokenHash checks whether the given plaintext token matches the stored hash
// in constant time.
func VerifyTokenHash(token, hash string) bool {
	computed := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}

// CreateSession records a new session and returns it with the token to hand to
// the browser.
func (s *Store) CreateSession(userID int64, ttl time.Duration, ip, userAgent, amr, acr string) (token string, sess *Session, err error) {
	token, hash, err := NewSessionToken()
	if err != nil {
		return "", nil, err
	}

	user, err := s.UserByID(userID)
	if err != nil {
		return "", nil, err
	}

	now := s.now()
	res, err := s.db.Exec(`INSERT INTO sessions
		(user_id, token_hash, created_at, expires_at, last_seen_at, ip, user_agent, amr, acr)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, hash, formatTime(now), formatTime(now.Add(ttl)), formatTime(now),
		normaliseIP(ip), truncate(userAgent, 400), amr, acr)
	if err != nil {
		return "", nil, fmt.Errorf("insert session: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return "", nil, fmt.Errorf("insert session: %w", err)
	}
	return token, &Session{
		ID: id, UserID: userID, CreatedAt: now, ExpiresAt: now.Add(ttl), LastSeenAt: now,
		IP: normaliseIP(ip), UserAgent: userAgent, AMR: amr, ACR: acr, SessionGen: user.SessionGen,
	}, nil
}

// SessionUser resolves a session token to its session and the current account,
// rejecting expired, revoked, and generation-stale sessions. It also refreshes
// last_seen_at, at most once a minute to keep writes rare.
func (s *Store) SessionUser(token string) (*Session, *User, error) {
	if token == "" {
		return nil, nil, ErrNotFound
	}
	hash := HashToken(token)
	var (
		sess       Session
		userGen    int64
		createdAt  string
		expiresAt  string
		lastSeenAt string
		revokedAt  string
	)
	row := s.db.QueryRow(`SELECT s.id, s.user_id, s.created_at, s.expires_at, s.last_seen_at,
			s.ip, s.user_agent, s.amr, s.acr, s.revoked_at, u.session_gen
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ?`, hash)
	err := row.Scan(&sess.ID, &sess.UserID, &createdAt, &expiresAt, &lastSeenAt,
		&sess.IP, &sess.UserAgent, &sess.AMR, &sess.ACR, &revokedAt, &userGen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("look up session: %w", err)
	}

	sess.CreatedAt = parseTime(createdAt)
	sess.ExpiresAt = parseTime(expiresAt)
	sess.LastSeenAt = parseTime(lastSeenAt)
	sess.RevokedAt = parseTime(revokedAt)
	sess.SessionGen = userGen

	now := s.now()
	if !sess.RevokedAt.IsZero() || now.After(sess.ExpiresAt) {
		return nil, nil, ErrNotFound
	}

	user, err := s.UserByID(sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	// A generation mismatch means the password changed or sessions were revoked
	// after this session was issued.
	if user.SessionGen != userGen || user.Status != UserActive {
		return nil, nil, ErrNotFound
	}

	if now.Sub(sess.LastSeenAt) > time.Minute {
		if _, err := s.db.Exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`,
			formatTime(now), sess.ID); err != nil {
			return nil, nil, fmt.Errorf("touch session: %w", err)
		}
		sess.LastSeenAt = now
	}
	return &sess, user, nil
}

// RevokeSession marks one session revoked. It is idempotent.
func (s *Store) RevokeSession(sessionID int64) error {
	_, err := s.db.Exec(`UPDATE sessions SET revoked_at = ?
		WHERE id = ? AND revoked_at = ''`, s.nowText(), sessionID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeSessionByToken revokes the session a token refers to, for sign-out.
func (s *Store) RevokeSessionByToken(token string) error {
	if token == "" {
		return nil
	}
	_, err := s.db.Exec(`UPDATE sessions SET revoked_at = ?
		WHERE token_hash = ? AND revoked_at = ''`, s.nowText(), HashToken(token))
	if err != nil {
		return fmt.Errorf("revoke session by token: %w", err)
	}
	return nil
}

// RevokeAllSessions revokes every session of an account. It does not bump the
// generation, which callers that also want to invalidate refresh tokens should
// do separately.
func (s *Store) RevokeAllSessions(userID int64) error {
	return s.revokeSessionsTx(nil, userID, s.nowText())
}

// SessionInfo is a row in the account's "active sessions" list.
type SessionInfo struct {
	ID         int64
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IP         string
	UserAgent  string
	AMR        string
	Current    bool
}

// ListSessions returns the account's live sessions, newest activity first.
func (s *Store) ListSessions(userID, currentID int64) ([]SessionInfo, error) {
	rows, err := s.db.Query(`SELECT id, created_at, last_seen_at, expires_at, ip, user_agent, amr
		FROM sessions
		WHERE user_id = ? AND revoked_at = '' AND expires_at > ?
		ORDER BY last_seen_at DESC`, userID, s.nowText())
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var out []SessionInfo
	for rows.Next() {
		var (
			info                         SessionInfo
			createdAt, lastSeen, expires string
		)
		if err := rows.Scan(&info.ID, &createdAt, &lastSeen, &expires, &info.IP, &info.UserAgent, &info.AMR); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		info.CreatedAt = parseTime(createdAt)
		info.LastSeenAt = parseTime(lastSeen)
		info.ExpiresAt = parseTime(expires)
		info.Current = info.ID == currentID
		out = append(out, info)
	}
	return out, rows.Err()
}

// DeleteExpiredSessions removes finished rows. It runs periodically so the
// table does not grow without bound.
func (s *Store) DeleteExpiredSessions() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions
		WHERE expires_at < ? OR (revoked_at <> '' AND revoked_at < ?)`,
		s.nowText(), formatTime(s.now().Add(-24*time.Hour)))
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return res.RowsAffected()
}

// revokeSessionsTx revokes all sessions of a user inside an existing
// transaction, or standalone when tx is nil.
func (s *Store) revokeSessionsTx(tx *sql.Tx, userID int64, now string) error {
	const q = `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at = ''`
	var err error
	if tx != nil {
		_, err = tx.Exec(q, now, userID)
	} else {
		_, err = s.db.Exec(q, now, userID)
	}
	if err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}

// revokeRefreshTokensTx revokes all refresh and access tokens of a user, so a
// password change or a disabled account takes effect at the resource servers
// too, not only in the browser.
func (s *Store) revokeRefreshTokensTx(tx *sql.Tx, userID int64, reason, now string) error {
	const q = `UPDATE refresh_tokens SET revoked_at = ?, revoked_reason = ?
		WHERE user_id = ? AND revoked_at = ''`
	const qa = `UPDATE access_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at = ''`
	exec := s.db.Exec
	if tx != nil {
		exec = tx.Exec
	}
	if _, err := exec(q, now, reason, userID); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	if _, err := exec(qa, now, userID); err != nil {
		return fmt.Errorf("revoke access tokens: %w", err)
	}
	return nil
}

// normaliseIP keeps only a canonical address, dropping ports and anything
// unparsable so the audit log cannot be poisoned with arbitrary text.
func normaliseIP(raw string) string {
	if raw == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr.Unmap().String()
	}
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		return ap.Addr().Unmap().String()
	}
	return ""
}

// truncate caps a string at n runes, so a hostile user agent cannot bloat rows.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
