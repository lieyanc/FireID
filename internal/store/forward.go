package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ForwardCodeTTL bounds the hop from the IdP back to the app's host.
const ForwardCodeTTL = time.Minute

// ForwardCode is a redeemed forward-auth code.
type ForwardCode struct {
	AppID     int64
	SessionID int64
	StateHash string
	Origin    string
	ReturnURL string
}

// CreateForwardCode stores a one-time code for the IdP session sessionID,
// redeemable only on origin, only for appID, and only by the browser holding
// the state cookie whose hash is stateHash.
func (s *Store) CreateForwardCode(code string, appID, sessionID int64, stateHash, origin, returnURL string) error {
	now := s.now()
	_, err := s.db.Exec(`INSERT INTO forward_codes
		(code_hash, app_id, session_id, state_hash, origin, return_url, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		HashToken(code), appID, sessionID, stateHash, origin, returnURL,
		formatTime(now), formatTime(now.Add(ForwardCodeTTL)))
	if err != nil {
		return fmt.Errorf("insert forward code: %w", err)
	}
	return nil
}

// ConsumeForwardCode redeems a code for appID once. An unknown, expired,
// spent or foreign code is ErrNotFound.
func (s *Store) ConsumeForwardCode(code string, appID int64) (*ForwardCode, error) {
	var fc ForwardCode
	err := s.inTx(func(tx *sql.Tx) error {
		now := s.nowText()
		res, err := tx.Exec(`UPDATE forward_codes SET used_at = ?
			WHERE code_hash = ? AND app_id = ? AND used_at = '' AND expires_at > ?`,
			now, HashToken(code), appID, now)
		if err != nil {
			return fmt.Errorf("consume forward code: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return tx.QueryRow(`SELECT app_id, session_id, state_hash, origin, return_url
			FROM forward_codes WHERE code_hash = ?`, HashToken(code)).
			Scan(&fc.AppID, &fc.SessionID, &fc.StateHash, &fc.Origin, &fc.ReturnURL)
	})
	if err != nil {
		return nil, err
	}
	return &fc, nil
}

// ForwardSession is an app-scoped session derived from an IdP session.
type ForwardSession struct {
	ID        int64
	AppID     int64
	SessionID int64
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// liveParent is the condition under which an IdP session may back a forward
// session: not revoked, not expired, and its account still active.
const liveParent = `s.revoked_at = '' AND s.expires_at > ? AND u.status = '` + UserActive + `'`

// CreateForwardSession issues the app's session for a live IdP session. It
// expires with its parent and dies when the parent is revoked.
func (s *Store) CreateForwardSession(token string, appID, sessionID int64) (*ForwardSession, error) {
	now := s.now()
	var expiresAt string
	var userID int64
	err := s.db.QueryRow(`SELECT s.expires_at, s.user_id FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = ? AND `+liveParent, sessionID, formatTime(now)).Scan(&expiresAt, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load parent session: %w", err)
	}
	res, err := s.db.Exec(`INSERT INTO forward_sessions(token_hash, app_id, session_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`, HashToken(token), appID, sessionID, formatTime(now), expiresAt)
	if err != nil {
		return nil, fmt.Errorf("insert forward session: %w", err)
	}
	id, _ := res.LastInsertId()
	return &ForwardSession{ID: id, AppID: appID, SessionID: sessionID, UserID: userID,
		CreatedAt: now, ExpiresAt: parseTime(expiresAt)}, nil
}

// ForwardSessionUser resolves an app's session cookie. It is ErrNotFound
// unless the session belongs to appID and its IdP session is still live.
func (s *Store) ForwardSessionUser(token string, appID int64) (*ForwardSession, *User, error) {
	if token == "" {
		return nil, nil, ErrNotFound
	}
	var fs ForwardSession
	var createdAt, expiresAt string
	err := s.db.QueryRow(`SELECT f.id, f.app_id, f.session_id, s.user_id, f.created_at, f.expires_at
		FROM forward_sessions f
		JOIN sessions s ON s.id = f.session_id
		JOIN users u ON u.id = s.user_id
		WHERE f.token_hash = ? AND f.app_id = ? AND f.expires_at > ? AND `+liveParent,
		HashToken(token), appID, s.nowText(), s.nowText()).
		Scan(&fs.ID, &fs.AppID, &fs.SessionID, &fs.UserID, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("look up forward session: %w", err)
	}
	fs.CreatedAt, fs.ExpiresAt = parseTime(createdAt), parseTime(expiresAt)
	user, err := s.UserByID(fs.UserID)
	if err != nil {
		return nil, nil, err
	}
	return &fs, user, nil
}

// DeleteForwardSession ends one app session (sign-out on the app's host).
func (s *Store) DeleteForwardSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM forward_sessions WHERE token_hash = ?`, HashToken(token))
	if err != nil {
		return fmt.Errorf("delete forward session: %w", err)
	}
	return nil
}

// DeleteExpiredForward removes spent codes and finished app sessions.
func (s *Store) DeleteExpiredForward() (int64, error) {
	now := s.nowText()
	var total int64
	for _, q := range []string{
		`DELETE FROM forward_codes WHERE expires_at < ?`,
		`DELETE FROM forward_sessions WHERE expires_at < ?
			OR session_id IN (SELECT id FROM sessions WHERE revoked_at <> '')`,
	} {
		res, err := s.db.Exec(q, now)
		if err != nil {
			return total, fmt.Errorf("delete expired forward rows: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// UserGroupNames returns the names of the groups a user belongs to, sorted.
func (s *Store) UserGroupNames(userID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT g.name FROM group_members gm JOIN groups g ON g.id = gm.group_id
		WHERE gm.user_id = ? ORDER BY g.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("user groups: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		// Names from before the comma rule are left out rather than split.
		if groupNameOK(name) {
			out = append(out, name)
		}
	}
	return out, rows.Err()
}

// groupNameOK keeps group names safe to join into the comma-separated
// X-FireID-Groups header.
func groupNameOK(name string) bool {
	return !strings.ContainsAny(name, ",\r\n\t\x00") && !strings.ContainsFunc(name, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	})
}
