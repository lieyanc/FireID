package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// User is a person. Status and SessionGen are the two fields that gate access:
// only an active user may sign in, and bumping SessionGen revokes everything
// already issued to them.
type User struct {
	ID            int64
	Username      string
	Email         string
	DisplayName   string
	Status        string
	IsSuperAdmin  bool
	PasswordHash  string
	SessionGen    int64
	TOTPSecretEnc string
	TOTPConfirmed bool
	// TOTPLastStep is the highest time step already accepted.
	TOTPLastStep int64
	Locale       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  time.Time
}

// User status values.
const (
	UserPending  = "pending"
	UserActive   = "active"
	UserDisabled = "disabled"
)

const userColumns = `id, username, email, display_name, status, is_super_admin, password_hash,
	session_gen, totp_secret_enc, totp_confirmed_at, totp_last_step, locale, created_at, updated_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var superAdmin int
	var totpConfirmed, createdAt, updatedAt, lastLogin string
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.Status, &superAdmin,
		&u.PasswordHash, &u.SessionGen, &u.TOTPSecretEnc, &totpConfirmed, &u.TOTPLastStep, &u.Locale,
		&createdAt, &updatedAt, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	u.IsSuperAdmin = superAdmin != 0
	u.TOTPConfirmed = totpConfirmed != ""
	u.CreatedAt = parseTime(createdAt)
	u.UpdatedAt = parseTime(updatedAt)
	u.LastLoginAt = parseTime(lastLogin)
	return &u, nil
}

// CountUsers reports how many accounts exist, which tells the setup flow
// whether it still needs to create the first super admin.
func (s *Store) CountUsers() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// HasSuperAdmin reports whether any account is a super admin.
func (s *Store) HasSuperAdmin() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_super_admin = 1`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("count super admins: %w", err)
	}
	return n > 0, nil
}

// UserByID looks a user up by primary key.
func (s *Store) UserByID(id int64) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// UserByUsername looks a user up by username, case-insensitively. Usernames are
// stored lower-case; callers pass whatever the person typed.
func (s *Store) UserByUsername(username string) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE username = ?`, NormaliseUsername(username))
	return scanUser(row)
}

// UserByEmail looks a user up by email, case-insensitively.
func (s *Store) UserByEmail(email string) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE email = ?`, NormaliseEmail(email))
	return scanUser(row)
}

// NewUser is the input to CreateUser.
type NewUser struct {
	Username     string
	Email        string
	DisplayName  string
	PasswordHash string
	Status       string
	IsSuperAdmin bool
}

// CreateUser inserts an account. The caller is responsible for hashing the
// password; an empty hash means the account can only be reached through a
// passkey or an emailed link until one is set.
func (s *Store) CreateUser(in NewUser) (*User, error) {
	username := NormaliseUsername(in.Username)
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	email := NormaliseEmail(in.Email)
	if err := ValidateEmail(email); err != nil {
		return nil, err
	}
	status := in.Status
	if status == "" {
		status = UserPending
	}
	now := s.nowText()
	superAdmin := 0
	if in.IsSuperAdmin {
		superAdmin = 1
	}
	res, err := s.db.Exec(`INSERT INTO users
		(username, email, display_name, status, is_super_admin, password_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		username, email, strings.TrimSpace(in.DisplayName), status, superAdmin, in.PasswordHash, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: username or email is already registered", ErrConflict)
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return s.UserByID(id)
}

// SetPassword stores a new password hash and revokes every existing session for
// the account, on the assumption that a password change means the old
// credentials may be in someone else's hands.
func (s *Store) SetPassword(userID int64, hash string) error {
	return s.inTx(func(tx *sql.Tx) error {
		now := s.nowText()
		if _, err := tx.Exec(`UPDATE users SET password_hash = ?, session_gen = session_gen + 1,
			updated_at = ? WHERE id = ?`, hash, now, userID); err != nil {
			return fmt.Errorf("set password: %w", err)
		}
		if err := s.revokeSessionsTx(tx, userID, now); err != nil {
			return err
		}
		return s.revokeRefreshTokensTx(tx, userID, "password changed", now)
	})
}

// ClearPassword removes the stored hash, which a passkey-only account can do.
func (s *Store) ClearPassword(userID int64) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = '', session_gen = session_gen + 1,
		updated_at = ? WHERE id = ?`, s.nowText(), userID)
	if err != nil {
		return fmt.Errorf("clear password: %w", err)
	}
	return nil
}

// SetStatus changes the account status. Disabling revokes every session and
// refresh token immediately.
func (s *Store) SetStatus(userID int64, status string) error {
	switch status {
	case UserPending, UserActive, UserDisabled:
	default:
		return fmt.Errorf("unknown user status %q", status)
	}
	return s.inTx(func(tx *sql.Tx) error {
		now := s.nowText()
		if _, err := tx.Exec(`UPDATE users SET status = ?, updated_at = ? WHERE id = ?`,
			status, now, userID); err != nil {
			return fmt.Errorf("set status: %w", err)
		}
		if status != UserActive {
			if err := s.revokeSessionsTx(tx, userID, now); err != nil {
				return err
			}
			return s.revokeRefreshTokensTx(tx, userID, "account "+status, now)
		}
		return nil
	})
}

// ActivateUser marks the account active, which is what email verification does.
func (s *Store) ActivateUser(userID int64) error {
	_, err := s.db.Exec(`UPDATE users SET status = ?, updated_at = ?
		WHERE id = ? AND status = ?`, UserActive, s.nowText(), userID, UserPending)
	if err != nil {
		return fmt.Errorf("activate user: %w", err)
	}
	return nil
}

// TouchLogin records a successful sign-in.
func (s *Store) TouchLogin(userID int64) error {
	_, err := s.db.Exec(`UPDATE users SET last_login_at = ? WHERE id = ?`, s.nowText(), userID)
	if err != nil {
		return fmt.Errorf("touch login: %w", err)
	}
	return nil
}

// BumpSessionGen revokes every session and token issued for the account without
// changing the password. Used by "sign out everywhere".
func (s *Store) BumpSessionGen(userID int64) error {
	return s.inTx(func(tx *sql.Tx) error {
		now := s.nowText()
		if _, err := tx.Exec(`UPDATE users SET session_gen = session_gen + 1, updated_at = ?
			WHERE id = ?`, now, userID); err != nil {
			return fmt.Errorf("bump session generation: %w", err)
		}
		if err := s.revokeSessionsTx(tx, userID, now); err != nil {
			return err
		}
		return s.revokeRefreshTokensTx(tx, userID, "sessions revoked", now)
	})
}

// ListUsers returns accounts ordered by creation, newest first. limit ≤ 0 means
// no limit.
func (s *Store) ListUsers(limit, offset int) ([]*User, error) {
	q := `SELECT ` + userColumns + ` FROM users ORDER BY id DESC`
	args := []any{}
	if limit > 0 {
		q += ` LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// NormaliseUsername lower-cases and trims a username.
func NormaliseUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// NormaliseEmail lower-cases and trims an email address.
func NormaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
