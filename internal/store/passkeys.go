package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PasskeyNameMaxLen bounds the label a person gives a passkey.
const PasskeyNameMaxLen = 64

// Passkey is a registered WebAuthn credential.
type Passkey struct {
	ID           int64
	UserID       int64
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	// Transports is the space-separated list the browser reported, e.g.
	// "internal hybrid".
	Transports        string
	AAGUID            []byte
	Name              string
	BackupEligible    bool
	BackupState       bool
	UserVerified      bool
	AttestationType   string
	AttestationFormat string
	CreatedAt         time.Time
	LastUsedAt        time.Time
}

const passkeyColumns = `id, user_id, credential_id, public_key, sign_count, transports, aaguid, name,
	backup_eligible, backup_state, user_verified, attestation_type, attestation_format, created_at, last_used_at`

func scanPasskey(row interface{ Scan(...any) error }) (*Passkey, error) {
	var (
		p                   Passkey
		aaguid              string
		be, bs, uv          int
		createdAt, lastUsed string
	)
	err := row.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.PublicKey, &p.SignCount, &p.Transports,
		&aaguid, &p.Name, &be, &bs, &uv, &p.AttestationType, &p.AttestationFormat, &createdAt, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan passkey: %w", err)
	}
	p.AAGUID, _ = base64.RawURLEncoding.DecodeString(aaguid)
	p.BackupEligible, p.BackupState, p.UserVerified = be != 0, bs != 0, uv != 0
	p.CreatedAt = parseTime(createdAt)
	p.LastUsedAt = parseTime(lastUsed)
	return &p, nil
}

// ValidatePasskeyName bounds the label of a passkey. An empty name is allowed;
// the UI shows a default.
func ValidatePasskeyName(name string) error {
	if len([]rune(name)) > PasskeyNameMaxLen {
		return fmt.Errorf("%w: passkey name must be at most %d characters", ErrInvalid, PasskeyNameMaxLen)
	}
	return nil
}

// EnsureWebAuthnID returns the account's passkey user handle, creating it on
// first use. The handle is random, so a passkey on a shared device says
// nothing about the account beyond what its name and display name show.
func (s *Store) EnsureWebAuthnID(userID int64) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate user handle: %w", err)
	}
	if _, err := s.db.Exec(`UPDATE users SET webauthn_id = ? WHERE id = ? AND webauthn_id = ''`,
		base64.RawURLEncoding.EncodeToString(raw), userID); err != nil {
		return "", fmt.Errorf("set user handle: %w", err)
	}
	var id string
	err := s.db.QueryRow(`SELECT webauthn_id FROM users WHERE id = ?`, userID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read user handle: %w", err)
	}
	return id, nil
}

// UserByWebAuthnID resolves a passkey user handle to its account.
func (s *Store) UserByWebAuthnID(handle string) (*User, error) {
	if handle == "" {
		return nil, ErrNotFound
	}
	return scanUser(s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE webauthn_id = ?`, handle))
}

// CreatePasskey stores a newly registered credential. ErrConflict means the
// credential is already registered, to this account or another.
func (s *Store) CreatePasskey(p *Passkey) (*Passkey, error) {
	name := strings.TrimSpace(p.Name)
	if err := ValidatePasskeyName(name); err != nil {
		return nil, err
	}
	res, err := s.db.Exec(`INSERT INTO webauthn_credentials
		(user_id, credential_id, public_key, sign_count, transports, aaguid, name,
		 backup_eligible, backup_state, user_verified, attestation_type, attestation_format, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.UserID, p.CredentialID, p.PublicKey, p.SignCount, p.Transports,
		base64.RawURLEncoding.EncodeToString(p.AAGUID), name,
		boolInt(p.BackupEligible), boolInt(p.BackupState), boolInt(p.UserVerified),
		p.AttestationType, p.AttestationFormat, s.nowText())
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: this passkey is already registered", ErrConflict)
		}
		return nil, fmt.Errorf("insert passkey: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("insert passkey: %w", err)
	}
	return s.passkey(id)
}

func (s *Store) passkey(id int64) (*Passkey, error) {
	return scanPasskey(s.db.QueryRow(`SELECT `+passkeyColumns+` FROM webauthn_credentials WHERE id = ?`, id))
}

// ListPasskeys returns the account's passkeys, oldest first.
func (s *Store) ListPasskeys(userID int64) ([]*Passkey, error) {
	rows, err := s.db.Query(`SELECT `+passkeyColumns+` FROM webauthn_credentials
		WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	defer rows.Close()
	var out []*Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountPasskeys reports how many passkeys the account has.
func (s *Store) CountPasskeys(userID int64) (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`,
		userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count passkeys: %w", err)
	}
	return n, nil
}

// RecordPasskeyUse stores what a successful assertion reported. The update is
// conditional on the counter the check was made against, so two assertions
// racing with the same counter cannot both pass: the loser gets ErrConsumed.
func (s *Store) RecordPasskeyUse(id int64, prevCount, signCount uint32, backupState, userVerified bool) error {
	res, err := s.db.Exec(`UPDATE webauthn_credentials
		SET sign_count = ?, backup_state = ?, user_verified = MAX(user_verified, ?), last_used_at = ?
		WHERE id = ? AND sign_count = ?`,
		signCount, boolInt(backupState), boolInt(userVerified), s.nowText(), id, prevCount)
	if err != nil {
		return fmt.Errorf("record passkey use: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConsumed
	}
	return nil
}

// RenamePasskey changes the label of one of the account's passkeys.
func (s *Store) RenamePasskey(userID, id int64, name string) error {
	name = strings.TrimSpace(name)
	if err := ValidatePasskeyName(name); err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?`,
		name, id, userID)
	if err != nil {
		return fmt.Errorf("rename passkey: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ErrLastCredential is returned when removing a passkey would leave the account
// with no way to sign in except an emailed link.
var ErrLastCredential = errors.New("this is the account's last way to sign in")

// DeletePasskey removes one of the account's passkeys. The last credential —
// no password and no other passkey left — may only go when allowLast is set,
// which is the caller saying another recovery path exists (email sign-in, or
// an administrator reset).
func (s *Store) DeletePasskey(userID, id int64, allowLast bool) error {
	return s.inTx(func(tx *sql.Tx) error {
		var owner int64
		err := tx.QueryRow(`SELECT user_id FROM webauthn_credentials WHERE id = ?`, id).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && owner != userID) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("look up passkey: %w", err)
		}
		if !allowLast {
			var others int
			var hash string
			if err := tx.QueryRow(`SELECT
					(SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ? AND id <> ?),
					password_hash FROM users WHERE id = ?`, userID, id, userID).Scan(&others, &hash); err != nil {
				return fmt.Errorf("count credentials: %w", err)
			}
			if others == 0 && hash == "" {
				return ErrLastCredential
			}
		}
		if _, err := tx.Exec(`DELETE FROM webauthn_credentials WHERE id = ?`, id); err != nil {
			return fmt.Errorf("delete passkey: %w", err)
		}
		return nil
	})
}

// RevokeUserSession revokes one of the account's sessions. ErrNotFound means
// the session does not exist, belongs to someone else, or has already ended,
// which the caller cannot tell apart.
func (s *Store) RevokeUserSession(userID, sessionID int64) error {
	res, err := s.db.Exec(`UPDATE sessions SET revoked_at = ?
		WHERE id = ? AND user_id = ? AND revoked_at = '' AND expires_at > ?`,
		s.nowText(), sessionID, userID, s.nowText())
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeOtherSessions signs the account out everywhere except the session
// keepID, and revokes the tokens issued to applications.
func (s *Store) RevokeOtherSessions(userID, keepID int64) error {
	return s.inTx(func(tx *sql.Tx) error {
		now := s.nowText()
		if _, err := tx.Exec(`UPDATE sessions SET revoked_at = ?
			WHERE user_id = ? AND id <> ? AND revoked_at = ''`, now, userID, keepID); err != nil {
			return fmt.Errorf("revoke sessions: %w", err)
		}
		return s.revokeRefreshTokensTx(tx, userID, "signed out everywhere", now)
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
