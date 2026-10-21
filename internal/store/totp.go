package store

import (
	"database/sql"
	"fmt"
)

// BeginTOTPEnrolment stores a new, unconfirmed TOTP secret. It replaces an
// earlier unconfirmed one, so an abandoned enrolment can simply be restarted,
// but it never touches a confirmed secret: turning TOTP off is a separate,
// re-authenticated step. ErrConflict means TOTP is already on.
func (s *Store) BeginTOTPEnrolment(userID int64, encryptedSecret string) error {
	res, err := s.db.Exec(`UPDATE users SET totp_secret_enc = ?, totp_last_step = 0, updated_at = ?
		WHERE id = ? AND totp_confirmed_at = ''`, encryptedSecret, s.nowText(), userID)
	if err != nil {
		return fmt.Errorf("begin totp enrolment: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.UserByID(userID); err != nil {
			return err
		}
		return fmt.Errorf("%w: two-step verification is already on", ErrConflict)
	}
	return nil
}

// AcceptTOTPStep records step as used. It fails with ErrConsumed when a code
// of this step or a later one was already accepted, which is what stops a
// code from working twice — also when two requests race with the same code.
func (s *Store) AcceptTOTPStep(userID, step int64) error {
	return acceptTOTPStep(s.db.Exec, userID, step)
}

func acceptTOTPStep(exec func(string, ...any) (sql.Result, error), userID, step int64) error {
	res, err := exec(`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`,
		step, userID, step)
	if err != nil {
		return fmt.Errorf("accept totp step: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConsumed
	}
	return nil
}

// ConfirmTOTP finishes an enrolment: the code of step proved that the secret
// stored as secretEnc works, and recoveryHashes become the account's recovery
// codes. ErrConflict means there was no pending enrolment to confirm, or a
// newer enrolment replaced secretEnc meanwhile — confirming that one would
// tie the account to a secret no authenticator holds.
func (s *Store) ConfirmTOTP(userID int64, secretEnc string, step int64, recoveryHashes []string) error {
	return s.inTx(func(tx *sql.Tx) error {
		now := s.nowText()
		res, err := tx.Exec(`UPDATE users SET totp_confirmed_at = ?, updated_at = ?
			WHERE id = ? AND totp_secret_enc = ? AND totp_secret_enc <> '' AND totp_confirmed_at = ''`,
			now, now, userID, secretEnc)
		if err != nil {
			return fmt.Errorf("confirm totp: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: no two-step verification enrolment is pending", ErrConflict)
		}
		if err := acceptTOTPStep(tx.Exec, userID, step); err != nil {
			return err
		}
		return s.replaceRecoveryCodesTx(tx, userID, recoveryHashes)
	})
}

// DisableTOTP removes the secret and every recovery code.
func (s *Store) DisableTOTP(userID int64) error {
	return s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE users SET totp_secret_enc = '', totp_confirmed_at = '',
			totp_last_step = 0, updated_at = ? WHERE id = ?`, s.nowText(), userID); err != nil {
			return fmt.Errorf("disable totp: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
			return fmt.Errorf("delete recovery codes: %w", err)
		}
		return nil
	})
}

// ReplaceRecoveryCodes swaps the account's recovery codes for a new set.
func (s *Store) ReplaceRecoveryCodes(userID int64, hashes []string) error {
	return s.inTx(func(tx *sql.Tx) error { return s.replaceRecoveryCodesTx(tx, userID, hashes) })
}

func (s *Store) replaceRecoveryCodesTx(tx *sql.Tx, userID int64, hashes []string) error {
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	now := s.nowText()
	for _, h := range hashes {
		if _, err := tx.Exec(`INSERT INTO recovery_codes(user_id, code_hash, created_at) VALUES(?, ?, ?)`,
			userID, h, now); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return nil
}

// UseRecoveryCode spends the recovery code with the given hash. ErrNotFound
// means it does not exist or was already used.
func (s *Store) UseRecoveryCode(userID int64, hash string) error {
	res, err := s.db.Exec(`UPDATE recovery_codes SET used_at = ?
		WHERE user_id = ? AND code_hash = ? AND used_at = ''`, s.nowText(), userID, hash)
	if err != nil {
		return fmt.Errorf("use recovery code: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecoveryCodesLeft counts the unused recovery codes.
func (s *Store) RecoveryCodesLeft(userID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at = ''`,
		userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}
	return n, nil
}
