package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Credential token purposes.
const (
	// PurposeEmailLogin is an emailed sign-in: a link and a typed code.
	PurposeEmailLogin = "magic_link"
)

// MaxCodeAttempts is how many wrong codes a token survives.
const MaxCodeAttempts = 5

// CredentialToken is a single-use token delivered out of band. Only hashes of
// the token and its code are stored.
type CredentialToken struct {
	ID        int64
	UserID    int64
	Purpose   string
	TokenHash string
	CodeHash  string
	Attempts  int
	Email     string
	ExpiresAt time.Time
	UsedAt    time.Time
	CreatedAt time.Time
}

const credentialTokenColumns = `id, user_id, purpose, token_hash, code_hash, attempts, email,
	expires_at, used_at, created_at`

func scanCredentialToken(row interface{ Scan(...any) error }) (*CredentialToken, error) {
	var t CredentialToken
	var expires, used, created string
	err := row.Scan(&t.ID, &t.UserID, &t.Purpose, &t.TokenHash, &t.CodeHash, &t.Attempts, &t.Email,
		&expires, &used, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan credential token: %w", err)
	}
	t.ExpiresAt = parseTime(expires)
	t.UsedAt = parseTime(used)
	t.CreatedAt = parseTime(created)
	return &t, nil
}

// CreateCredentialToken stores a new token and spends every earlier unused
// token of the same purpose for the user, so only the latest email works.
func (s *Store) CreateCredentialToken(userID int64, purpose, email, tokenHash, codeHash, ip string, ttl time.Duration) error {
	return s.inTx(func(tx *sql.Tx) error {
		now := s.now()
		if _, err := tx.Exec(`UPDATE credential_tokens SET used_at = ?
			WHERE user_id = ? AND purpose = ? AND used_at = ''`, formatTime(now), userID, purpose); err != nil {
			return fmt.Errorf("retire credential tokens: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO credential_tokens(user_id, purpose, token_hash, code_hash, email,
			expires_at, created_at, ip) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
			userID, purpose, tokenHash, codeHash, NormaliseEmail(email),
			formatTime(now.Add(ttl)), formatTime(now), normaliseIP(ip)); err != nil {
			return fmt.Errorf("insert credential token: %w", err)
		}
		return nil
	})
}

// CredentialTokenByHash returns a live token by the hash of its value. Spent
// and expired tokens are ErrNotFound. Looking a token up does not spend it;
// ConsumeCredentialToken does.
func (s *Store) CredentialTokenByHash(purpose, tokenHash string) (*CredentialToken, error) {
	return scanCredentialToken(s.db.QueryRow(`SELECT `+credentialTokenColumns+` FROM credential_tokens
		WHERE purpose = ? AND token_hash = ? AND used_at = '' AND expires_at > ?`,
		purpose, tokenHash, s.nowText()))
}

// LatestCredentialToken returns the live token most recently sent to email.
func (s *Store) LatestCredentialToken(purpose, email string) (*CredentialToken, error) {
	return scanCredentialToken(s.db.QueryRow(`SELECT `+credentialTokenColumns+` FROM credential_tokens
		WHERE purpose = ? AND email = ? AND used_at = '' AND expires_at > ?
		ORDER BY id DESC LIMIT 1`, purpose, NormaliseEmail(email), s.nowText()))
}

// ConsumeCredentialToken spends a token. ErrConsumed means another request
// spent it first, or it expired in the meantime.
func (s *Store) ConsumeCredentialToken(id int64) error {
	now := s.nowText()
	res, err := s.db.Exec(`UPDATE credential_tokens SET used_at = ?
		WHERE id = ? AND used_at = '' AND expires_at > ?`, now, id, now)
	if err != nil {
		return fmt.Errorf("consume credential token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConsumed
	}
	return nil
}

// ReserveCodeAttempt claims one of a token's code attempts before the code is
// compared. Claiming first is what holds the budget under concurrency: a
// burst of parallel guesses cannot all read the same count. ErrConsumed means
// the attempts have run out, or the token is spent or expired.
func (s *Store) ReserveCodeAttempt(id int64) error {
	now := s.nowText()
	res, err := s.db.Exec(`UPDATE credential_tokens SET attempts = attempts + 1
		WHERE id = ? AND used_at = '' AND expires_at > ? AND attempts < ?`, id, now, MaxCodeAttempts)
	if err != nil {
		return fmt.Errorf("reserve code attempt: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConsumed
	}
	return nil
}

// SpendIfExhausted spends a token whose code attempts have run out, so its
// link stops working too.
func (s *Store) SpendIfExhausted(id int64) error {
	_, err := s.db.Exec(`UPDATE credential_tokens SET used_at = ?
		WHERE id = ? AND used_at = '' AND attempts >= ?`, s.nowText(), id, MaxCodeAttempts)
	if err != nil {
		return fmt.Errorf("spend exhausted token: %w", err)
	}
	return nil
}

// DeleteExpiredCredentialTokens removes tokens that expired or were spent
// more than a day ago.
func (s *Store) DeleteExpiredCredentialTokens() (int64, error) {
	cutoff := formatTime(s.now().Add(-24 * time.Hour))
	res, err := s.db.Exec(`DELETE FROM credential_tokens WHERE expires_at < ?
		OR (used_at <> '' AND used_at < ?)`, cutoff, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired credential tokens: %w", err)
	}
	return res.RowsAffected()
}
