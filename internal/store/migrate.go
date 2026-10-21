package store

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed migrate.sql
var schemaSQL string

// schemaVersion is bumped whenever the schema grows (v6: back-channel logout),
// so an operator can tell from the database which build last touched it.
const schemaVersion = 6

// incrementalColumns are added to existing tables on upgrade. Adding a column
// here (rather than editing migrate.sql) is what keeps old databases working.
var incrementalColumns = []struct {
	table string
	name  string
	def   string
}{
	// v2: authorization codes remember the request they came from so a replay
	// can revoke the tokens that were minted from them, and refresh tokens
	// carry the original authentication context for refreshed ID tokens.
	{"auth_codes", "auth_request_id", "TEXT NOT NULL DEFAULT ''"},
	{"refresh_tokens", "auth_request_id", "TEXT NOT NULL DEFAULT ''"},
	{"refresh_tokens", "auth_time", "TEXT NOT NULL DEFAULT ''"},
	{"refresh_tokens", "amr", "TEXT NOT NULL DEFAULT ''"},
	{"refresh_tokens", "acr", "TEXT NOT NULL DEFAULT ''"},
	{"auth_requests", "prompt", "TEXT NOT NULL DEFAULT ''"},
	{"auth_requests", "max_age", "INTEGER NOT NULL DEFAULT -1"},
	{"auth_requests", "acr_values", "TEXT NOT NULL DEFAULT ''"},
	// v3: TOTP replay protection, and typed codes for emailed sign-in tokens.
	{"users", "totp_last_step", "INTEGER NOT NULL DEFAULT 0"},
	{"credential_tokens", "code_hash", "TEXT NOT NULL DEFAULT ''"},
	{"credential_tokens", "attempts", "INTEGER NOT NULL DEFAULT 0"},
	// v4: passkeys — the per-account user handle and the credential details
	// a later metadata check needs.
	{"users", "webauthn_id", "TEXT NOT NULL DEFAULT ''"},
	{"webauthn_credentials", "attestation_type", "TEXT NOT NULL DEFAULT ''"},
	{"webauthn_credentials", "attestation_format", "TEXT NOT NULL DEFAULT ''"},
	{"webauthn_credentials", "user_verified", "INTEGER NOT NULL DEFAULT 0"},
	// v6: back-channel logout — the public session ID put in ID tokens (and
	// carried by refresh tokens so a refreshed ID token keeps it), and where
	// an app wants to be told that a session ended.
	{"sessions", "sid", "TEXT NOT NULL DEFAULT ''"},
	{"refresh_tokens", "sid", "TEXT NOT NULL DEFAULT ''"},
	{"apps", "backchannel_logout_uri", "TEXT NOT NULL DEFAULT ''"},
	{"apps", "backchannel_logout_session_required", "INTEGER NOT NULL DEFAULT 0"},
}

// incrementalIndexes cover incremental columns: indexes, backfills and
// triggers. They run after the columns exist; putting them in migrate.sql
// would fail on an old database, where the schema is applied before the
// columns are added.
var incrementalIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_auth_codes_auth_request ON auth_codes(auth_request_id)`,
	`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_auth_request ON refresh_tokens(auth_request_id)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_webauthn_id ON users(webauthn_id) WHERE webauthn_id <> ''`,
	// Sessions from before v6 get a session ID too. It is an identifier, not
	// a secret, so SQLite's generator is good enough.
	`UPDATE sessions SET sid = lower(hex(randomblob(16))) WHERE sid = ''`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_sid ON sessions(sid) WHERE sid <> ''`,
	// Every way a session ends — sign-out, revocation, a password change, a
	// disabled account — sets revoked_at, so this one trigger queues the
	// back-channel notifications in the same transaction for all of them.
	// A session that simply expires sends nothing.
	`CREATE TRIGGER IF NOT EXISTS sessions_backchannel_logout
		AFTER UPDATE OF revoked_at ON sessions
		WHEN OLD.revoked_at = '' AND NEW.revoked_at <> ''
		BEGIN
			INSERT INTO backchannel_outbox(app_id, user_id, sid, created_at, next_attempt_at)
			SELECT a.id, NEW.user_id, NEW.sid, NEW.revoked_at, NEW.revoked_at
			FROM session_apps sa JOIN apps a ON a.id = sa.app_id
			WHERE sa.session_id = NEW.id AND a.backchannel_logout_uri <> '';
		END`,
}

// migrate applies the schema, then any incremental columns, then records the
// version. It is safe to run on every start.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	for _, c := range incrementalColumns {
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", c.table, c.name, c.def)
		if _, err := s.db.Exec(stmt); err != nil && !isDuplicateColumn(err) {
			return fmt.Errorf("add column %s.%s: %w", c.table, c.name, err)
		}
	}
	for _, stmt := range incrementalIndexes {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&n); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if n == 0 {
		_, err := s.db.Exec(`INSERT INTO schema_version(version) VALUES(?)`, schemaVersion)
		return err
	}
	_, err := s.db.Exec(`UPDATE schema_version SET version=?`, schemaVersion)
	return err
}

// isDuplicateColumn reports whether an ALTER TABLE failed only because the
// column is already present, which is the normal path on every restart.
func isDuplicateColumn(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column name")
}
