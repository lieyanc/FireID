package store

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed migrate.sql
var schemaSQL string

// schemaVersion is bumped whenever incrementalColumns grows, so an operator can
// tell from the database which build last touched it.
const schemaVersion = 1

// incrementalColumns are added to existing tables on upgrade. Adding a column
// here (rather than editing migrate.sql) is what keeps old databases working.
var incrementalColumns = []struct {
	table string
	name  string
	def   string
}{
	// First release — nothing yet. Example for later:
	// {"apps", "tos_url", "TEXT NOT NULL DEFAULT ''"},
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
