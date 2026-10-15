// Package store owns the SQLite database: schema, queries, and the invariants
// that must hold regardless of which caller reaches them. Anything that could
// weaken an authentication decision (single-use codes, refresh-token rotation,
// session revocation) is enforced here rather than in the HTTP layer.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a write violates a uniqueness rule.
var ErrConflict = errors.New("conflict")

// ErrConsumed is returned when a single-use value has already been redeemed.
var ErrConsumed = errors.New("already consumed")

// DBFileName is the database file inside the data directory.
const DBFileName = "fireid.db"

// Store is the database handle plus the small amount of process state that
// depends on it.
type Store struct {
	db      *sql.DB
	dataDir string

	mu       sync.RWMutex
	timeFunc func() time.Time
}

// Open prepares the data directory, opens the database, and migrates it.
func Open(dataDir string) (*Store, error) {
	if dataDir == "" {
		dataDir = "."
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, DBFileName)

	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// modernc's driver serialises writes internally; a small pool avoids
	// SQLITE_BUSY storms without hurting read throughput.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	s := &Store{db: db, dataDir: dataDir, timeFunc: func() time.Time { return time.Now().UTC() }}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for packages that need a transaction of their own.
// Callers must not change the connection pool settings.
func (s *Store) DB() *sql.DB { return s.db }

// DataDir is the directory the database lives in.
func (s *Store) DataDir() string { return s.dataDir }

// now returns the current time through the store's clock, which tests
// override. All persisted timestamps come from here so time-based invariants
// stay testable.
func (s *Store) now() time.Time {
	s.mu.RLock()
	fn := s.timeFunc
	s.mu.RUnlock()
	return fn()
}

// SetClock replaces the clock. Tests only.
func (s *Store) SetClock(fn func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timeFunc = fn
}

// nowText renders a timestamp in the workspace's storage format.
func (s *Store) nowText() string { return formatTime(s.now()) }

// formatTime renders a timestamp as RFC 3339 with second precision in UTC.
// Sub-second precision is deliberately dropped: it makes stored values
// comparable as strings and keeps the audit log readable.
func formatTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// parseTime reads a stored timestamp. An empty string is the zero time, which
// callers use to mean "never".
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// inTx runs fn inside a transaction, rolling back on error or panic.
func (s *Store) inTx(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// isUniqueViolation reports whether err is a SQLite uniqueness error, which the
// driver reports as a message rather than a typed error.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed: UNIQUE")
}

// isForeignKeyViolation reports whether err is a SQLite foreign-key error.
func isForeignKeyViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "FOREIGN KEY constraint failed")
}
