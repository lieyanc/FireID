package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The database holds password hashes and sealed keys: it must be owner-only
// however permissive the umask or a pre-existing file was.
func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DBFileName)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// A write makes SQLite create the WAL and shared-memory files.
	if _, err := st.CreateUser(NewUser{Username: "alice", Email: "alice@example.com", Status: UserActive}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s has mode %o, want no group or other access", filepath.Base(p), mode)
		}
	}
}

// Revoking a refresh-token family, on reuse or at the revocation endpoint,
// also ends the access tokens the family produced.
func TestRevokeFamilyRevokesItsAccessTokens(t *testing.T) {
	f := newOIDCFixture(t)
	ar := f.approvedRequest(t)
	rt, err := f.st.CreateRefreshToken("rt-1", RefreshTokenSpec{AppID: f.app.ID, UserID: f.user.ID,
		Scope: "openid", AuthRequestID: ar.ID, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.CreateAccessToken("at-1", f.app.ID, f.user.ID, "openid", ar.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	// An unrelated grant of the same user and app is left alone.
	other := f.approvedRequest(t)
	if _, err := f.st.CreateAccessToken("at-other", f.app.ID, f.user.ID, "openid", other.ID, time.Hour); err != nil {
		t.Fatal(err)
	}

	if err := f.st.RevokeRefreshTokenFamily(rt.FamilyID, "replay_detected"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AccessTokenByID("at-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("access token of the revoked family: %v", err)
	}
	if _, err := f.st.AccessTokenByID("at-other"); err != nil {
		t.Fatalf("unrelated access token: %v", err)
	}
	if got, err := f.st.RefreshTokenByToken("rt-1"); err != nil || got.RevokedAt.IsZero() {
		t.Fatalf("refresh token not revoked: %v %v", got, err)
	}
}
