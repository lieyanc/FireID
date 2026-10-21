package store

import (
	"errors"
	"testing"
	"time"
)

// oidcFixture is a store with one user, one app and an adjustable clock.
type oidcFixture struct {
	st   *Store
	now  time.Time
	user *User
	app  *App
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := &oidcFixture{st: st, now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	st.SetClock(func() time.Time { return f.now })

	f.user, err = st.CreateUser(NewUser{Username: "alice", Email: "alice@example.com", Status: UserActive})
	if err != nil {
		t.Fatal(err)
	}
	f.app, _, err = st.CreateApp(NewApp{
		Slug: "rp", Name: "RP", OwnerUserID: f.user.ID,
		RedirectURIs: []string{"https://rp.example/cb"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *oidcFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

// approvedRequest stores and approves an authorization request.
func (f *oidcFixture) approvedRequest(t *testing.T) *AuthRequest {
	t.Helper()
	ar := &AuthRequest{AppID: f.app.ID, RedirectURI: "https://rp.example/cb", Scope: "openid", MaxAge: -1}
	if err := f.st.CreateAuthRequest(ar); err != nil {
		t.Fatal(err)
	}
	if err := f.st.ApproveAuthRequest(ar.ID, f.user.ID, f.now, "pwd", ACRLoA1, ""); err != nil {
		t.Fatal(err)
	}
	return ar
}

func TestAuthCodeSingleUse(t *testing.T) {
	t.Run("second redemption is a replay and revokes what the first produced", func(t *testing.T) {
		f := newOIDCFixture(t)
		ar := f.approvedRequest(t)
		if err := f.st.SaveAuthCode(ar.ID, "code-1", time.Minute); err != nil {
			t.Fatal(err)
		}
		ac, err := f.st.ConsumeAuthCode("code-1")
		if err != nil {
			t.Fatal(err)
		}
		if ac.AuthRequestID != ar.ID || ac.UserID != f.user.ID {
			t.Fatalf("code carried %q/%d, want %q/%d", ac.AuthRequestID, ac.UserID, ar.ID, f.user.ID)
		}
		if _, err := f.st.CreateRefreshToken("rt-1", RefreshTokenSpec{
			AppID: f.app.ID, UserID: f.user.ID, Scope: "openid", AuthRequestID: ar.ID, TTL: time.Hour,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.CreateAccessToken("at-1", f.app.ID, f.user.ID, "openid", ar.ID, time.Hour); err != nil {
			t.Fatal(err)
		}

		if _, err := f.st.ConsumeAuthCode("code-1"); !errors.Is(err, ErrConsumed) {
			t.Fatalf("replay: got %v, want ErrConsumed", err)
		}
		rt, err := f.st.RefreshTokenByToken("rt-1")
		if err != nil {
			t.Fatal(err)
		}
		if rt.RevokedAt.IsZero() || rt.RevokedReason != "code_replayed" {
			t.Fatalf("refresh token after replay: revoked=%v reason=%q", rt.RevokedAt, rt.RevokedReason)
		}
		if _, err := f.st.AccessTokenByID("at-1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("access token after replay: got %v, want ErrNotFound", err)
		}
	})

	t.Run("expired code is refused", func(t *testing.T) {
		f := newOIDCFixture(t)
		ar := f.approvedRequest(t)
		if err := f.st.SaveAuthCode(ar.ID, "code-1", 30*time.Second); err != nil {
			t.Fatal(err)
		}
		f.advance(31 * time.Second)
		if _, err := f.st.ConsumeAuthCode("code-1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("one request yields one code", func(t *testing.T) {
		f := newOIDCFixture(t)
		ar := f.approvedRequest(t)
		if err := f.st.SaveAuthCode(ar.ID, "code-1", time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := f.st.SaveAuthCode(ar.ID, "code-2", time.Minute); !errors.Is(err, ErrConsumed) {
			t.Fatalf("second code: got %v, want ErrConsumed", err)
		}
	})

	t.Run("unapproved request yields no code", func(t *testing.T) {
		f := newOIDCFixture(t)
		ar := &AuthRequest{AppID: f.app.ID, RedirectURI: "https://rp.example/cb", Scope: "openid", MaxAge: -1}
		if err := f.st.CreateAuthRequest(ar); err != nil {
			t.Fatal(err)
		}
		if err := f.st.SaveAuthCode(ar.ID, "code-1", time.Minute); err == nil {
			t.Fatal("issued a code for an unapproved request")
		}
	})

	t.Run("unknown code", func(t *testing.T) {
		f := newOIDCFixture(t)
		if _, err := f.st.ConsumeAuthCode("nope"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})
}

func TestAuthRequestExpiry(t *testing.T) {
	f := newOIDCFixture(t)
	ar := &AuthRequest{AppID: f.app.ID, RedirectURI: "https://rp.example/cb", Scope: "openid", MaxAge: -1}
	if err := f.st.CreateAuthRequest(ar); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AuthRequestByID(ar.ID); err != nil {
		t.Fatal(err)
	}
	f.advance(AuthRequestTTL)
	if _, err := f.st.AuthRequestByID(ar.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lookup after expiry: got %v, want ErrNotFound", err)
	}
	if err := f.st.ApproveAuthRequest(ar.ID, f.user.ID, f.now, "pwd", ACRLoA1, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approval after expiry: got %v, want ErrNotFound", err)
	}
	if n, err := f.st.DeleteExpiredAuthRequests(); err != nil || n != 1 {
		t.Fatalf("purge: n=%d err=%v", n, err)
	}
}

func TestRefreshTokenRotation(t *testing.T) {
	spec := func(f *oidcFixture) RefreshTokenSpec {
		return RefreshTokenSpec{AppID: f.app.ID, UserID: f.user.ID, Scope: "openid offline_access",
			AuthTime: f.now, AMR: "pwd otp", ACR: ACRLoA2, TTL: time.Hour}
	}

	t.Run("rotation keeps the family and the authentication context", func(t *testing.T) {
		f := newOIDCFixture(t)
		first, err := f.st.CreateRefreshToken("rt-1", spec(f))
		if err != nil {
			t.Fatal(err)
		}
		f.advance(time.Minute)
		second, err := f.st.RotateRefreshToken("rt-1", "rt-2", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if second.FamilyID != first.FamilyID {
			t.Fatalf("family changed: %q -> %q", first.FamilyID, second.FamilyID)
		}
		if second.AMR != "pwd otp" || second.ACR != ACRLoA2 || !second.AuthTime.Equal(first.AuthTime) {
			t.Fatalf("context lost: amr=%q acr=%q authTime=%v", second.AMR, second.ACR, second.AuthTime)
		}
		old, err := f.st.RefreshTokenByToken("rt-1")
		if err != nil {
			t.Fatal(err)
		}
		if old.RotatedAt.IsZero() {
			t.Fatal("old token not marked rotated")
		}
	})

	t.Run("replaying a rotated token revokes the whole family", func(t *testing.T) {
		f := newOIDCFixture(t)
		if _, err := f.st.CreateRefreshToken("rt-1", spec(f)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.RotateRefreshToken("rt-1", "rt-2", time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.RotateRefreshToken("rt-1", "rt-3", time.Hour); !errors.Is(err, ErrRefreshReplayed) {
			t.Fatalf("replay: got %v, want ErrRefreshReplayed", err)
		}
		live, err := f.st.RefreshTokenByToken("rt-2")
		if err != nil {
			t.Fatal(err)
		}
		if live.RevokedAt.IsZero() || live.RevokedReason != "replay_detected" {
			t.Fatalf("descendant not revoked: revoked=%v reason=%q", live.RevokedAt, live.RevokedReason)
		}
		if _, err := f.st.RefreshTokenByToken("rt-3"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("replay minted a token: %v", err)
		}
		if _, err := f.st.RotateRefreshToken("rt-2", "rt-4", time.Hour); !errors.Is(err, ErrRefreshRevoked) {
			t.Fatalf("revoked descendant: got %v, want ErrRefreshRevoked", err)
		}
	})

	t.Run("expired token is refused", func(t *testing.T) {
		f := newOIDCFixture(t)
		if _, err := f.st.CreateRefreshToken("rt-1", spec(f)); err != nil {
			t.Fatal(err)
		}
		f.advance(time.Hour)
		if _, err := f.st.RotateRefreshToken("rt-1", "rt-2", time.Hour); !errors.Is(err, ErrRefreshExpired) {
			t.Fatalf("got %v, want ErrRefreshExpired", err)
		}
	})

	t.Run("password change revokes refresh and access tokens", func(t *testing.T) {
		f := newOIDCFixture(t)
		if _, err := f.st.CreateRefreshToken("rt-1", spec(f)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.CreateAccessToken("at-1", f.app.ID, f.user.ID, "openid", "", time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := f.st.SetPassword(f.user.ID, "new-hash"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.RotateRefreshToken("rt-1", "rt-2", time.Hour); !errors.Is(err, ErrRefreshRevoked) {
			t.Fatalf("refresh after password change: got %v, want ErrRefreshRevoked", err)
		}
		if _, err := f.st.AccessTokenByID("at-1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("access after password change: got %v, want ErrNotFound", err)
		}
	})
}

func TestAccessTokenLifetime(t *testing.T) {
	f := newOIDCFixture(t)
	exp, err := f.st.CreateAccessToken("at-1", f.app.ID, f.user.ID, "openid email", "req", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(f.now.Add(time.Hour)) {
		t.Fatalf("expiry %v, want %v", exp, f.now.Add(time.Hour))
	}
	at, err := f.st.AccessTokenByID("at-1")
	if err != nil {
		t.Fatal(err)
	}
	if at.Scope != "openid email" || at.UserID != f.user.ID {
		t.Fatalf("unexpected row %+v", at)
	}
	f.advance(time.Hour)
	if _, err := f.st.AccessTokenByID("at-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after expiry: got %v, want ErrNotFound", err)
	}
	if n, err := f.st.DeleteExpiredAccessTokens(); err != nil || n != 1 {
		t.Fatalf("purge: n=%d err=%v", n, err)
	}
}

func TestMigrateUpgradesV1Database(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Turn the fresh database back into the v1 shape: no incremental columns
	// and none of the indexes that depend on them.
	for _, stmt := range []string{
		`DROP INDEX idx_auth_codes_auth_request`,
		`DROP INDEX idx_refresh_tokens_auth_request`,
		`DROP INDEX idx_users_webauthn_id`,
		`DROP INDEX idx_sessions_sid`,
		`DROP TRIGGER sessions_backchannel_logout`,
	} {
		if _, err := st.db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range incrementalColumns {
		if _, err := st.db.Exec(`ALTER TABLE ` + c.table + ` DROP COLUMN ` + c.name); err != nil {
			t.Fatalf("drop %s.%s: %v", c.table, c.name, err)
		}
	}
	// A session from before v6 has no sid.
	if _, err := st.db.Exec(`INSERT INTO users(username, email, status, created_at, updated_at)
		VALUES ('old', 'old@example.com', 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO sessions(user_id, token_hash, created_at, expires_at, last_seen_at)
		SELECT id, 'h', '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z', '2026-01-01T00:00:00Z' FROM users`); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	st, err = Open(dir)
	if err != nil {
		t.Fatalf("reopen v1 database: %v", err)
	}
	defer st.Close()
	for _, c := range incrementalColumns {
		var n int
		if err := st.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`,
			c.table, c.name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("column %s.%s missing after upgrade", c.table, c.name)
		}
	}
	var sid string
	if err := st.db.QueryRow(`SELECT sid FROM sessions`).Scan(&sid); err != nil || len(sid) != 32 {
		t.Fatalf("old session sid %q (err %v)", sid, err)
	}
	var version int
	if err := st.db.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("schema version %d (err %v), want %d", version, err, schemaVersion)
	}
}
