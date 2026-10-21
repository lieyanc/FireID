package store

import (
	"errors"
	"testing"
	"time"
)

func TestBackchannelOutbox(t *testing.T) {
	f := newOIDCFixture(t)
	uri := "https://rp.example/backchannel"
	if err := f.st.UpdateApp(f.app.ID, AppUpdate{BackchannelLogoutURI: &uri}); err != nil {
		t.Fatal(err)
	}
	quiet, _, err := f.st.CreateApp(NewApp{Slug: "quiet", Name: "Quiet", OwnerUserID: f.user.ID,
		RedirectURIs: []string{"https://quiet.example/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	_, sess, err := f.st.CreateSession(f.user.ID, time.Hour, "", "", "pwd", ACRLoA1)
	if err != nil {
		t.Fatal(err)
	}
	if sess.SID == "" {
		t.Fatal("session without sid")
	}
	for _, id := range []int64{f.app.ID, quiet.ID, f.app.ID} {
		if err := f.st.RecordSessionApp(sess.ID, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.st.RevokeSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	// Revoking again changes nothing and must not queue twice.
	if err := f.st.RevokeSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	jobs, err := f.st.DueBackchannel(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].AppID != f.app.ID || jobs[0].SID != sess.SID ||
		jobs[0].URI != uri || jobs[0].UserID != f.user.ID || jobs[0].ClientID != f.app.ClientID {
		t.Fatalf("jobs: %+v", jobs)
	}

	if err := f.st.BackchannelRetry(jobs[0].ID, "status 500", f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if jobs, _ := f.st.DueBackchannel(10); len(jobs) != 0 {
		t.Fatalf("retried job due early: %+v", jobs)
	}
	f.advance(time.Minute)
	jobs, _ = f.st.DueBackchannel(10)
	if len(jobs) != 1 || jobs[0].Attempts != 1 {
		t.Fatalf("after retry: %+v", jobs)
	}
	if err := f.st.BackchannelDone(jobs[0].ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.st.PendingBackchannel(f.app.ID); n != 0 {
		t.Fatalf("pending after done: %d", n)
	}
}

func TestBackchannelEveryRevocationPath(t *testing.T) {
	f := newOIDCFixture(t)
	uri := "https://rp.example/backchannel"
	if err := f.st.UpdateApp(f.app.ID, AppUpdate{BackchannelLogoutURI: &uri}); err != nil {
		t.Fatal(err)
	}
	signIn := func() (string, *Session) {
		t.Helper()
		token, sess, err := f.st.CreateSession(f.user.ID, time.Hour, "", "", "pwd", ACRLoA1)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.st.RecordSessionApp(sess.ID, f.app.ID); err != nil {
			t.Fatal(err)
		}
		return token, sess
	}
	for name, end := range map[string]func(token string, sess *Session) error{
		"sign-out":        func(token string, _ *Session) error { return f.st.RevokeSessionByToken(token) },
		"revoke one":      func(_ string, s *Session) error { return f.st.RevokeUserSession(f.user.ID, s.ID) },
		"others":          func(string, *Session) error { return f.st.RevokeOtherSessions(f.user.ID, 0) },
		"password change": func(string, *Session) error { return f.st.SetPassword(f.user.ID, "x") },
		"password clear":  func(string, *Session) error { return f.st.ClearPassword(f.user.ID) },
		"disable":         func(string, *Session) error { return f.st.SetStatus(f.user.ID, UserDisabled) },
		"bump generation": func(string, *Session) error { return f.st.BumpSessionGen(f.user.ID) },
	} {
		if err := f.st.SetStatus(f.user.ID, UserActive); err != nil {
			t.Fatal(err)
		}
		token, sess := signIn()
		if err := end(token, sess); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		jobs, err := f.st.DueBackchannel(10)
		if err != nil || len(jobs) != 1 || jobs[0].SID != sess.SID {
			t.Fatalf("%s: jobs %+v %v", name, jobs, err)
		}
		_ = f.st.BackchannelDone(jobs[0].ID)
	}
}

func TestBackchannelURIValidation(t *testing.T) {
	f := newOIDCFixture(t)
	for _, bad := range []string{"http://rp.example/bc", "https://rp.example/bc#frag", "ftp://rp.example", "/relative"} {
		if err := f.st.UpdateApp(f.app.ID, AppUpdate{BackchannelLogoutURI: &bad}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for _, ok := range []string{"https://rp.example/bc?x=1", "http://127.0.0.1:9000/bc", ""} {
		if err := f.st.UpdateApp(f.app.ID, AppUpdate{BackchannelLogoutURI: &ok}); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	yes := true
	if err := f.st.UpdateApp(f.app.ID, AppUpdate{BackchannelSessionRequired: &yes}); err != nil {
		t.Fatal(err)
	}
	app, _ := f.st.AppByID(f.app.ID)
	if !app.BackchannelSessionRequired {
		t.Fatal("session required not stored")
	}
}

func TestSigningKeyRotation(t *testing.T) {
	f := newOIDCFixture(t)
	if err := f.st.InsertCurrentSigningKey("k1", "ES256", "enc1", "{}"); err != nil {
		t.Fatal(err)
	}
	if err := f.st.RetireSigningKey("k1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("retire current: %v", err)
	}
	f.advance(time.Second)
	if err := f.st.RotateSigningKey("k2", "ES256", "enc2", "{}"); err != nil {
		t.Fatal(err)
	}
	cur, err := f.st.CurrentSigningKey()
	if err != nil || cur.KID != "k2" {
		t.Fatalf("current: %+v %v", cur, err)
	}
	pub, _ := f.st.PublishedSigningKeys()
	if len(pub) != 2 {
		t.Fatalf("published after rotation: %d", len(pub))
	}
	if err := f.st.RetireSigningKey("k1"); err != nil {
		t.Fatal(err)
	}
	if err := f.st.RetireSigningKey("k1"); err != nil {
		t.Fatalf("retire twice: %v", err)
	}
	if err := f.st.RetireSigningKey("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retire unknown: %v", err)
	}
	pub, _ = f.st.PublishedSigningKeys()
	all, _ := f.st.ListSigningKeys()
	if len(pub) != 1 || pub[0].KID != "k2" || len(all) != 2 || all[1].RetiredAt.IsZero() {
		t.Fatalf("published %d, all %+v", len(pub), all)
	}
	if err := f.st.RotateSigningKey("k2", "ES256", "x", "{}"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate kid: %v", err)
	}
	if cur, _ := f.st.CurrentSigningKey(); cur == nil || cur.KID != "k2" {
		t.Fatal("failed rotation changed the current key")
	}
}

func TestAuditLog(t *testing.T) {
	f := newOIDCFixture(t)
	bob, err := f.st.CreateUser(NewUser{Username: "bob", Email: "bob@example.com", Status: UserActive})
	if err != nil {
		t.Fatal(err)
	}
	events := []AuditEvent{
		{Event: "auth.sign_in", ActorUserID: f.user.ID, ActorType: ActorUser, UserID: f.user.ID, IP: "192.0.2.1:443"},
		{Event: "auth.sign_in_failed", Severity: SeverityWarning, UserID: bob.ID, Detail: map[string]any{"reason": "password"}},
		{Event: "app.update", ActorUserID: f.user.ID, ActorType: ActorAdmin, AppID: f.app.ID},
		{Event: "app.member_add", ActorUserID: f.user.ID, ActorType: ActorAdmin, AppID: f.app.ID, UserID: bob.ID},
	}
	for _, e := range events {
		if err := f.st.Audit(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.st.Audit(AuditEvent{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nameless event: %v", err)
	}
	// A vanished user is dropped from the row, not the event.
	if err := f.st.Audit(AuditEvent{Event: "auth.sign_out", UserID: 9999}); err != nil {
		t.Fatal(err)
	}

	all, err := f.st.ListAudit(AuditQuery{})
	if err != nil || len(all) != 5 || all[0].Event != "auth.sign_out" || all[0].UserID != 0 {
		t.Fatalf("all: %d %v", len(all), err)
	}
	if all[4].IP != "192.0.2.1" || all[4].ActorType != ActorUser {
		t.Fatalf("first row: %+v", all[4])
	}
	if all[3].Detail["reason"] != "password" || all[3].Severity != SeverityWarning {
		t.Fatalf("detail: %+v", all[3])
	}
	check := func(name string, q AuditQuery, want ...string) {
		t.Helper()
		rows, err := f.st.ListAudit(q)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range rows {
			got = append(got, r.Event)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: got %v want %v", name, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s: got %v want %v", name, got, want)
			}
		}
	}
	check("app", AuditQuery{AppID: f.app.ID}, "app.member_add", "app.update")
	check("bob", AuditQuery{UserID: bob.ID}, "app.member_add", "auth.sign_in_failed")
	check("prefix", AuditQuery{Event: "auth."}, "auth.sign_out", "auth.sign_in_failed", "auth.sign_in")
	check("exact", AuditQuery{Event: "auth.sign_in"}, "auth.sign_in")
	check("page", AuditQuery{BeforeID: all[1].ID, Limit: 2}, "app.update", "auth.sign_in_failed")

	f.advance(AuditRetention + time.Hour)
	_ = f.st.Audit(AuditEvent{Event: "later"})
	if n, err := f.st.DeleteOldAudit(); err != nil || n != 5 {
		t.Fatalf("purge: %d %v", n, err)
	}
}
