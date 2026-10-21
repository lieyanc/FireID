package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/lieyanc/FireID/internal/store"
)

// auditPage fetches one page of an audit view.
func (e *oidcEnv) auditPage(c *http.Client, path string) ([]map[string]any, any) {
	e.t.Helper()
	st, body := e.send(c, http.MethodGet, path, nil)
	wantStatus(e.t, path, st, http.StatusOK, body)
	list, ok := body["entries"].([]any)
	if !ok {
		e.t.Fatalf("%s: no entries in %v", path, body)
	}
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		out = append(out, x.(map[string]any))
	}
	return out, body["nextBefore"]
}

func refID(v any) int64 {
	m, ok := v.(map[string]any)
	if !ok {
		return 0
	}
	id, _ := m["id"].(float64)
	return int64(id)
}

func TestAuditAccess(t *testing.T) {
	e := newAdminEnv(t)

	st, body := e.send(e.alice, http.MethodGet, "/api/admin/audit", nil)
	wantError(t, "manager, global log", st, http.StatusForbidden, body, "forbidden")
	st, body = e.send(e.bobC, http.MethodGet, "/api/admin/audit", nil)
	wantError(t, "stranger, global log", st, http.StatusForbidden, body, "forbidden")
	st, body = e.send(e.root, http.MethodGet, "/api/admin/audit", nil)
	wantStatus(t, "super, global log", st, http.StatusOK, body)

	// A manager reads their own app's log and nobody else's.
	st, body = e.send(e.alice, http.MethodGet, "/api/admin/apps/alices/audit", nil)
	wantStatus(t, "own app log", st, http.StatusOK, body)
	st, body = e.send(e.alice, http.MethodGet, "/api/admin/apps/web/audit", nil)
	wantError(t, "foreign app log", st, http.StatusNotFound, body, "not_found")
	st, body = e.send(e.bobC, http.MethodGet, "/api/admin/apps/alices/audit", nil)
	wantError(t, "stranger app log", st, http.StatusNotFound, body, "not_found")

	for _, q := range []string{"user=alice", "before=x", "limit=-1", "limit=0"} {
		st, body = e.send(e.root, http.MethodGet, "/api/admin/audit?"+q, nil)
		wantError(t, q, st, http.StatusBadRequest, body, "invalid")
	}
	st, body = e.send(e.root, http.MethodGet, "/api/admin/audit?app=nope", nil)
	wantError(t, "unknown app", st, http.StatusNotFound, body, "not_found")

	if p := e.me(e.root)["permissions"].(map[string]any); p["viewAudit"] != true || p["manageKeys"] != true {
		t.Fatalf("super permissions %v", p)
	}
	if p := e.me(e.alice)["permissions"].(map[string]any); p["viewAudit"] != false || p["manageKeys"] != false {
		t.Fatalf("manager permissions %v", p)
	}
}

func TestAuditSignIn(t *testing.T) {
	e := newAdminEnv(t)
	const wrong = "not-the-password-0451"

	c := e.browser()
	e.passwordSignIn(c, "alice")
	st, body := e.postJSON(e.browser(), "/api/auth/login", map[string]any{"username": "alice", "password": wrong})
	wantError(t, "wrong password", st, http.StatusUnauthorized, body, "invalid_credentials")
	st, body = e.postJSON(e.browser(), "/api/auth/login", map[string]any{"username": "nosuchuser", "password": wrong})
	wantError(t, "unknown user", st, http.StatusUnauthorized, body, "invalid_credentials")
	st, body = e.postJSON(c, "/api/auth/logout", map[string]any{})
	wantStatus(t, "logout", st, http.StatusNoContent, body)

	entries, _ := e.auditPage(e.root, "/api/admin/audit?event=auth.sign_in")
	if len(entries) != 1 {
		t.Fatalf("sign-in entries %v", entries)
	}
	in := entries[0]
	if refID(in["user"]) != e.user.ID || refID(in["actor"]) != e.user.ID || in["actorType"] != "user" ||
		in["ip"] != "127.0.0.1" || in["userAgent"] == "" {
		t.Fatalf("sign-in entry %v", in)
	}
	if d := in["detail"].(map[string]any); d["method"] != "password" || strings.Join(stringList(d["amr"]), " ") != "pwd" {
		t.Fatalf("sign-in detail %v", d)
	}

	failed, _ := e.auditPage(e.root, "/api/admin/audit?event=auth.sign_in_failed")
	if len(failed) != 2 {
		t.Fatalf("failure entries %v", failed)
	}
	// Newest first: the unknown account, then alice's wrong password.
	if failed[0]["user"] != nil || failed[0]["detail"].(map[string]any)["reason"] != "unknown_account" {
		t.Fatalf("unknown account entry %v", failed[0])
	}
	if refID(failed[1]["user"]) != e.user.ID || failed[1]["severity"] != "warning" ||
		failed[1]["actor"] != nil || failed[1]["detail"].(map[string]any)["reason"] != "wrong_password" ||
		failed[1]["detail"].(map[string]any)["method"] != "password" {
		t.Fatalf("wrong password entry %v", failed[1])
	}

	// Neither the attempted password nor the made-up username is stored.
	rows, err := e.st.ListAudit(store.AuditQuery{Limit: store.AuditMaxLimit})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rows)
	for _, secret := range []string{wrong, testPassword, "nosuchuser"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit rows contain %q: %s", secret, raw)
		}
	}

	out, _ := e.auditPage(e.root, fmt.Sprintf("/api/admin/audit?event=auth.sign_out&user=%d", e.user.ID))
	if len(out) != 1 {
		t.Fatalf("sign-out entries %v", out)
	}
	// The prefix filter takes every auth.* event.
	if all, _ := e.auditPage(e.root, "/api/admin/audit?event=auth."); len(all) != 4 {
		t.Fatalf("auth.* entries %d", len(all))
	}
}

func TestAuditAppUpdate(t *testing.T) {
	e := newAdminEnv(t)
	st, body := e.send(e.alice, http.MethodPatch, "/api/admin/apps/alices",
		map[string]any{"name": "Renamed", "description": ""})
	wantStatus(t, "patch", st, http.StatusNoContent, body)

	entries, _ := e.auditPage(e.alice, "/api/admin/apps/alices/audit?event=app.update")
	if len(entries) != 1 {
		t.Fatalf("app log %v", entries)
	}
	got := entries[0]
	app, _ := got["app"].(map[string]any)
	if app["slug"] != "alices" || app["name"] != "Renamed" || refID(got["actor"]) != e.user.ID ||
		got["actorType"] != "admin" {
		t.Fatalf("app.update entry %v", got)
	}
	// Only the field that changed is named; the empty description already was.
	if f := stringList(got["detail"].(map[string]any)["fields"]); strings.Join(f, ",") != "name" {
		t.Fatalf("changed fields %v", f)
	}
	rows, err := e.st.ListAudit(store.AuditQuery{Event: "app.update"})
	if err != nil || len(rows) != 1 || rows[0].AppID != e.owned.ID {
		t.Fatalf("stored row %+v %v", rows, err)
	}

	// The same entry shows in the global log filtered by app, and the other
	// apps' logs stay empty.
	if all, _ := e.auditPage(e.root, "/api/admin/audit?app=alices&event=app.update"); len(all) != 1 {
		t.Fatalf("global log by app %v", all)
	}
	if other, _ := e.auditPage(e.root, "/api/admin/apps/web/audit"); len(other) != 0 {
		t.Fatalf("web app log %v", other)
	}
}

func TestAuditPagination(t *testing.T) {
	e := newAdminEnv(t)
	for i := range 5 {
		if err := e.st.Audit(store.AuditEvent{Event: "test.page", Detail: map[string]any{"n": i}}); err != nil {
			t.Fatal(err)
		}
	}
	var seen []float64
	path := "/api/admin/audit?event=test.&limit=2"
	for page := 0; ; page++ {
		entries, next := e.auditPage(e.root, path)
		for _, x := range entries {
			seen = append(seen, x["detail"].(map[string]any)["n"].(float64))
		}
		if next == nil {
			if page != 2 || len(entries) != 1 {
				t.Fatalf("last page %d has %d entries", page, len(entries))
			}
			break
		}
		if len(entries) != 2 || next.(float64) != entries[1]["id"].(float64) {
			t.Fatalf("page %d: %d entries, nextBefore %v", page, len(entries), next)
		}
		path = fmt.Sprintf("/api/admin/audit?event=test.&limit=2&before=%d", int64(next.(float64)))
	}
	if fmt.Sprint(seen) != "[4 3 2 1 0]" {
		t.Fatalf("entries in order %v", seen)
	}
}

func TestAppBackchannelSettings(t *testing.T) {
	e := newAdminEnv(t)
	for _, uri := range []string{"http://rp.example/logout", "https://rp.example/logout#frag", "ftp://rp.example/"} {
		st, body := e.send(e.alice, http.MethodPatch, "/api/admin/apps/alices", map[string]any{"backchannelLogoutUri": uri})
		wantError(t, uri, st, http.StatusBadRequest, body, "invalid")
	}

	st, body := e.send(e.alice, http.MethodPatch, "/api/admin/apps/alices", map[string]any{
		"backchannelLogoutUri": "https://rp.example/logout", "backchannelLogoutSessionRequired": true,
	})
	wantStatus(t, "set", st, http.StatusNoContent, body)
	st, body = e.send(e.alice, http.MethodGet, "/api/admin/apps/alices", nil)
	wantStatus(t, "get", st, http.StatusOK, body)
	app := body["app"].(map[string]any)
	if app["backchannelLogoutUri"] != "https://rp.example/logout" || app["backchannelLogoutSessionRequired"] != true ||
		body["backchannelPending"] != float64(0) {
		t.Fatalf("app detail %v pending %v", app, body["backchannelPending"])
	}
	entries, _ := e.auditPage(e.alice, "/api/admin/apps/alices/audit?event=app.update")
	if len(entries) != 1 || strings.Join(stringList(entries[0]["detail"].(map[string]any)["fields"]), ",") !=
		"backchannelLogoutUri,backchannelLogoutSessionRequired" {
		t.Fatalf("app.update entries %v", entries)
	}

	// Loopback http is allowed for development; "" turns it off.
	for _, uri := range []string{"http://127.0.0.1:9000/logout", ""} {
		st, body = e.send(e.alice, http.MethodPatch, "/api/admin/apps/alices", map[string]any{"backchannelLogoutUri": uri})
		wantStatus(t, "set "+uri, st, http.StatusNoContent, body)
	}
	st, body = e.send(e.alice, http.MethodGet, "/api/admin/apps", nil)
	wantStatus(t, "list", st, http.StatusOK, body)
	if a := body["apps"].([]any)[0].(map[string]any); a["backchannelLogoutUri"] != "" {
		t.Fatalf("listed app %v", a)
	}
}

func TestAuditLockout(t *testing.T) {
	e := newAdminEnv(t)
	for i := range 7 {
		st, body := e.postJSON(e.browser(), "/api/auth/login", map[string]any{"username": "alice", "password": "wrong password!"})
		want := http.StatusUnauthorized
		if i == 6 {
			want = http.StatusTooManyRequests
		}
		wantStatus(t, fmt.Sprintf("attempt %d", i+1), st, want, body)
	}
	locked, _ := e.auditPage(e.root, "/api/admin/audit?event=auth.locked")
	scopes := map[string]bool{}
	for _, x := range locked {
		d := x["detail"].(map[string]any)
		if refID(x["user"]) != e.user.ID || x["severity"] != "warning" || d["method"] != "password" ||
			d["lockoutSeconds"].(float64) <= 0 {
			t.Fatalf("lock-out entry %v", x)
		}
		scopes[d["scope"].(string)] = true
	}
	if len(locked) != 2 || !scopes["source"] || !scopes["account"] {
		t.Fatalf("lock-out entries %v", locked)
	}
	// The refused seventh attempt is covered by the lock-out, not logged again.
	if failed, _ := e.auditPage(e.root, "/api/admin/audit?event=auth.sign_in_failed"); len(failed) != 6 {
		t.Fatalf("%d failure entries, want 6", len(failed))
	}
}

func TestAuditAccountChanges(t *testing.T) {
	e := newAdminEnv(t)
	here, there := e.browser(), e.browser()
	e.passwordSignIn(here, "alice")
	e.passwordSignIn(there, "alice")
	secret, recovery, step := e.enrolTOTP(here)

	st, body := e.postJSON(here, "/api/account/recovery-codes", map[string]any{"code": totpAt(t, secret, step+1)})
	wantStatus(t, "recovery codes", st, http.StatusOK, body)
	recovery = append(recovery, stringList(body["recoveryCodes"])...)
	st, body = e.send(here, http.MethodPatch, "/api/account/profile", map[string]any{"displayName": "Alice L."})
	wantStatus(t, "profile", st, http.StatusNoContent, body)
	pk := e.addPasskey(e.user.ID, "laptop")
	st, body = e.send(here, http.MethodDelete, fmt.Sprintf("/api/account/passkeys/%d", pk.ID), nil)
	wantStatus(t, "passkey remove", st, http.StatusNoContent, body)
	_, sessions := e.send(here, http.MethodGet, "/api/account/sessions", nil)
	for _, x := range sessions["sessions"].([]any) {
		if s := x.(map[string]any); s["current"] != true {
			st, body = e.send(here, http.MethodDelete, fmt.Sprintf("/api/account/sessions/%d", int64(s["id"].(float64))), nil)
			wantStatus(t, "session revoke", st, http.StatusNoContent, body)
		}
	}
	st, body = e.postJSON(here, "/api/account/totp/disable", map[string]any{"code": recovery[len(recovery)-1]})
	wantStatus(t, "totp disable", st, http.StatusNoContent, body)
	st, body = e.postJSON(here, "/api/account/password",
		map[string]any{"currentPassword": testPassword, "newPassword": "a different long passphrase"})
	wantStatus(t, "password", st, http.StatusNoContent, body)

	entries, _ := e.auditPage(e.root, "/api/admin/audit?event=account.")
	var events []string
	for _, x := range entries {
		if refID(x["user"]) != e.user.ID || refID(x["actor"]) != e.user.ID || x["actorType"] != "user" {
			t.Fatalf("account entry %v", x)
		}
		events = append(events, strings.TrimPrefix(x["event"].(string), "account."))
	}
	// Two other sessions: there, and the one newAdminEnv opened for alice.
	want := "password_change totp_disable session_revoke session_revoke passkey_remove update recovery_codes totp_enable"
	if got := strings.Join(events, " "); got != want {
		t.Fatalf("account events %q, want %q", got, want)
	}
	if d := entries[4]["detail"].(map[string]any); d["name"] != "laptop" {
		t.Fatalf("passkey_remove detail %v", d)
	}

	rows, err := e.st.ListAudit(store.AuditQuery{Limit: store.AuditMaxLimit})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rows)
	for _, s := range append([]string{secret, "a different long passphrase"}, recovery...) {
		if strings.Contains(string(raw), s) {
			t.Fatalf("audit rows contain a secret %q", s)
		}
	}
}
