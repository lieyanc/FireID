package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lieyanc/FireID/internal/store"
)

// send issues a JSON request with any method, as the UI would.
func (e *oidcEnv) send(c *http.Client, method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, e.abs(path), rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

// addPasskey stores a credential directly, standing in for a registration.
func (e *oidcEnv) addPasskey(userID int64, name string) *store.Passkey {
	e.t.Helper()
	p, err := e.st.CreatePasskey(&store.Passkey{UserID: userID, CredentialID: []byte("cred-" + name),
		PublicKey: []byte("pk"), Transports: "internal hybrid", Name: name, BackupEligible: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

func TestPasskeysNeedHostName(t *testing.T) {
	e := newOIDCEnv(t) // the issuer is http://127.0.0.1:port
	owner := e.browser()
	e.passwordSignIn(owner, "alice")

	st, body := e.postJSON(e.browser(), "/api/auth/login/passkey/begin", map[string]any{})
	wantError(t, "login begin", st, http.StatusNotFound, body, "passkeys_unavailable")
	st, body = e.postJSON(owner, "/api/account/passkeys/begin", map[string]any{"password": testPassword})
	wantError(t, "register begin", st, http.StatusNotFound, body, "passkeys_unavailable")
}

func TestPasskeyCeremonies(t *testing.T) {
	e := newOIDCEnv(t)
	// The RP ID must be a host name; the API's own origin check still uses
	// the 127.0.0.1 public base, which these requests satisfy by sending no
	// Origin.
	e.auth.SetIssuer(strings.Replace(e.issuer, "127.0.0.1", "localhost", 1))
	owner := e.browser()
	e.passwordSignIn(owner, "alice")

	t.Run("sign-in begin returns a ceremony", func(t *testing.T) {
		st, body := e.postJSON(e.browser(), "/api/auth/login/passkey/begin", map[string]any{})
		wantStatus(t, "begin", st, http.StatusOK, body)
		pk, _ := body["publicKey"].(map[string]any)
		if body["ceremonyId"] == "" || pk["challenge"] == nil || pk["rpId"] != "localhost" {
			t.Fatalf("ceremony %v", body)
		}
	})

	t.Run("an unknown ceremony is refused", func(t *testing.T) {
		st, body := e.postJSON(e.browser(), "/api/auth/login/passkey/finish",
			map[string]any{"ceremonyId": "nope", "response": map[string]any{}})
		wantError(t, "finish", st, http.StatusUnauthorized, body, "invalid_ceremony")
	})

	t.Run("a bad answer is invalid_credentials and uses the ceremony up", func(t *testing.T) {
		_, begin := e.postJSON(e.browser(), "/api/auth/login/passkey/begin", map[string]any{})
		req := map[string]any{"ceremonyId": begin["ceremonyId"], "response": map[string]any{"id": "x"}}
		st, body := e.postJSON(e.browser(), "/api/auth/login/passkey/finish", req)
		wantError(t, "finish", st, http.StatusUnauthorized, body, "invalid_credentials")
		st, body = e.postJSON(e.browser(), "/api/auth/login/passkey/finish", req)
		wantError(t, "replay", st, http.StatusUnauthorized, body, "invalid_ceremony")
	})

	t.Run("registration needs the password", func(t *testing.T) {
		st, body := e.postJSON(owner, "/api/account/passkeys/begin", map[string]any{"password": "wrong password!"})
		wantError(t, "begin", st, http.StatusUnauthorized, body, "invalid_credentials")
		st, body = e.postJSON(e.browser(), "/api/account/passkeys/begin", map[string]any{"password": testPassword})
		wantError(t, "anonymous", st, http.StatusUnauthorized, body, "unauthenticated")
	})

	t.Run("a registration is bound to the session that started it", func(t *testing.T) {
		st, begin := e.postJSON(owner, "/api/account/passkeys/begin", map[string]any{"password": testPassword})
		wantStatus(t, "begin", st, http.StatusOK, begin)
		pk, _ := begin["publicKey"].(map[string]any)
		if excl, _ := pk["user"].(map[string]any); excl["name"] != "alice" {
			t.Fatalf("creation options %v", pk)
		}
		other := e.browser()
		e.passwordSignIn(other, "alice")
		st, body := e.postJSON(other, "/api/account/passkeys/finish",
			map[string]any{"ceremonyId": begin["ceremonyId"], "name": "x", "response": map[string]any{}})
		wantError(t, "other session", st, http.StatusUnauthorized, body, "invalid_ceremony")
	})

	t.Run("an overlong name is refused before the ceremony is spent", func(t *testing.T) {
		_, begin := e.postJSON(owner, "/api/account/passkeys/begin", map[string]any{"password": testPassword})
		st, body := e.postJSON(owner, "/api/account/passkeys/finish", map[string]any{
			"ceremonyId": begin["ceremonyId"], "name": strings.Repeat("n", store.PasskeyNameMaxLen+1),
			"response": map[string]any{}})
		wantError(t, "finish", st, http.StatusBadRequest, body, "invalid")
	})
}

func TestAccountPasskeys(t *testing.T) {
	e := newOIDCEnv(t)
	owner := e.browser()
	e.passwordSignIn(owner, "alice")
	mine := e.addPasskey(e.user.ID, "MacBook")
	theirs := e.addPasskey(e.root.ID, "Root key")

	st, body := e.send(owner, http.MethodGet, "/api/account/passkeys", nil)
	wantStatus(t, "list", st, http.StatusOK, body)
	list, _ := body["passkeys"].([]any)
	if len(list) != 1 {
		t.Fatalf("passkeys %v", body)
	}
	p := list[0].(map[string]any)
	if p["name"] != "MacBook" || p["backupEligible"] != true || p["lastUsedAt"] != "" ||
		strings.Join(stringList(p["transports"]), " ") != "internal hybrid" {
		t.Fatalf("passkey %v", p)
	}
	if _, leaked := p["publicKey"]; leaked {
		t.Fatal("key material in the response")
	}

	path := fmt.Sprintf("/api/account/passkeys/%d", mine.ID)
	st, body = e.postJSON(owner, path+"/rename", map[string]any{"name": "Work laptop"})
	wantStatus(t, "rename", st, http.StatusNoContent, body)
	st, body = e.postJSON(owner, path+"/rename", map[string]any{"name": strings.Repeat("n", 65)})
	wantError(t, "long name", st, http.StatusBadRequest, body, "invalid")
	st, body = e.postJSON(owner, fmt.Sprintf("/api/account/passkeys/%d/rename", theirs.ID), map[string]any{"name": "x"})
	wantError(t, "foreign rename", st, http.StatusNotFound, body, "not_found")
	st, body = e.send(owner, http.MethodDelete, fmt.Sprintf("/api/account/passkeys/%d", theirs.ID), nil)
	wantError(t, "foreign delete", st, http.StatusNotFound, body, "not_found")
	st, body = e.send(owner, http.MethodDelete, "/api/account/passkeys/abc", nil)
	wantError(t, "bad id", st, http.StatusNotFound, body, "not_found")

	st, body = e.send(owner, http.MethodDelete, path, nil)
	wantStatus(t, "delete", st, http.StatusNoContent, body)
	if n, _ := e.st.CountPasskeys(e.user.ID); n != 0 {
		t.Fatalf("%d passkeys left", n)
	}
}

func TestLastCredential(t *testing.T) {
	e := newOIDCEnv(t)
	// Without email there is no way back in once the only passkey is gone.
	e.mailer.mu.Lock()
	e.mailer.enabled = false
	e.mailer.mu.Unlock()
	owner := e.browser()
	e.passwordSignIn(owner, "alice")
	only := e.addPasskey(e.user.ID, "only")
	if err := e.st.ClearPassword(e.user.ID); err != nil {
		t.Fatal(err)
	}
	// Clearing the password ended the session; sign in again as if by passkey.
	owner = e.sessionFor(e.user)

	st, body := e.send(owner, http.MethodDelete, fmt.Sprintf("/api/account/passkeys/%d", only.ID), nil)
	wantError(t, "delete", st, http.StatusConflict, body, "last_credential")
}

// sessionFor signs a browser in directly, standing in for a sign-in method the
// tests cannot drive.
func (e *oidcEnv) sessionFor(u *store.User) *http.Client {
	e.t.Helper()
	token, sess, err := e.st.CreateSession(u.ID, 3600e9, "127.0.0.1", "test", "webauthn", store.ACRLoA2)
	if err != nil {
		e.t.Fatal(err)
	}
	c := e.browser()
	req, _ := http.NewRequest(http.MethodGet, e.issuer, nil)
	c.Jar.SetCookies(req.URL, []*http.Cookie{{Name: "fireid_session", Value: token, Path: "/", Expires: sess.ExpiresAt}})
	return c
}

func TestAccountSessions(t *testing.T) {
	e := newOIDCEnv(t)
	here, there := e.browser(), e.browser()
	e.passwordSignIn(here, "alice")
	e.passwordSignIn(there, "alice")
	e.passwordSignIn(e.browser(), "root")

	st, body := e.send(here, http.MethodGet, "/api/account/sessions", nil)
	wantStatus(t, "list", st, http.StatusOK, body)
	list, _ := body["sessions"].([]any)
	if len(list) != 2 {
		t.Fatalf("sessions %v", body)
	}
	var current, other int64
	for _, x := range list {
		s := x.(map[string]any)
		id := int64(s["id"].(float64))
		if s["current"] == true {
			current = id
		} else {
			other = id
		}
		if strings.Join(stringList(s["amr"]), " ") != "pwd" || s["ip"] != "127.0.0.1" || s["expiresAt"] == "" {
			t.Fatalf("session %v", s)
		}
	}
	if current == 0 || other == 0 || int64(e.me(here)["sessionId"].(float64)) != current {
		t.Fatalf("current %d other %d", current, other)
	}

	st, body = e.send(here, http.MethodDelete, fmt.Sprintf("/api/account/sessions/%d", current), nil)
	wantError(t, "revoke current", st, http.StatusConflict, body, "cannot_revoke_current")
	st, body = e.send(there, http.MethodDelete, fmt.Sprintf("/api/account/sessions/%d", other+1), nil)
	wantError(t, "foreign session", st, http.StatusNotFound, body, "not_found")

	st, body = e.send(here, http.MethodDelete, fmt.Sprintf("/api/account/sessions/%d", other), nil)
	wantStatus(t, "revoke", st, http.StatusNoContent, body)
	st, body = e.send(there, http.MethodGet, "/api/account/sessions", nil)
	wantError(t, "revoked browser", st, http.StatusUnauthorized, body, "unauthenticated")
	st, body = e.send(here, http.MethodDelete, fmt.Sprintf("/api/account/sessions/%d", other), nil)
	wantError(t, "revoke twice", st, http.StatusNotFound, body, "not_found")
}

func TestAccountProfile(t *testing.T) {
	e := newOIDCEnv(t)
	owner := e.browser()
	e.passwordSignIn(owner, "alice")

	st, body := e.send(owner, http.MethodPatch, "/api/account/profile", map[string]any{"displayName": "  Alice L.  "})
	wantStatus(t, "patch", st, http.StatusNoContent, body)
	if u := e.me(owner)["user"].(map[string]any); u["displayName"] != "Alice L." {
		t.Fatalf("display name %v", u["displayName"])
	}
	st, body = e.send(owner, http.MethodPatch, "/api/account/profile", map[string]any{"displayName": strings.Repeat("x", 500)})
	wantError(t, "long", st, http.StatusBadRequest, body, "invalid")
	st, body = e.send(owner, http.MethodPatch, "/api/account/profile", map[string]any{"username": "mallory"})
	wantError(t, "username", st, http.StatusBadRequest, body, "invalid_body")
}

func TestAccountPassword(t *testing.T) {
	e := newOIDCEnv(t)
	here, there := e.browser(), e.browser()
	e.passwordSignIn(here, "alice")
	e.passwordSignIn(there, "alice")
	const next = "a different long passphrase"

	st, body := e.postJSON(here, "/api/account/password",
		map[string]any{"currentPassword": "wrong password!", "newPassword": next})
	wantError(t, "wrong current", st, http.StatusUnauthorized, body, "invalid_credentials")
	st, body = e.postJSON(here, "/api/account/password",
		map[string]any{"currentPassword": testPassword, "newPassword": "short"})
	wantError(t, "weak", st, http.StatusBadRequest, body, "weak_password")

	st, body = e.postJSON(here, "/api/account/password",
		map[string]any{"currentPassword": testPassword, "newPassword": next})
	wantStatus(t, "change", st, http.StatusNoContent, body)

	e.me(here) // still signed in
	st, body = e.send(there, http.MethodGet, "/api/account/sessions", nil)
	wantError(t, "other browser", st, http.StatusUnauthorized, body, "unauthenticated")
	st, body = e.postJSON(e.browser(), "/api/auth/login", map[string]any{"username": "alice", "password": testPassword})
	wantError(t, "old password", st, http.StatusUnauthorized, body, "invalid_credentials")
	st, body = e.postJSON(e.browser(), "/api/auth/login", map[string]any{"username": "alice", "password": next})
	wantStatus(t, "new password", st, http.StatusOK, body)
}

func TestAccountRevokeOtherSessions(t *testing.T) {
	e := newOIDCEnv(t)
	here, there, admin := e.browser(), e.browser(), e.browser()
	e.passwordSignIn(here, "alice")
	e.passwordSignIn(admin, "root")
	// there also signs in to an app and holds a refresh token.
	cb := e.authorize(there, e.webParams("openid offline_access"), true)
	resp, tok := e.exchangeWeb(cb.Query().Get("code"))
	if resp.StatusCode != http.StatusOK || tok["refresh_token"] == nil {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}

	// Cross-site and unauthenticated requests are refused.
	req, _ := http.NewRequest(http.MethodPost, e.issuer+"/api/account/sessions/revoke-others", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	cross, err := here.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cross.Body.Close()
	if cross.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site: status %d", cross.StatusCode)
	}
	st, body := e.postJSON(e.browser(), "/api/account/sessions/revoke-others", map[string]any{})
	wantError(t, "signed out", st, http.StatusUnauthorized, body, "unauthenticated")
	e.me(there) // still signed in

	st, body = e.postJSON(here, "/api/account/sessions/revoke-others", map[string]any{})
	wantStatus(t, "revoke others", st, http.StatusNoContent, body)
	e.me(here)
	e.me(admin) // another account is untouched
	st, body = e.send(there, http.MethodGet, "/api/account/sessions", nil)
	wantError(t, "other browser", st, http.StatusUnauthorized, body, "unauthenticated")
	st, body = e.send(here, http.MethodGet, "/api/account/sessions", nil)
	if list, _ := body["sessions"].([]any); st != http.StatusOK || len(list) != 1 {
		t.Fatalf("sessions left: %d %v", st, body)
	}
	resp, next := e.postForm(http.DefaultClient, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)},
		"client_id": {e.web.ClientID}, "client_secret": {e.webSecret},
	}, "", "")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("refresh after revoke-others: %v", next)
	}

	rows, err := e.st.ListAudit(store.AuditQuery{Event: "account.sessions_revoke_others"})
	if err != nil || len(rows) != 1 || rows[0].UserID != e.user.ID || rows[0].ActorUserID != e.user.ID ||
		rows[0].ActorType != store.ActorUser {
		t.Fatalf("audit rows %+v %v", rows, err)
	}
}
