package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/store"
)

// regEnv is adminEnv plus one app per registration mode, all owned by root.
type regEnv struct {
	*adminEnv
	apps map[string]*store.App
}

func newRegEnv(t *testing.T) *regEnv {
	t.Helper()
	e := &regEnv{adminEnv: newAdminEnv(t), apps: map[string]*store.App{}}
	for _, a := range []struct{ slug, mode, access string }{
		{"open", store.RegOpen, store.AccessMembersOnly},
		{"approval", store.RegAdminApproval, store.AccessMembersOnly},
		{"invite", store.RegInvite, store.AccessMembersOnly},
		{"grouped", store.RegInvite, store.AccessGroups},
		{"gone", store.RegOpen, store.AccessMembersOnly},
		{"barred", store.RegOpen, store.AccessMembersOnly},
	} {
		app, _, err := e.st.CreateApp(store.NewApp{Slug: a.slug, Name: strings.ToUpper(a.slug[:1]) + a.slug[1:],
			OwnerUserID: e.oidcEnv.root.ID, RedirectURIs: []string{rpCallback},
			RegistrationMode: a.mode, DefaultAccess: a.access})
		if err != nil {
			t.Fatal(err)
		}
		e.apps[a.slug] = app
	}
	if err := e.st.SetAppStatus(e.apps["gone"].ID, store.AppSuspended); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetMembership(e.apps["barred"].ID, e.bob.ID, store.RoleMember, store.MemberBlocked, 0); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *regEnv) auditEvents(event string) []*store.AuditEntry {
	e.t.Helper()
	entries, err := e.st.ListAudit(store.AuditQuery{Event: event})
	if err != nil {
		e.t.Fatal(err)
	}
	return entries
}

func catalogStates(t *testing.T, body map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	list, _ := body["apps"].([]any)
	for _, x := range list {
		a := x.(map[string]any)
		out[a["slug"].(string)] = a["state"].(string) + "/" + a["join"].(string)
	}
	return out
}

func TestCatalogVisibility(t *testing.T) {
	e := newRegEnv(t)
	st, body := e.send(e.bobC, http.MethodGet, "/api/apps", nil)
	wantStatus(t, "catalog", st, http.StatusOK, body)
	got := catalogStates(t, body)
	want := map[string]string{"web": "allowed/", "cli": "allowed/", "open": "available/join",
		"approval": "available/request"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("bob's catalog %v, want %v", got, want)
	}
	list := body["apps"].([]any)
	if first := list[0].(map[string]any); first["name"] != "Approval" || first["description"] == nil ||
		first["homepageUrl"] == nil || first["logoUrl"] == nil {
		t.Fatalf("catalog entry %v", first)
	}

	st, body = e.send(e.root, http.MethodGet, "/api/apps", nil)
	wantStatus(t, "root catalog", st, http.StatusOK, body)
	for slug, s := range catalogStates(t, body) {
		if s != "allowed/" || slug == "gone" {
			t.Fatalf("root sees %s as %s", slug, s)
		}
	}

	st, body = e.send(e.bobC, http.MethodGet, "/api/apps/open", nil)
	wantStatus(t, "one app", st, http.StatusOK, body)
	if a := body["app"].(map[string]any); a["slug"] != "open" || a["state"] != "available" || a["join"] != "join" {
		t.Fatalf("one app %v", a)
	}
	for _, slug := range []string{"nope", "closed", "invite", "grouped", "gone", "barred"} {
		st, body = e.send(e.bobC, http.MethodGet, "/api/apps/"+slug, nil)
		wantError(t, "hidden "+slug, st, http.StatusNotFound, body, "not_found")
	}
	st, body = e.send(e.browser(), http.MethodGet, "/api/apps", nil)
	wantError(t, "signed out", st, http.StatusUnauthorized, body, "unauthenticated")
}

func TestSelfJoin(t *testing.T) {
	e := newRegEnv(t)
	for _, slug := range []string{"nope", "closed", "invite", "grouped", "gone", "barred"} {
		st, body := e.send(e.bobC, http.MethodPost, "/api/apps/"+slug+"/join", map[string]any{})
		wantError(t, "join "+slug, st, http.StatusNotFound, body, "not_found")
	}
	for _, slug := range []string{"web", "approval"} {
		st, body := e.send(e.bobC, http.MethodPost, "/api/apps/"+slug+"/join", map[string]any{})
		wantError(t, "join "+slug, st, http.StatusConflict, body, "conflict")
	}
	st, body := e.send(e.bobC, http.MethodPost, "/api/apps/open/join", map[string]any{})
	wantStatus(t, "join", st, http.StatusNoContent, body)
	if acc, _ := e.st.CanUseApp(e.apps["open"], e.bob); !acc.Allowed || acc.Role != store.RoleMember {
		t.Fatalf("after join %+v", acc)
	}
	st, body = e.send(e.bobC, http.MethodPost, "/api/apps/open/join", map[string]any{})
	wantError(t, "join twice", st, http.StatusConflict, body, "conflict")

	entries := e.auditEvents("app.self_join")
	if len(entries) != 1 || entries[0].AppID != e.apps["open"].ID || entries[0].UserID != e.bob.ID ||
		entries[0].ActorUserID != e.bob.ID || entries[0].ActorType != store.ActorUser {
		t.Fatalf("audit %+v", entries)
	}
}

func TestAccessRequestFlow(t *testing.T) {
	e := newRegEnv(t)
	// alice manages the approval app as an admin member, so she hears too.
	if err := e.st.SetMembership(e.apps["approval"].ID, e.user.ID, store.RoleAdmin, store.MemberActive, 0); err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"nope", "closed", "invite", "gone", "barred"} {
		st, body := e.send(e.bobC, http.MethodPost, "/api/apps/"+slug+"/request", map[string]any{})
		wantError(t, "request "+slug, st, http.StatusNotFound, body, "not_found")
	}
	st, body := e.send(e.bobC, http.MethodPost, "/api/apps/open/request", map[string]any{})
	wantError(t, "request on an open app", st, http.StatusConflict, body, "conflict")
	st, body = e.send(e.bobC, http.MethodPost, "/api/apps/approval/request",
		map[string]any{"message": strings.Repeat("x", 501)})
	wantError(t, "long message", st, http.StatusBadRequest, body, "invalid")

	before := e.mailer.count()
	const secretNote = "my-private-note-7731"
	st, body = e.send(e.bobC, http.MethodPost, "/api/apps/approval/request", map[string]any{"message": secretNote})
	wantStatus(t, "request", st, http.StatusCreated, body)
	reqID := int64(body["id"].(float64))
	e.auth.WaitForMail()
	if n := e.mailer.count() - before; n != 2 {
		t.Fatalf("%d manager notices, want 2 (owner and admin)", n)
	}
	e.mailer.mu.Lock()
	for _, m := range e.mailer.sent[before:] {
		if strings.Contains(m.body, secretNote) || !strings.Contains(m.body, "/admin/apps/approval") {
			t.Errorf("notice to %s: %q", m.to, m.body)
		}
	}
	e.mailer.mu.Unlock()
	if strings.Contains(e.logs.String(), secretNote) {
		t.Fatal("request message logged")
	}

	st, body = e.send(e.bobC, http.MethodGet, "/api/apps/approval", nil)
	if st != http.StatusOK || body["app"].(map[string]any)["state"] != "pending" {
		t.Fatalf("pending state: %d %v", st, body)
	}
	st, body = e.send(e.bobC, http.MethodPost, "/api/apps/approval/request", map[string]any{})
	wantError(t, "second request", st, http.StatusConflict, body, "conflict")

	// A denial removes the pending membership, so bob may ask again.
	path := fmt.Sprintf("/api/admin/apps/approval/access-requests/%d/decide", reqID)
	st, body = e.send(e.alice, http.MethodPost, path, map[string]any{"approve": false})
	wantStatus(t, "deny", st, http.StatusNoContent, body)
	if _, err := e.st.Membership(e.apps["approval"].ID, e.bob.ID); err == nil {
		t.Fatal("pending membership survived the denial")
	}
	st, body = e.send(e.bobC, http.MethodPost, "/api/apps/approval/request", map[string]any{})
	wantStatus(t, "ask again", st, http.StatusCreated, body)
	path = fmt.Sprintf("/api/admin/apps/approval/access-requests/%d/decide", int64(body["id"].(float64)))
	st, body = e.send(e.alice, http.MethodPost, path, map[string]any{"approve": true})
	wantStatus(t, "approve", st, http.StatusNoContent, body)
	if acc, _ := e.st.CanUseApp(e.apps["approval"], e.bob); !acc.Allowed {
		t.Fatalf("after approval %+v", acc)
	}
	_, body = e.send(e.bobC, http.MethodGet, "/api/apps/approval", nil)
	if body["app"].(map[string]any)["state"] != "allowed" {
		t.Fatalf("state after approval %v", body)
	}

	entries := e.auditEvents("app.access_request")
	if len(entries) != 2 || entries[0].UserID != e.bob.ID || entries[0].AppID != e.apps["approval"].ID {
		t.Fatalf("audit %+v", entries)
	}
}

// createInvite makes an invite as c and returns its id and token.
func (e *regEnv) createInvite(c *http.Client, slug string, req map[string]any) (int64, string) {
	e.t.Helper()
	st, body := e.send(c, http.MethodPost, "/api/admin/apps/"+slug+"/invites", req)
	wantStatus(e.t, "create invite", st, http.StatusCreated, body)
	link, _ := body["url"].(string)
	token, ok := strings.CutPrefix(link, e.issuer+"/invite/")
	if !ok || len(token) < 40 {
		e.t.Fatalf("invite url %q", link)
	}
	return int64(body["invite"].(map[string]any)["id"].(float64)), token
}

func TestInviteAdmin(t *testing.T) {
	e := newRegEnv(t)
	carol, _ := e.st.CreateUser(store.NewUser{Username: "carol", Email: "carol@example.com", Status: store.UserActive})
	if err := e.st.SetMembership(e.owned.ID, carol.ID, store.RoleAdmin, store.MemberActive, 0); err != nil {
		t.Fatal(err)
	}
	carolC := e.sessionFor(carol)

	st, body := e.send(e.bobC, http.MethodPost, "/api/admin/apps/alices/invites", map[string]any{})
	wantError(t, "stranger", st, http.StatusNotFound, body, "not_found")
	st, body = e.send(carolC, http.MethodPost, "/api/admin/apps/alices/invites", map[string]any{"role": "admin"})
	wantError(t, "app admin invites an admin", st, http.StatusForbidden, body, "forbidden")
	for _, bad := range []map[string]any{
		{"role": "owner"}, {"expiresInDays": 0}, {"expiresInDays": 31}, {"maxUses": 0}, {"maxUses": 101},
		{"email": "nope"},
	} {
		st, body = e.send(e.alice, http.MethodPost, "/api/admin/apps/alices/invites", bad)
		wantError(t, fmt.Sprint(bad), st, http.StatusBadRequest, body, "invalid")
	}

	before := e.mailer.count()
	st, body = e.send(e.alice, http.MethodPost, "/api/admin/apps/alices/invites",
		map[string]any{"email": "Dan@Example.com", "role": "admin", "expiresInDays": 3, "maxUses": 4})
	wantStatus(t, "create", st, http.StatusCreated, body)
	inv := body["invite"].(map[string]any)
	link := body["url"].(string)
	if inv["email"] != "dan@example.com" || inv["role"] != "admin" || inv["maxUses"] != 4.0 || inv["uses"] != 0.0 ||
		inv["revokedAt"] != nil || refID(inv["createdBy"]) != e.user.ID {
		t.Fatalf("invite %v", inv)
	}
	exp, _ := time.Parse(time.RFC3339, inv["expiresAt"].(string))
	if d := time.Until(exp); d < 71*time.Hour || d > 73*time.Hour {
		t.Fatalf("expires in %v", d)
	}
	e.auth.WaitForMail()
	if e.mailer.count() != before+1 || !strings.Contains(e.mailer.sent[before].body, link) ||
		e.mailer.sent[before].to != "dan@example.com" {
		t.Fatalf("invite mail %v", e.mailer.sent[before:])
	}
	token := strings.TrimPrefix(link, e.issuer+"/invite/")
	if strings.Contains(e.logs.String(), token) {
		t.Fatal("invite token logged")
	}

	id, _ := e.createInvite(carolC, "alices", map[string]any{})
	st, body = e.send(e.alice, http.MethodGet, "/api/admin/apps/alices/invites", nil)
	wantStatus(t, "list", st, http.StatusOK, body)
	list := body["invites"].([]any)
	if len(list) != 2 || refID(list[0]) != id || list[0].(map[string]any)["role"] != "member" ||
		strings.Contains(fmt.Sprint(body), token) {
		t.Fatalf("list %v", list)
	}
	st, body = e.send(e.bobC, http.MethodGet, "/api/admin/apps/alices/invites", nil)
	wantError(t, "stranger list", st, http.StatusNotFound, body, "not_found")
	st, body = e.send(e.alice, http.MethodDelete, fmt.Sprintf("/api/admin/apps/web/invites/%d", id), nil)
	wantError(t, "revoke through a foreign app", st, http.StatusNotFound, body, "not_found")
	st, body = e.send(e.root, http.MethodDelete, fmt.Sprintf("/api/admin/apps/web/invites/%d", id), nil)
	wantError(t, "revoke through another app", st, http.StatusNotFound, body, "not_found")
	st, body = e.send(e.alice, http.MethodDelete, fmt.Sprintf("/api/admin/apps/alices/invites/%d", id), nil)
	wantStatus(t, "revoke", st, http.StatusNoContent, body)
	_, body = e.send(e.alice, http.MethodGet, "/api/admin/apps/alices/invites", nil)
	if body["invites"].([]any)[0].(map[string]any)["revokedAt"] == nil {
		t.Fatalf("revoked invite %v", body)
	}

	created := e.auditEvents("app.invite_create")
	if len(created) != 2 || created[1].Detail["role"] != "admin" || created[1].Detail["maxUses"] != 4.0 ||
		strings.Contains(fmt.Sprint(created[1].Detail), token) {
		t.Fatalf("create audit %+v", created)
	}
	if revoked := e.auditEvents("app.invite_revoke"); len(revoked) != 1 || revoked[0].AppID != e.owned.ID {
		t.Fatalf("revoke audit %+v", revoked)
	}
}

func TestInviteAccept(t *testing.T) {
	e := newRegEnv(t)
	_, token := e.createInvite(e.alice, "alices", map[string]any{"maxUses": 2})

	st, body := e.send(e.browser(), http.MethodGet, "/api/invites/"+token, nil)
	wantStatus(t, "preview", st, http.StatusOK, body)
	if a := body["app"].(map[string]any); a["name"] != "Alice's app" || body["email"] != "" || body["expiresAt"] == "" ||
		a["slug"] != nil {
		t.Fatalf("preview %v", body)
	}
	st, body = e.send(e.browser(), http.MethodPost, "/api/invites/"+token+"/accept", map[string]any{})
	wantError(t, "signed out", st, http.StatusUnauthorized, body, "unauthenticated")

	st, body = e.send(e.bobC, http.MethodPost, "/api/invites/"+token+"/accept", map[string]any{})
	wantStatus(t, "accept", st, http.StatusOK, body)
	if a := body["app"].(map[string]any); a["slug"] != "alices" || a["name"] != "Alice's app" {
		t.Fatalf("accept %v", body)
	}
	if acc, _ := e.st.CanUseApp(e.owned, e.bob); !acc.Allowed || acc.Role != store.RoleMember {
		t.Fatalf("after accept %+v", acc)
	}
	acc := e.auditEvents("app.invite_accept")
	if len(acc) != 1 || acc[0].UserID != e.bob.ID || acc[0].AppID != e.owned.ID {
		t.Fatalf("accept audit %+v", acc)
	}
	carol, _ := e.st.CreateUser(store.NewUser{Username: "carol", Email: "carol@example.com", Status: store.UserActive})
	st, body = e.send(e.sessionFor(carol), http.MethodPost, "/api/invites/"+token+"/accept", map[string]any{})
	wantStatus(t, "second use", st, http.StatusOK, body)

	t.Run("used up", func(t *testing.T) {
		st, body := e.send(e.root, http.MethodPost, "/api/invites/"+token+"/accept", map[string]any{})
		wantError(t, "used up", st, http.StatusNotFound, body, "not_found")
		st, body = e.send(e.browser(), http.MethodGet, "/api/invites/"+token, nil)
		wantError(t, "preview used up", st, http.StatusNotFound, body, "not_found")
	})
	t.Run("revoked", func(t *testing.T) {
		id, tok := e.createInvite(e.alice, "alices", map[string]any{})
		e.send(e.alice, http.MethodDelete, fmt.Sprintf("/api/admin/apps/alices/invites/%d", id), nil)
		st, body := e.send(e.browser(), http.MethodGet, "/api/invites/"+tok, nil)
		wantError(t, "preview revoked", st, http.StatusNotFound, body, "not_found")
		st, body = e.send(e.root, http.MethodPost, "/api/invites/"+tok+"/accept", map[string]any{})
		wantError(t, "accept revoked", st, http.StatusNotFound, body, "not_found")
	})
	t.Run("email mismatch", func(t *testing.T) {
		_, tok := e.createInvite(e.alice, "alices", map[string]any{"email": "dan@example.com"})
		st, body := e.send(e.browser(), http.MethodGet, "/api/invites/"+tok, nil)
		if st != http.StatusOK || body["email"] != "dan@example.com" {
			t.Fatalf("preview %d %v", st, body)
		}
		st, body = e.send(e.root, http.MethodPost, "/api/invites/"+tok+"/accept", map[string]any{})
		wantError(t, "mismatch", st, http.StatusForbidden, body, "invite_email_mismatch")
		dan, _ := e.st.CreateUser(store.NewUser{Username: "dan", Email: "DAN@example.com", Status: store.UserActive})
		st, body = e.send(e.sessionFor(dan), http.MethodPost, "/api/invites/"+tok+"/accept", map[string]any{})
		wantStatus(t, "matching address", st, http.StatusOK, body)
	})
	t.Run("blocked", func(t *testing.T) {
		_, tok := e.createInvite(e.root, "barred", map[string]any{})
		st, body := e.send(e.bobC, http.MethodPost, "/api/invites/"+tok+"/accept", map[string]any{})
		wantError(t, "blocked", st, http.StatusForbidden, body, "blocked")
		if m, _ := e.st.Membership(e.apps["barred"].ID, e.bob.ID); m.Status != store.MemberBlocked {
			t.Fatalf("block lifted %+v", m)
		}
	})
	t.Run("suspended app", func(t *testing.T) {
		_, tok := e.createInvite(e.root, "gone", map[string]any{})
		st, body := e.send(e.browser(), http.MethodGet, "/api/invites/"+tok, nil)
		wantError(t, "preview suspended", st, http.StatusNotFound, body, "not_found")
	})
	t.Run("expired", func(t *testing.T) {
		_, tok := e.createInvite(e.alice, "alices", map[string]any{"expiresInDays": 1})
		e.shiftClock(25 * time.Hour)
		st, body := e.send(e.browser(), http.MethodGet, "/api/invites/"+tok, nil)
		wantError(t, "preview expired", st, http.StatusNotFound, body, "not_found")
	})
	if strings.Contains(e.logs.String(), token) {
		t.Fatal("invite token logged")
	}
}

func TestInviteLookupsThrottled(t *testing.T) {
	e := newRegEnv(t)
	c := e.browser()
	var st int
	var body map[string]any
	for i := 0; i < 12; i++ {
		st, body = e.send(c, http.MethodGet, fmt.Sprintf("/api/invites/guess-%d", i), nil)
	}
	wantError(t, "guessing", st, http.StatusTooManyRequests, body, "rate_limited")
}

func TestRegisterWithInvite(t *testing.T) {
	e := newRegEnv(t) // auth.registration is closed in the test config
	req := map[string]any{"username": "newbie", "email": "newbie@example.com", "password": testPassword}
	st, body := e.postJSON(e.browser(), "/api/register", req)
	wantError(t, "closed", st, http.StatusForbidden, body, "forbidden")

	req["invite"] = "not-a-real-invite"
	st, body = e.postJSON(e.browser(), "/api/register", req)
	wantError(t, "bad invite", st, http.StatusNotFound, body, "not_found")

	_, token := e.createInvite(e.alice, "alices", map[string]any{})
	req["invite"] = token
	st, body = e.postJSON(e.browser(), "/api/register", req)
	wantStatus(t, "invited", st, http.StatusCreated, body)
	if u := body["user"].(map[string]any); u["username"] != "newbie" || u["status"] != store.UserPending ||
		body["emailVerification"] != true {
		t.Fatalf("register %v", body)
	}
	// The invite was checked, not spent.
	if inv, err := e.st.InviteByToken(token); err != nil || inv.Uses != 0 {
		t.Fatalf("invite after register %+v %v", inv, err)
	}
	// The verification code activates the account, which can then accept.
	to, code, _ := e.lastMail()
	if to != "newbie@example.com" || code == "" {
		t.Fatalf("verification mail to %q", to)
	}
	c := e.browser()
	st, body = e.postJSON(c, "/api/auth/email/verify", map[string]any{"email": "newbie@example.com", "code": code})
	wantStatus(t, "verify", st, http.StatusOK, body)
	st, body = e.send(c, http.MethodPost, "/api/invites/"+token+"/accept", map[string]any{})
	wantStatus(t, "accept after register", st, http.StatusOK, body)

	req["username"], req["email"] = "newbie", "other@example.com"
	_, token = e.createInvite(e.alice, "alices", map[string]any{})
	req["invite"] = token
	st, body = e.postJSON(e.browser(), "/api/register", req)
	wantError(t, "taken", st, http.StatusConflict, body, "conflict")
	if strings.Contains(e.logs.String(), token) {
		t.Fatal("invite token logged")
	}
}

func TestRegisterOpen(t *testing.T) {
	e := newEnvWith(t, func(c *auth.Config) { c.Registration = "open" })
	st, body := e.postJSON(e.browser(), "/api/register", map[string]any{"username": "newbie",
		"email": "newbie@example.com", "password": testPassword, "displayName": "New"})
	wantStatus(t, "open", st, http.StatusCreated, body)
	st, body = e.postJSON(e.browser(), "/api/register", map[string]any{"username": "short",
		"email": "short@example.com", "password": "short"})
	wantError(t, "weak", st, http.StatusBadRequest, body, "weak_password")
	if n := len(func() []*store.AuditEntry {
		l, _ := e.st.ListAudit(store.AuditQuery{Event: "account.register"})
		return l
	}()); n != 1 {
		t.Fatalf("%d register audit entries", n)
	}
}

func TestDeniedOffersJoin(t *testing.T) {
	e := newRegEnv(t)
	params := func(app *store.App) url.Values {
		return url.Values{"client_id": {app.ClientID}, "redirect_uri": {rpCallback}, "scope": {"openid"},
			"state": {"s"}, "nonce": {"n"}}
	}
	c := e.signedIn() // alice
	loc := e.authorize(c, params(e.apps["open"]), false)
	q := loc.Query()
	if loc.Path != "/denied" || q.Get("app") != "open" || q.Get("reason") != store.ReasonNotPermitted ||
		q.Get("auth_req_id") == "" {
		t.Fatalf("open app refusal went to %s", loc)
	}
	// After joining, the same request resumes and reaches the client.
	st, body := e.send(c, http.MethodPost, "/api/apps/open/join", map[string]any{})
	wantStatus(t, "join", st, http.StatusNoContent, body)
	loc = location(t, e.get(c, "/login?auth_req_id="+url.QueryEscape(q.Get("auth_req_id"))), http.StatusFound)
	if loc.Path != "/authorize/callback" {
		t.Fatalf("resume went to %s", loc)
	}

	// A closed app still sends the error to the client, as does prompt=none.
	if loc := e.authorize(c, params(e.closed), false); loc.Query().Get("error") != "access_denied" {
		t.Fatalf("closed app refusal went to %s", loc)
	}
	p := params(e.apps["approval"])
	p.Set("prompt", "none")
	if loc := e.authorize(c, p, false); loc.Query().Get("error") != "access_denied" {
		t.Fatalf("prompt=none refusal went to %s", loc)
	}

	// The JSON sign-in reports the app and what can be done.
	b := e.browser()
	p = params(e.apps["approval"])
	p.Set("response_type", "code")
	loc = location(t, e.get(b, "/authorize?"+p.Encode()), http.StatusFound)
	st, body = e.postJSON(b, "/api/auth/login", map[string]any{"username": "alice", "password": testPassword,
		"authReqId": loc.Query().Get("auth_req_id")})
	wantStatus(t, "sign-in", st, http.StatusOK, body)
	if body["denied"] != store.ReasonNotPermitted || body["deniedApp"] != "approval" || body["join"] != "request" ||
		!strings.HasPrefix(body["redirectTo"].(string), e.issuer+"/denied?") {
		t.Fatalf("sign-in body %v", body)
	}
}

// The /denied detour is only for refusals the person can fix; it never
// replaces the protocol answer for prompt=none or for closed and invite apps.
func TestDeniedDetourLimits(t *testing.T) {
	e := newRegEnv(t)
	c := e.signedIn() // alice, no membership in any of these apps
	for _, tc := range []struct {
		app    *store.App
		prompt string
	}{
		{e.closed, ""}, {e.apps["invite"], ""}, {e.apps["grouped"], ""},
		{e.apps["open"], "none"}, {e.apps["approval"], "none"},
		{e.closed, "none"}, {e.apps["invite"], "none"},
	} {
		p := url.Values{"client_id": {tc.app.ClientID}, "redirect_uri": {rpCallback}, "scope": {"openid"},
			"state": {"s"}, "nonce": {"n"}}
		if tc.prompt != "" {
			p.Set("prompt", tc.prompt)
		}
		loc := e.authorize(c, p, false)
		if loc.Path == "/denied" || loc.Query().Get("error") != "access_denied" ||
			!strings.HasPrefix(loc.String(), rpCallback) {
			t.Errorf("%s prompt=%q went to %s", tc.app.Slug, tc.prompt, loc)
		}
	}
}
