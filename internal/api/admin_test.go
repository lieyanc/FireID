package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lieyanc/FireID/internal/store"
)

// adminEnv adds an app owned by alice, and bob, a user with no relationship
// to it, to the standard environment.
type adminEnv struct {
	*oidcEnv
	bob   *store.User
	owned *store.App
	alice *http.Client
	root  *http.Client
	bobC  *http.Client
}

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	e := &adminEnv{oidcEnv: newOIDCEnv(t)}
	var err error
	e.bob, err = e.st.CreateUser(store.NewUser{Username: "bob", Email: "bob@example.com", Status: store.UserActive})
	if err != nil {
		t.Fatal(err)
	}
	e.owned, _, err = e.st.CreateApp(store.NewApp{Slug: "alices", Name: "Alice's app",
		OwnerUserID: e.user.ID, RedirectURIs: []string{rpCallback}})
	if err != nil {
		t.Fatal(err)
	}
	e.alice, e.root, e.bobC = e.sessionFor(e.user), e.sessionFor(e.oidcEnv.root), e.sessionFor(e.bob)
	return e
}

func appSlugs(t *testing.T, body map[string]any) []string {
	t.Helper()
	list, ok := body["apps"].([]any)
	if !ok {
		t.Fatalf("no apps list in %v", body)
	}
	var out []string
	for _, a := range list {
		out = append(out, a.(map[string]any)["slug"].(string))
	}
	return out
}

func TestAppsListOwnerSeesOnlyTheirs(t *testing.T) {
	e := newAdminEnv(t)
	st, body := e.send(e.alice, http.MethodGet, "/api/admin/apps", nil)
	wantStatus(t, "owner list", st, http.StatusOK, body)
	if got := appSlugs(t, body); len(got) != 1 || got[0] != "alices" {
		t.Fatalf("owner sees %v", got)
	}
	st, body = e.send(e.root, http.MethodGet, "/api/admin/apps", nil)
	wantStatus(t, "super list", st, http.StatusOK, body)
	if got := appSlugs(t, body); len(got) != 4 {
		t.Fatalf("super sees %v", got)
	}
	st, body = e.send(e.bobC, http.MethodGet, "/api/admin/apps", nil)
	if st == http.StatusOK && len(appSlugs(t, body)) != 0 {
		t.Fatalf("stranger sees %v", body)
	}
	// Another owner's app answers 404, not 403, so slugs cannot be probed.
	st, body = e.send(e.alice, http.MethodGet, "/api/admin/apps/web", nil)
	wantError(t, "foreign app", st, http.StatusNotFound, body, "not_found")
	st, body = e.send(e.alice, http.MethodGet, "/api/admin/apps/alices", nil)
	wantStatus(t, "own app", st, http.StatusOK, body)
	app := body["app"].(map[string]any)
	if app["clientId"] != e.owned.ClientID || app["clientSecret"] != nil || app["secretHash"] != nil {
		t.Fatalf("app body %v", app)
	}
	me := e.me(e.alice)
	if p := me["permissions"].(map[string]any); p["manageApps"] != true || p["createApps"] == true {
		t.Fatalf("owner permissions %v", p)
	}
}

func TestCreateAppReturnsSecret(t *testing.T) {
	e := newAdminEnv(t)
	req := map[string]any{"slug": "new-app", "name": "New", "redirectUris": []string{"https://new.example/cb"},
		"tokenEndpointAuthMethod": "client_secret_post", "ownerUserId": e.user.ID}
	st, body := e.send(e.alice, http.MethodPost, "/api/admin/apps", req)
	if st != http.StatusForbidden {
		t.Fatalf("owner created an app: %d %v", st, body)
	}
	st, body = e.send(e.root, http.MethodPost, "/api/admin/apps", req)
	wantStatus(t, "create", st, http.StatusCreated, body)
	secret, _ := body["clientSecret"].(string)
	app := body["app"].(map[string]any)
	if secret == "" || app["slug"] != "new-app" || int64(app["ownerUserId"].(float64)) != e.user.ID {
		t.Fatalf("create body %v", body)
	}
	a, err := e.st.AppBySlug("new-app")
	if err != nil || a.SecretHash != store.HashToken(secret) {
		t.Fatalf("stored app %+v %v", a, err)
	}
	// The secret is not shown again.
	_, body = e.send(e.alice, http.MethodGet, "/api/admin/apps/new-app", nil)
	if strings.Contains(fmt.Sprint(body), secret) {
		t.Fatal("secret appeared in a later read")
	}
	for _, bad := range []map[string]any{
		{"slug": "Bad Slug", "name": "x", "redirectUris": []string{"https://x.example/cb"}},
		{"slug": "ok", "name": "x", "redirectUris": []string{"http://x.example/cb"}},
		{"slug": "ok", "name": "x", "redirectUris": []string{"https://x.example/cb"}, "unknown": 1},
	} {
		if st, body := e.send(e.root, http.MethodPost, "/api/admin/apps", bad); st != http.StatusBadRequest {
			t.Errorf("accepted %v: %d %v", bad, st, body)
		}
	}
	if st, _ := e.send(e.root, http.MethodPost, "/api/admin/apps", req); st != http.StatusConflict {
		t.Fatalf("duplicate slug: %d", st)
	}
}

func TestRotateSecretAndStatus(t *testing.T) {
	e := newAdminEnv(t)
	old, _ := e.st.AppBySlug("alices")
	st, body := e.send(e.alice, http.MethodPost, "/api/admin/apps/alices/secret/rotate", map[string]any{})
	wantStatus(t, "rotate", st, http.StatusOK, body)
	secret, _ := body["clientSecret"].(string)
	now, _ := e.st.AppBySlug("alices")
	if secret == "" || now.SecretHash == old.SecretHash || now.SecretHash != store.HashToken(secret) {
		t.Fatal("secret not rotated")
	}
	st, body = e.send(e.alice, http.MethodPost, "/api/admin/apps/alices/status", map[string]any{"status": "suspended"})
	wantStatus(t, "suspend", st, http.StatusNoContent, body)
	if a, _ := e.st.AppBySlug("alices"); a.Status != store.AppSuspended {
		t.Fatalf("status %q", a.Status)
	}
	st, _ = e.send(e.bobC, http.MethodPost, "/api/admin/apps/alices/status", map[string]any{"status": "active"})
	if st != http.StatusNotFound {
		t.Fatalf("stranger changed status: %d", st)
	}
	name := "Renamed"
	st, body = e.send(e.alice, http.MethodPatch, "/api/admin/apps/alices", map[string]any{"name": name,
		"registrationMode": "admin_approval"})
	wantStatus(t, "patch", st, http.StatusNoContent, body)
	if a, _ := e.st.AppBySlug("alices"); a.Name != name || a.RegistrationMode != store.RegAdminApproval {
		t.Fatalf("after patch %+v", a)
	}
}

func TestAppOwnerCanAddMember(t *testing.T) {
	e := newAdminEnv(t)
	acc, _ := e.st.CanUseApp(e.owned, e.bob)
	if acc.Allowed {
		t.Fatal("bob allowed before membership")
	}
	st, body := e.send(e.alice, http.MethodPost, "/api/admin/apps/alices/members",
		map[string]any{"userId": e.bob.ID, "role": "member", "status": "active"})
	wantStatus(t, "add", st, http.StatusCreated, body)
	acc, _ = e.st.CanUseApp(e.owned, e.bob)
	if !acc.Allowed || acc.Reason != "member" {
		t.Fatalf("after add: %+v", acc)
	}
	st, body = e.send(e.alice, http.MethodGet, "/api/admin/apps/alices/members", nil)
	wantStatus(t, "list", st, http.StatusOK, body)
	if members, _ := body["members"].([]any); len(members) != 2 {
		t.Fatalf("members %v", body)
	}
	// The owner's own row is not editable here.
	st, _ = e.send(e.alice, http.MethodPost, "/api/admin/apps/alices/members",
		map[string]any{"userId": e.user.ID, "role": "member", "status": "blocked"})
	if st != http.StatusBadRequest {
		t.Fatalf("owner demoted: %d", st)
	}
	st, body = e.send(e.alice, http.MethodDelete, fmt.Sprintf("/api/admin/apps/alices/members/%d", e.bob.ID), nil)
	wantStatus(t, "remove", st, http.StatusNoContent, body)
	if acc, _ = e.st.CanUseApp(e.owned, e.bob); acc.Allowed {
		t.Fatal("bob still allowed")
	}
}

func TestNonOwnerCannotAddMember(t *testing.T) {
	e := newAdminEnv(t)
	st, _ := e.send(e.bobC, http.MethodPost, "/api/admin/apps/alices/members",
		map[string]any{"userId": e.bob.ID, "role": "admin", "status": "active"})
	if st != http.StatusNotFound && st != http.StatusForbidden {
		t.Fatalf("stranger added themselves: %d", st)
	}
	if _, err := e.st.Membership(e.owned.ID, e.bob.ID); err == nil {
		t.Fatal("membership created")
	}
	// An app admin may not hand out the owner role.
	if err := e.st.SetMembership(e.owned.ID, e.bob.ID, store.RoleAdmin, store.MemberActive, e.user.ID); err != nil {
		t.Fatal(err)
	}
	st, _ = e.send(e.bobC, http.MethodPost, "/api/admin/apps/alices/members",
		map[string]any{"userId": e.bob.ID, "role": "owner", "status": "active"})
	if st != http.StatusForbidden && st != http.StatusBadRequest {
		t.Fatalf("app admin made themselves owner: %d", st)
	}
	// Cross-site requests are refused before anything else.
	req, _ := http.NewRequest(http.MethodPost, e.issuer+"/api/admin/apps/alices/members",
		strings.NewReader(fmt.Sprintf(`{"userId":%d,"role":"member","status":"active"}`, e.bob.ID)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := e.alice.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site add: %d", resp.StatusCode)
	}
}

func TestApproveAccessRequestCreatesActiveMembership(t *testing.T) {
	e := newAdminEnv(t)
	req, err := e.st.CreateAccessRequest(e.owned.ID, e.bob.ID, "let me in")
	if err != nil {
		t.Fatal(err)
	}
	st, body := e.send(e.alice, http.MethodGet, "/api/admin/apps/alices/access-requests", nil)
	wantStatus(t, "list", st, http.StatusOK, body)
	reqs, _ := body["requests"].([]any)
	if len(reqs) != 1 || reqs[0].(map[string]any)["message"] != "let me in" {
		t.Fatalf("requests %v", body)
	}
	// Deciding through an app the request does not belong to finds nothing.
	path := fmt.Sprintf("/api/admin/apps/web/access-requests/%d/decide", req.ID)
	if st, _ := e.send(e.root, http.MethodPost, path, map[string]any{"approve": true}); st != http.StatusNotFound {
		t.Fatalf("decided through another app: %d", st)
	}
	before := e.mailer.count()
	path = fmt.Sprintf("/api/admin/apps/alices/access-requests/%d/decide", req.ID)
	st, body = e.send(e.alice, http.MethodPost, path, map[string]any{"approve": true})
	wantStatus(t, "approve", st, http.StatusNoContent, body)
	acc, _ := e.st.CanUseApp(e.owned, e.bob)
	if !acc.Allowed || acc.Reason != "member" {
		t.Fatalf("after approval %+v", acc)
	}
	if st, _ := e.send(e.alice, http.MethodPost, path, map[string]any{"approve": false}); st != http.StatusConflict {
		t.Fatalf("second decision: %d", st)
	}
	e.auth.WaitForMail()
	if e.mailer.count() != before+1 {
		t.Fatal("no notice sent")
	}
	to, subject, _ := e.lastNotice()
	if to != "bob@example.com" || !strings.Contains(subject, "approved") {
		t.Fatalf("notice %q %q", to, subject)
	}
}

func TestGroupsRequireSuperAdmin(t *testing.T) {
	e := newAdminEnv(t)
	st, _ := e.send(e.alice, http.MethodPost, "/api/admin/groups", map[string]any{"name": "friends", "description": ""})
	if st != http.StatusForbidden {
		t.Fatalf("owner created a group: %d", st)
	}
	st, body := e.send(e.root, http.MethodPost, "/api/admin/groups", map[string]any{"name": "friends", "description": "f"})
	wantStatus(t, "create", st, http.StatusCreated, body)
	gid := int64(body["group"].(map[string]any)["id"].(float64))

	st, body = e.send(e.root, http.MethodPost, fmt.Sprintf("/api/admin/groups/%d/members", gid),
		map[string]any{"userIds": []int64{e.bob.ID}})
	wantStatus(t, "members", st, http.StatusNoContent, body)
	if st, _ := e.send(e.alice, http.MethodPost, fmt.Sprintf("/api/admin/groups/%d/members", gid),
		map[string]any{"userIds": []int64{e.user.ID}}); st != http.StatusForbidden {
		t.Fatalf("owner changed group members: %d", st)
	}
	// Owners may read the list to grant a group to their app.
	st, body = e.send(e.alice, http.MethodGet, "/api/admin/groups", nil)
	wantStatus(t, "owner list", st, http.StatusOK, body)
	if st, _ := e.send(e.bobC, http.MethodGet, "/api/admin/groups", nil); st != http.StatusForbidden {
		t.Fatalf("stranger listed groups: %d", st)
	}
	st, body = e.send(e.alice, http.MethodPost, "/api/admin/apps/alices/groups", map[string]any{"groupIds": []int64{gid}})
	wantStatus(t, "grant", st, http.StatusNoContent, body)
	acc, _ := e.st.CanUseApp(e.owned, e.bob)
	if !acc.Allowed || acc.Reason != "group" {
		t.Fatalf("group access %+v", acc)
	}
}

func TestUserSearchRespectsDelegation(t *testing.T) {
	e := newAdminEnv(t)
	search := func(c *http.Client, q string) (int, []any) {
		st, body := e.send(c, http.MethodGet, "/api/admin/users/search?q="+url.QueryEscape(q), nil)
		users, _ := body["users"].([]any)
		return st, users
	}
	if st, users := search(e.root, "b"); st != http.StatusOK || len(users) != 1 {
		t.Fatalf("super prefix search: %d %v", st, users)
	}
	if st, users := search(e.alice, "b"); st != http.StatusOK || len(users) != 0 {
		t.Fatalf("owner prefix search leaked: %d %v", st, users)
	}
	if st, users := search(e.alice, "bob@example.com"); st != http.StatusOK || len(users) != 1 {
		t.Fatalf("owner exact search: %d %v", st, users)
	}
	if st, _ := search(e.bobC, "alice"); st != http.StatusForbidden {
		t.Fatalf("stranger searched: %d", st)
	}
}
