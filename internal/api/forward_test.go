package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lieyanc/FireID/internal/store"
)

const siteOrigin = "https://site.example"

// forwardEnv is the standard environment plus an app protecting
// https://site.example through forward auth.
type forwardEnv struct {
	*oidcEnv
	app *store.App
}

func newForwardEnv(t *testing.T, access string) *forwardEnv {
	t.Helper()
	e := &forwardEnv{oidcEnv: newOIDCEnv(t)}
	var err error
	e.app, _, err = e.st.CreateApp(store.NewApp{Slug: "site", Name: "Site", OwnerUserID: e.root.ID,
		RedirectURIs: []string{siteOrigin + "/__fireid/callback"}, DefaultAccess: access})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// viaProxy sends a request as nginx would for the site: to FireID's
// backend path, carrying the headers the include sets.
func (e *forwardEnv) viaProxy(c *http.Client, backendPath, originalURL string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.issuer+backendPath, nil)
	req.Header.Set("X-FireID-App", e.app.Slug)
	req.Header.Set("X-Original-URL", originalURL)
	// The browser's cookies for the site's host live under siteOrigin in the jar.
	site, _ := url.Parse(siteOrigin)
	for _, ck := range c.Jar.Cookies(site) {
		req.AddCookie(ck)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	// Cookies the backend set belong to the site's host.
	if cs := resp.Cookies(); len(cs) > 0 {
		c.Jar.SetCookies(site, cs)
	}
	return resp
}

// signInToSite drives the whole hop for a browser already signed in at the
// IdP, and returns the final redirect target.
func (e *forwardEnv) signInToSite(c *http.Client, want string) *url.URL {
	e.t.Helper()
	resp := e.viaProxy(c, "/api/authz/forward", want)
	if resp.StatusCode != http.StatusUnauthorized {
		e.t.Fatalf("forward before sign-in: %d", resp.StatusCode)
	}
	start, _ := url.Parse(resp.Header.Get("Location"))
	if start.Scheme+"://"+start.Host != siteOrigin || start.Path != "/__fireid/start" {
		e.t.Fatalf("start location %v", start)
	}
	resp = e.viaProxy(c, "/api/authz/app/start?"+start.RawQuery, start.String())
	authz := location(e.t, resp, http.StatusFound)
	resp = e.get(c, authz.RequestURI())
	cb := location(e.t, resp, http.StatusFound)
	if cb.Scheme+"://"+cb.Host != siteOrigin || cb.Path != "/__fireid/callback" {
		e.t.Fatalf("callback location %v", cb)
	}
	resp = e.viaProxy(c, "/api/authz/app/callback?"+cb.RawQuery, cb.String())
	return location(e.t, resp, http.StatusFound)
}

func TestForwardAuthFlow(t *testing.T) {
	e := newForwardEnv(t, store.AccessAllUsers)
	c := e.browser()
	e.passwordSignIn(c, "alice")

	back := e.signInToSite(c, siteOrigin+"/docs?page=2")
	if back.String() != siteOrigin+"/docs?page=2" {
		t.Fatalf("returned to %v", back)
	}
	resp := e.viaProxy(c, "/api/authz/forward", siteOrigin+"/docs?page=2")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("forward after sign-in: %d", resp.StatusCode)
	}
	h := resp.Header
	if h.Get("X-FireID-User") != "alice" || h.Get("X-FireID-Email") != "alice@example.com" ||
		h.Get("X-FireID-Name") != "Alice" || h.Get("X-FireID-Sub") == "" {
		t.Fatalf("identity headers %v", h)
	}

	// The site's cookie is only good for this app.
	other, _, err := e.st.CreateApp(store.NewApp{Slug: "other", Name: "Other", OwnerUserID: e.root.ID,
		RedirectURIs: []string{siteOrigin + "/__fireid/callback"}, DefaultAccess: store.AccessAllUsers})
	if err != nil {
		t.Fatal(err)
	}
	saved := e.app
	e.app = other
	if resp := e.viaProxy(c, "/api/authz/forward", siteOrigin+"/"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cookie accepted by another app: %d", resp.StatusCode)
	}
	e.app = saved

	// Signing out at the IdP ends the site session too.
	if st, body := e.postJSON(c, "/api/auth/logout", map[string]any{}); st != http.StatusOK && st != http.StatusNoContent {
		t.Fatalf("logout %d %v", st, body)
	}
	if resp := e.viaProxy(c, "/api/authz/forward", siteOrigin+"/"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("site session outlived the IdP session: %d", resp.StatusCode)
	}
}

func TestForwardAuthAccessRules(t *testing.T) {
	e := newForwardEnv(t, store.AccessMembersOnly)
	c := e.browser()
	e.passwordSignIn(c, "alice")

	// Not a member: the IdP refuses and sends the browser to the denied page.
	resp := e.viaProxy(c, "/api/authz/forward", siteOrigin+"/")
	start, _ := url.Parse(resp.Header.Get("Location"))
	resp = e.viaProxy(c, "/api/authz/app/start?"+start.RawQuery, start.String())
	authz := location(t, resp, http.StatusFound)
	denied := location(t, e.get(c, authz.RequestURI()), http.StatusFound)
	if denied.Path != "/denied" || denied.Query().Get("reason") != store.ReasonNotPermitted {
		t.Fatalf("denied location %v", denied)
	}

	// A member gets in; blocking them later shuts the site at the next request.
	if err := e.st.SetMembership(e.app.ID, e.user.ID, store.RoleMember, store.MemberActive, e.root.ID); err != nil {
		t.Fatal(err)
	}
	e.signInToSite(c, siteOrigin+"/")
	if resp := e.viaProxy(c, "/api/authz/forward", siteOrigin+"/"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("member: %d", resp.StatusCode)
	}
	if err := e.st.SetMembership(e.app.ID, e.user.ID, store.RoleMember, store.MemberBlocked, e.root.ID); err != nil {
		t.Fatal(err)
	}
	resp = e.viaProxy(c, "/api/authz/forward", siteOrigin+"/")
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-FireID-Denied") != store.ReasonBlocked {
		t.Fatalf("blocked: %d %q", resp.StatusCode, resp.Header.Get("X-FireID-Denied"))
	}
}

func TestForwardAuthRefusals(t *testing.T) {
	e := newForwardEnv(t, store.AccessAllUsers)
	c := e.browser()
	e.passwordSignIn(c, "alice")

	t.Run("an unregistered host cannot start", func(t *testing.T) {
		resp := e.viaProxy(c, "/api/authz/app/start", "https://evil.example/__fireid/start")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
		q := url.Values{"app": {"site"}, "state": {"x"}, "rd": {"https://evil.example/"}}
		if resp := e.get(c, "/api/authz/authorize?"+q.Encode()); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize for unregistered host: %d", resp.StatusCode)
		}
	})

	t.Run("no app header is a misconfiguration", func(t *testing.T) {
		resp := e.get(c, "/api/authz/forward")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("a code needs the state cookie of the browser that started", func(t *testing.T) {
		resp := e.viaProxy(c, "/api/authz/forward", siteOrigin+"/")
		start, _ := url.Parse(resp.Header.Get("Location"))
		resp = e.viaProxy(c, "/api/authz/app/start?"+start.RawQuery, start.String())
		authz := location(t, resp, http.StatusFound)
		cb := location(t, e.get(c, authz.RequestURI()), http.StatusFound)

		// Another browser (no state cookie) cannot redeem it…
		victim := e.browser()
		if resp := e.viaProxy(victim, "/api/authz/app/callback?"+cb.RawQuery, cb.String()); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("redeemed without state: %d", resp.StatusCode)
		}
		// …and the attempt spent it.
		if resp := e.viaProxy(c, "/api/authz/app/callback?"+cb.RawQuery, cb.String()); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("code reused: %d", resp.StatusCode)
		}
	})

	t.Run("redirects never leave the site", func(t *testing.T) {
		back := e.signInToSite(c, siteOrigin+"/")
		if back.String() != siteOrigin+"/" {
			t.Fatalf("back %v", back)
		}
		resp := e.viaProxy(c, "/api/authz/app/start?rd="+url.QueryEscape("https://evil.example/x"), siteOrigin+"/__fireid/start")
		authz := location(t, resp, http.StatusFound)
		if rd := authz.Query().Get("rd"); rd != siteOrigin+"/" {
			t.Fatalf("rd %q", rd)
		}
		resp = e.viaProxy(c, "/api/authz/app/logout?rd="+url.QueryEscape("https://evil.example/"), siteOrigin+"/__fireid/logout")
		if loc := location(t, resp, http.StatusFound); loc.String() != siteOrigin+"/" {
			t.Fatalf("logout went to %v", loc)
		}
		if resp := e.viaProxy(c, "/api/authz/forward", siteOrigin+"/"); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("after site logout: %d", resp.StatusCode)
		}
	})

	t.Run("without an IdP session the browser is sent to sign in", func(t *testing.T) {
		q := url.Values{"app": {"site"}, "state": {"x"}, "rd": {siteOrigin + "/"}}
		loc := location(t, e.get(e.browser(), "/api/authz/authorize?"+q.Encode()), http.StatusFound)
		if loc.Path != "/sign-in" || !strings.HasPrefix(loc.Query().Get("return"), "/api/authz/authorize?") {
			t.Fatalf("sign-in location %v", loc)
		}
	})
}

func TestForwardAuthSnippet(t *testing.T) {
	e := newForwardEnv(t, store.AccessAllUsers)
	st, body := e.send(e.sessionFor(e.root), http.MethodGet, "/api/admin/apps/site/forward-auth", nil)
	wantStatus(t, "snippet", st, http.StatusOK, body)
	hosts, _ := body["hosts"].([]any)
	snippet, _ := body["serverSnippet"].(string)
	if len(hosts) != 1 || hosts[0] != siteOrigin || !strings.Contains(snippet, `proxy_set_header X-FireID-App "site";`) ||
		!strings.Contains(snippet, "internal;") || !strings.Contains(snippet, "proxy_pass_request_body off;") {
		t.Fatalf("forward-auth body %v", body)
	}
	if st, _ := e.send(e.sessionFor(e.user), http.MethodGet, "/api/admin/apps/site/forward-auth", nil); st != http.StatusNotFound {
		t.Fatalf("non-manager got the snippet: %d", st)
	}
}
