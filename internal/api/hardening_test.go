package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

// An authorization request ID is visible to whoever started the flow. A
// victim who opens the login link approves the request with their own
// session; the code must then reach only the victim's browser, never the
// attacker polling the callback.
func TestAuthorizeCallbackBoundToApprovingSession(t *testing.T) {
	e := newOIDCEnv(t)
	attacker := e.browser()
	p := e.webParams("openid")
	p.Set("response_type", "code")
	loc := location(t, e.get(attacker, "/authorize?"+p.Encode()), http.StatusFound)
	authReqID := loc.Query().Get("auth_req_id")
	if loc.Path != "/login" || authReqID == "" {
		t.Fatalf("authorize redirected to %s", loc)
	}

	victim := e.sessionFor(e.user)
	cb := location(t, e.get(victim, "/login?auth_req_id="+url.QueryEscape(authReqID)), http.StatusFound)
	if cb.Path != "/authorize/callback" {
		t.Fatalf("victim's login went to %s", cb)
	}

	t.Run("another browser gets no code", func(t *testing.T) {
		resp := e.get(attacker, cb.String())
		if resp.StatusCode == http.StatusFound {
			if u, _ := url.Parse(resp.Header.Get("Location")); u != nil && u.Query().Get("code") != "" {
				t.Fatalf("attacker received the victim's code: %s", u)
			}
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", resp.StatusCode)
		}
	})

	t.Run("the approving browser still gets its code", func(t *testing.T) {
		got := location(t, e.get(victim, cb.String()), http.StatusFound)
		if got.Host != "rp.example" || got.Query().Get("code") == "" {
			t.Fatalf("callback %s", got)
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.browser()
	e.passwordSignIn(c, "alice")

	for _, path := range []string{"/api/auth/me", "/api/setup"} {
		resp := e.get(c, path)
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", path, got)
		}
		for _, h := range []string{"Permissions-Policy", "Content-Security-Policy",
			"X-Content-Type-Options", "Referrer-Policy"} {
			if resp.Header.Get(h) == "" {
				t.Errorf("%s: no %s", path, h)
			}
		}
	}

	t.Run("discovery stays cacheable", func(t *testing.T) {
		resp := e.get(c, "/.well-known/openid-configuration")
		if got := resp.Header.Get("Cache-Control"); !strings.HasPrefix(got, "public") {
			t.Fatalf("Cache-Control %q", got)
		}
	})

	t.Run("HSTS only for an HTTPS issuer", func(t *testing.T) {
		if got := e.get(c, "/api/setup").Header.Get("Strict-Transport-Security"); got != "" {
			t.Fatalf("HSTS on an http issuer: %q", got)
		}
		s := &Server{deps: Deps{PublicBase: "https://id.example"}}
		rec := httptest.NewRecorder()
		s.withSecurityHeaders(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if got := rec.Header().Get("Strict-Transport-Security"); !strings.HasPrefix(got, "max-age=") {
			t.Fatalf("HSTS %q", got)
		}
	})
}

func TestTokenEndpointHygiene(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.browser()
	code := func() string {
		return e.authorize(c, e.webParams("openid"), !hasSession(e, c)).Query().Get("code")
	}
	form := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback},
			"client_id": {e.web.ClientID}, "client_secret": {e.webSecret}}
	}

	t.Run("token response is not cacheable", func(t *testing.T) {
		resp, tok := e.exchangeWeb(code())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("token: %d %v", resp.StatusCode, tok)
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control %q", got)
		}
	})

	t.Run("credentials in the query string are refused", func(t *testing.T) {
		resp, body := e.postForm(http.DefaultClient, "/oauth/token?"+form(code()).Encode(), url.Values{}, "", "")
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Fatalf("got %d %v", resp.StatusCode, body)
		}
		r, err := http.Get(e.issuer + "/oauth/token?" + form(code()).Encode())
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET token: %d", r.StatusCode)
		}
	})

	t.Run("userinfo refuses a token in the URL", func(t *testing.T) {
		_, tok := e.exchangeWeb(code())
		r, err := http.Get(e.issuer + "/userinfo?access_token=" + url.QueryEscape(tok["access_token"].(string)))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode == http.StatusOK {
			t.Fatal("userinfo answered a token from the query string")
		}
	})

	t.Run("bodies are capped", func(t *testing.T) {
		f := form(code())
		f.Set("padding", strings.Repeat("a", maxBodyBytes+1))
		resp, body := e.postForm(http.DefaultClient, "/oauth/token", f, "", "")
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("a %d-byte token request was accepted: %v", maxBodyBytes+1, body)
		}
	})
}

// hasSession reports whether the browser holds a Fire ID session.
func hasSession(e *oidcEnv, c *http.Client) bool {
	u, _ := url.Parse(e.issuer)
	return len(c.Jar.Cookies(u)) > 0
}

func TestServerLimits(t *testing.T) {
	s := &Server{deps: Deps{Log: slog.New(slog.DiscardHandler)}, mux: http.NewServeMux()}
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	switch {
	case s.http.ReadHeaderTimeout <= 0, s.http.ReadTimeout <= 0, s.http.WriteTimeout <= 0, s.http.IdleTimeout <= 0:
		t.Fatal("a server timeout is unset")
	case s.http.MaxHeaderBytes <= 0 || s.http.MaxHeaderBytes > 64<<10:
		t.Fatalf("MaxHeaderBytes %d", s.http.MaxHeaderBytes)
	}
}

// logBuffer collects log output from concurrent handlers.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// People type their password into the username field. A failed sign-in must
// not put the attempted name in the log, through any of the sign-in paths or
// the throttle that follows them.
func TestFailedSignInDoesNotLogTheAttemptedName(t *testing.T) {
	e := newOIDCEnv(t)
	const typed = "hunter2-typed-in-the-wrong-field"
	for range 6 {
		e.postJSON(http.DefaultClient, "/api/auth/login", map[string]any{"username": typed, "password": "x"})
	}
	e.postForm(http.DefaultClient, "/oidc/login", url.Values{
		"auth_req_id": {"none"}, "username": {typed}, "password": {"x"}}, "", "")
	if strings.Contains(e.logs.String(), typed) {
		t.Fatalf("the attempted username reached the log:\n%s", e.logs.String())
	}
	if !strings.Contains(e.logs.String(), "failed sign-in") {
		t.Fatal("failed sign-ins are no longer logged at all")
	}
}

// Every state-changing route outside the provider's own endpoints refuses a
// request from another site, before any handler runs.
func TestCrossSiteGuardCoversUnsafeRoutes(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.sessionFor(e.root)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/setup"},
		{http.MethodPost, "/api/auth/login"},
		{http.MethodPost, "/api/auth/logout"},
		{http.MethodPost, "/api/auth/email/start"},
		{http.MethodPost, "/api/auth/login/passkey/begin"},
		{http.MethodPost, "/oidc/login"},
		{http.MethodPatch, "/api/account/profile"},
		{http.MethodPost, "/api/account/password"},
		{http.MethodDelete, "/api/account/sessions/1"},
		{http.MethodPost, "/api/admin/apps"},
		{http.MethodDelete, "/api/admin/apps/web"},
		{http.MethodPost, "/api/admin/signing-keys/rotate"},
		{http.MethodPut, "/api/no-such-route"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, e.issuer+tc.path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://evil.example")
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d, want 403", resp.StatusCode)
			}
		})
	}
}

func TestStaticFiles(t *testing.T) {
	s := &Server{deps: Deps{Web: fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html>index")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}}}
	serve := func(method, target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.static(rec, httptest.NewRequest(method, target, nil))
		return rec
	}

	t.Run("hashed assets are immutable", func(t *testing.T) {
		rec := serve(http.MethodGet, "/assets/app.js")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") ||
			!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/javascript") {
			t.Fatalf("%d %v", rec.Code, rec.Header())
		}
	})
	t.Run("client routes get the shell, uncached", func(t *testing.T) {
		rec := serve(http.MethodGet, "/account/security")
		if rec.Code != http.StatusOK || rec.Body.String() != "<!doctype html>index" ||
			rec.Header().Get("Cache-Control") != "no-cache" {
			t.Fatalf("%d %q %v", rec.Code, rec.Body.String(), rec.Header())
		}
	})
	t.Run("traversal stays inside the embedded tree", func(t *testing.T) {
		for _, target := range []string{"/../config.json", "/assets/../../go.mod", "/%2e%2e/master.key"} {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.URL.Path = target
			rec := httptest.NewRecorder()
			s.static(rec, req)
			if rec.Body.String() != "<!doctype html>index" {
				t.Fatalf("%s: %d %q", target, rec.Code, rec.Body.String())
			}
		}
	})
	t.Run("unknown API paths are JSON 404s", func(t *testing.T) {
		if rec := serve(http.MethodGet, "/api/nope"); rec.Code != http.StatusNotFound {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("only GET and HEAD", func(t *testing.T) {
		if rec := serve(http.MethodPost, "/index.html"); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%d", rec.Code)
		}
	})
}
