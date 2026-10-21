package client

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// app is a relying party built on the flow handlers: /login, /callback, and
// pages to land on.
type app struct {
	srv    *httptest.Server
	client *Client
	fc     FlowConfig

	mu     sync.Mutex
	logins []*LoginResult
	errs   []error
}

func newApp(t *testing.T, fp *fakeProvider, issParam bool) *app {
	t.Helper()
	a := &app{}
	mux := http.NewServeMux()
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	fp.mu.Lock()
	fp.redirectURI = a.srv.URL + "/callback"
	fp.issParam = issParam
	fp.mu.Unlock()
	a.client = newTestClient(t, fp, nil)
	a.fc = FlowConfig{
		OnLogin: func(w http.ResponseWriter, r *http.Request, res *LoginResult) error {
			a.mu.Lock()
			a.logins = append(a.logins, res)
			a.mu.Unlock()
			if res.ReturnTo == "/fail" {
				return errors.New("session store down")
			}
			http.Redirect(w, r, res.ReturnTo, http.StatusFound)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			a.mu.Lock()
			a.errs = append(a.errs, err)
			a.mu.Unlock()
			defaultErrorHandler(w, r, err)
		},
	}
	mux.Handle("/login", a.client.LoginHandler(a.fc))
	mux.Handle("/callback", a.client.CallbackHandler(a.fc))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "page:"+r.URL.Path)
	})
	return a
}

func (a *app) lastError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.errs) == 0 {
		return nil
	}
	return a.errs[len(a.errs)-1]
}

// browser is an http.Client with a cookie jar. follow decides whether
// redirects are followed.
func browser(t *testing.T, follow bool) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Jar: jar}
	if !follow {
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return hc
}

func get(t *testing.T, hc *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := hc.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// startLogin hits /login without following and returns the state the
// provider was sent.
func startLogin(t *testing.T, a *app, hc *http.Client, ret string) string {
	t.Helper()
	resp, _ := get(t, hc, a.srv.URL+"/login?return="+url.QueryEscape(ret))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("code_challenge_method") != "S256" || loc.Query().Get("nonce") == "" {
		t.Fatalf("authorization request %s", loc)
	}
	return loc.Query().Get("state")
}

func TestFlowEndToEnd(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	a := newApp(t, fp, true)
	hc := browser(t, true)

	resp, body := get(t, hc, a.srv.URL+"/login?return=/dash")
	if resp.StatusCode != http.StatusOK || body != "page:/dash" {
		t.Fatalf("landed with %d %q (last error %v)", resp.StatusCode, body, a.lastError())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.logins) != 1 {
		t.Fatalf("%d logins", len(a.logins))
	}
	res := a.logins[0]
	if res.ReturnTo != "/dash" || res.Claims.Subject != "42" || res.Claims.SID != "sess-1" || res.Tokens.AccessToken == "" {
		t.Fatalf("result %+v", res)
	}
	if res.Claims.Nonce == "" || res.Claims.Nonce == "n-1" {
		t.Fatalf("nonce %q was not the login's", res.Claims.Nonce)
	}
	// The login cookie is gone after the callback.
	u, _ := url.Parse(a.srv.URL)
	for _, ck := range hc.Jar.Cookies(u) {
		if ck.Name == a.client.cookieName(a.fc) {
			t.Fatalf("login cookie survived: %v", ck)
		}
	}
}

// checkCookieName checks a default login cookie name: prefix plus eight hex
// digits.
func checkCookieName(t *testing.T, name, prefix string) {
	t.Helper()
	suffix := strings.TrimPrefix(name, prefix)
	if suffix == name || len(suffix) != 8 {
		t.Fatalf("cookie name %q does not have the form %s<8 hex digits>", name, prefix)
	}
	if _, err := hex.DecodeString(suffix); err != nil {
		t.Fatalf("cookie name %q: suffix is not hex", name)
	}
}

func TestFlowCookie(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	a := newApp(t, fp, false)
	resp, _ := get(t, browser(t, false), a.srv.URL+"/login?return=/x")
	var ck *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == a.client.cookieName(a.fc) {
			ck = c
		}
	}
	if ck == nil {
		t.Fatalf("no login cookie among %v", resp.Cookies())
	}
	checkCookieName(t, ck.Name, "fireid_rp_")
	if !ck.HttpOnly || ck.Path != "/" || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge != 600 || ck.Secure {
		t.Fatalf("cookie attributes %+v", ck)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("login redirect must not be cached")
	}
	// On an https RedirectURL the name carries the __Host- prefix and Secure.
	fp.mu.Lock()
	fp.redirectURI = "https://app.example.test/callback"
	fp.mu.Unlock()
	c := newTestClient(t, fp, nil)
	rec := httptest.NewRecorder()
	c.LoginHandler(FlowConfig{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	cks := rec.Result().Cookies()
	if len(cks) != 1 || !cks[0].Secure {
		t.Fatalf("https cookie %+v", cks)
	}
	checkCookieName(t, cks[0].Name, "__Host-fireid_rp_")
	// The name is the Client's own: another client ID at the same provider,
	// or another provider, gets a different one.
	sameProvider := newTestClient(t, fp, func(cfg *Config) { cfg.ClientID = "app-2" })
	otherProvider := newTestClient(t, newFakeProvider(t, clk), nil)
	if c.cookie == sameProvider.cookie || c.cookie == otherProvider.cookie || sameProvider.cookie == otherProvider.cookie {
		t.Fatalf("cookie names collide: %q %q %q", c.cookie, sameProvider.cookie, otherProvider.cookie)
	}
	// Only GET starts a login.
	rec = httptest.NewRecorder()
	c.LoginHandler(FlowConfig{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/login", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /login: %d", rec.Code)
	}
}

// TestFlowCookieBoundToClient is the mix-up of RFC 9700 section 4.4: an
// application with Clients at two providers, one of them hostile. A login
// started at the hostile provider shows it the state, nonce and challenge;
// it obtains a code at the honest provider for its own account under them
// and sends the browser to the honest Client's callback. That callback must
// not finish the login, whether the two Clients use their default cookie
// names or share one.
func TestFlowCookieBoundToClient(t *testing.T) {
	for name, shared := range map[string]bool{"default names": false, "shared name": true} {
		t.Run(name, func(t *testing.T) {
			clk := newClock()
			honest, hostile := newFakeProvider(t, clk), newFakeProvider(t, clk)
			honest.redirectURI = "https://app.example.test/callback/a"
			hostile.redirectURI = "https://app.example.test/callback/b"
			ca, cb := newTestClient(t, honest, nil), newTestClient(t, hostile, nil)
			logins := 0
			var lastErr error
			fc := FlowConfig{
				OnLogin: func(w http.ResponseWriter, r *http.Request, res *LoginResult) error {
					logins++
					return nil
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					lastErr = err
					defaultErrorHandler(w, r, err)
				},
			}
			if shared {
				fc.CookieName = "__Host-shared"
			}
			mux := http.NewServeMux()
			mux.Handle("/callback/a", ca.CallbackHandler(fc))
			mux.Handle("/login/b", cb.LoginHandler(fc))

			// The browser starts a login with the hostile provider.
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.test/login/b", nil))
			cookies := rec.Result().Cookies()
			if rec.Code != http.StatusFound || len(cookies) != 1 {
				t.Fatalf("login: %d %v", rec.Code, cookies)
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			q := loc.Query()

			// The hostile provider, knowing them, gets a code at the honest
			// one for its own account under the same state, nonce and challenge.
			hc := honest.srv.Client()
			hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			resp, err := hc.Get(honest.issuer + "/authorize?" + url.Values{
				"response_type": {"code"}, "client_id": {honest.clientID}, "redirect_uri": {honest.redirectURI},
				"scope": {"openid"}, "state": {q.Get("state")}, "nonce": {q.Get("nonce")},
				"code_challenge": {q.Get("code_challenge")}, "code_challenge_method": {"S256"},
			}.Encode())
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			cbURL, err := url.Parse(resp.Header.Get("Location"))
			if err != nil || cbURL.Query().Get("code") == "" {
				t.Fatalf("authorize at the honest provider: %d %v", resp.StatusCode, err)
			}

			// ... and sends the browser there with the cookie it has.
			req := httptest.NewRequest(http.MethodGet, "https://app.example.test/callback/a?"+cbURL.RawQuery, nil)
			req.AddCookie(cookies[0])
			rec = httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if logins != 0 {
				t.Fatal("a login started at the hostile provider finished at the honest Client")
			}
			want := "no login cookie"
			if shared {
				want = "another client"
			}
			if rec.Code != http.StatusBadRequest || !errors.Is(lastErr, ErrStateMismatch) || !strings.Contains(lastErr.Error(), want) {
				t.Fatalf("callback: %d %v, want ErrStateMismatch mentioning %q", rec.Code, lastErr, want)
			}
		})
	}
}

func TestFlowReturnPath(t *testing.T) {
	cases := map[string]string{
		"/dash":                                  "/dash",
		"/a/b?c=d#e":                             "/a/b?c=d#e",
		"":                                       "/",
		"//evil.test/x":                          "/",
		"/\\evil.test":                           "/",
		"https://evil.test":                      "/",
		"evil.test":                              "/",
		"/ok\r\nX: y":                            "/",
		"/" + strings.Repeat("a", maxReturnPath): "/",
	}
	for in, want := range cases {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}

	clk := newClock()
	fp := newFakeProvider(t, clk)
	a := newApp(t, fp, false)
	for _, ret := range []string{"//evil.test/x", "https://evil.test", "/\\evil.test"} {
		hc := browser(t, true)
		resp, body := get(t, hc, a.srv.URL+"/login?return="+url.QueryEscape(ret))
		if resp.StatusCode != http.StatusOK || body != "page:/" {
			t.Errorf("return=%q landed on %d %q", ret, resp.StatusCode, body)
		}
	}
}

func TestFlowCallbackRejects(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	a := newApp(t, fp, true)
	ctx := a.srv.URL + "/callback?"

	cases := map[string]struct {
		cookie bool
		query  func(state string) string
		age    time.Duration
		status int
		is     error
		code   string // AuthError code
	}{
		"no cookie": {
			cookie: false, query: func(string) string { return "state=x&code=y&iss=" + url.QueryEscape(fp.issuer) },
			status: http.StatusBadRequest, is: ErrStateMismatch,
		},
		"state mismatch": {
			cookie: true, query: func(string) string { return "state=wrong&code=y&iss=" + url.QueryEscape(fp.issuer) },
			status: http.StatusBadRequest, is: ErrStateMismatch,
		},
		"no state": {
			cookie: true, query: func(string) string { return "code=y&iss=" + url.QueryEscape(fp.issuer) },
			status: http.StatusBadRequest, is: ErrStateMismatch,
		},
		"login too old": {
			cookie: true, query: func(s string) string { return "state=" + s + "&code=y&iss=" + url.QueryEscape(fp.issuer) },
			age: loginTTL + time.Second, status: http.StatusBadRequest, is: ErrStateMismatch,
		},
		"iss mismatch": {
			cookie: true, query: func(s string) string { return "state=" + s + "&code=y&iss=https%3A%2F%2Fevil.test" },
			status: http.StatusBadRequest, is: ErrIssuerMismatch,
		},
		"iss missing though supported": {
			cookie: true, query: func(s string) string { return "state=" + s + "&code=y" },
			status: http.StatusBadRequest, is: ErrIssuerMismatch,
		},
		"access denied": {
			cookie: true, query: func(s string) string {
				return "state=" + s + "&error=access_denied&error_description=nope&iss=" + url.QueryEscape(fp.issuer)
			},
			status: http.StatusForbidden, code: "access_denied",
		},
		"server error": {
			cookie: true, query: func(s string) string { return "state=" + s + "&error=server_error&iss=" + url.QueryEscape(fp.issuer) },
			status: http.StatusBadGateway, code: "server_error",
		},
		"no code": {
			cookie: true, query: func(s string) string { return "state=" + s + "&iss=" + url.QueryEscape(fp.issuer) },
			status: http.StatusBadRequest, is: ErrBadCallback,
		},
		"bad code": {
			cookie: true, query: func(s string) string { return "state=" + s + "&code=forged&iss=" + url.QueryEscape(fp.issuer) },
			status: http.StatusBadGateway, is: nil,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			hc := browser(t, false)
			state := "none"
			if tc.cookie {
				state = startLogin(t, a, hc, "/dash")
			}
			if tc.age > 0 {
				clk.advance(tc.age)
				defer clk.advance(-tc.age)
			}
			resp, body := get(t, hc, ctx+tc.query(state))
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d body %q, want %d (error %v)", resp.StatusCode, body, tc.status, a.lastError())
			}
			if resp.Header.Get("Cache-Control") != "no-store" {
				t.Error("callback answer must not be cached")
			}
			err := a.lastError()
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("error %v is not %v", err, tc.is)
			}
			if tc.code != "" {
				var ae *AuthError
				if !errors.As(err, &ae) || ae.Code != tc.code {
					t.Fatalf("error %v is not AuthError %s", err, tc.code)
				}
			}
			if name == "bad code" {
				var te *TokenError
				if !errors.As(err, &te) {
					t.Fatalf("error %v is not a TokenError", err)
				}
			}
			if strings.Contains(body, "nope") {
				t.Error("error_description must not be echoed")
			}
		})
	}

	t.Run("POST", func(t *testing.T) {
		resp, err := http.Post(a.srv.URL+"/callback", "text/plain", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("OnLogin error", func(t *testing.T) {
		hc := browser(t, true)
		resp, _ := get(t, hc, a.srv.URL+"/login?return=/fail")
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if err := a.lastError(); err == nil || !strings.Contains(err.Error(), "session store down") {
			t.Fatalf("error %v", err)
		}
	})

	t.Run("newest login wins", func(t *testing.T) {
		hc := browser(t, false)
		first := startLogin(t, a, hc, "/one")
		startLogin(t, a, hc, "/two")
		resp, _ := get(t, hc, ctx+"state="+first+"&code=y&iss="+url.QueryEscape(fp.issuer))
		if resp.StatusCode != http.StatusBadRequest || !errors.Is(a.lastError(), ErrStateMismatch) {
			t.Fatalf("older tab: %d %v", resp.StatusCode, a.lastError())
		}
	})
}

func TestFlowWithoutIssParameter(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	a := newApp(t, fp, false)
	// Not advertised, not sent: fine.
	resp, body := get(t, browser(t, true), a.srv.URL+"/login?return=/dash")
	if resp.StatusCode != http.StatusOK || body != "page:/dash" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	// Not advertised but sent wrong: still refused.
	hc := browser(t, false)
	state := startLogin(t, a, hc, "/dash")
	resp, _ = get(t, hc, a.srv.URL+"/callback?state="+state+"&code=y&iss=https%3A%2F%2Fevil.test")
	if resp.StatusCode != http.StatusBadRequest || !errors.Is(a.lastError(), ErrIssuerMismatch) {
		t.Fatalf("%d %v", resp.StatusCode, a.lastError())
	}
}

func TestErrorStatus(t *testing.T) {
	cases := map[error]int{
		&AuthError{Code: "access_denied"}:                  http.StatusForbidden,
		&AuthError{Code: "temporarily_unavailable"}:        http.StatusBadGateway,
		&AuthError{Code: "invalid_request"}:                http.StatusBadRequest,
		&TokenError{Code: "invalid_grant"}:                 http.StatusBadGateway,
		fmt.Errorf("x: %w", ErrInvalidToken):               http.StatusBadGateway,
		fmt.Errorf("x: %w", ErrProvider):                   http.StatusBadGateway,
		fmt.Errorf("x: %w", ErrStateMismatch):              http.StatusBadRequest,
		fmt.Errorf("x: %w", ErrIssuerMismatch):             http.StatusBadRequest,
		fmt.Errorf("x: %w", ErrBadCallback):                http.StatusBadRequest,
		errors.New("session store down"):                   http.StatusInternalServerError,
		fmt.Errorf("client: OnLogin: %w", errors.New("x")): http.StatusInternalServerError,
	}
	for err, want := range cases {
		if got := ErrorStatus(err); got != want {
			t.Errorf("ErrorStatus(%v) = %d, want %d", err, got, want)
		}
	}
}
