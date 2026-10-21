package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lieyanc/FireID/client"
	"github.com/lieyanc/FireID/internal/store"
)

// These tests drive the real server through the client module, the way an
// application built on github.com/lieyanc/FireID/client would. The client's
// own tests use a fake provider; this is where the two halves meet.

// relyingParty is an application on the client module, served from a
// loopback httptest server, with everything its handlers produced recorded.
type relyingParty struct {
	t   *testing.T
	e   *oidcEnv
	srv *httptest.Server
	mux *http.ServeMux
	cfg client.Config
	c   *client.Client
	// keyFetches counts requests to /keys, to watch the JWKS cache.
	keyFetches atomic.Int32

	mu         sync.Mutex
	logins     []*client.LoginResult
	errs       []error
	callbacks  []url.Values // the query of every callback request
	logouts    []*client.LogoutToken
	rawLogouts []string // the raw logout tokens the handler received
}

// newRelyingParty starts the server so its address is known for app
// registration; connect builds the client afterwards.
func newRelyingParty(t *testing.T, e *oidcEnv) *relyingParty {
	t.Helper()
	rp := &relyingParty{t: t, e: e, mux: http.NewServeMux()}
	rp.srv = httptest.NewServer(rp.mux)
	t.Cleanup(rp.srv.Close)
	return rp
}

func (rp *relyingParty) callbackURL() string { return rp.srv.URL + "/callback" }

// register creates an app for the relying party with the given token
// endpoint auth method, owned by root and open to all users.
func (rp *relyingParty) register(slug, method string) (*store.App, string) {
	rp.t.Helper()
	in := store.NewApp{
		Slug: slug, Name: slug, OwnerUserID: rp.e.root.ID, TEAuthMethod: method,
		RedirectURIs:           []string{rp.callbackURL()},
		PostLogoutRedirectURIs: []string{rp.srv.URL + "/bye"},
		Scopes:                 []string{"openid", "profile", "email"},
		DefaultAccess:          store.AccessAllUsers,
	}
	if method == store.AuthNone {
		in.ClientType = store.ClientPublic
	}
	app, secret, err := rp.e.st.CreateApp(in)
	if err != nil {
		rp.t.Fatal(err)
	}
	return app, secret
}

// connect builds the client — Issuer, RedirectURL and a /keys-counting
// HTTP client filled in — and mounts the handlers: /login, /login-none
// (prompt=none), /callback, /backchannel-logout, and a page at every other
// path. cookie names the login cookie, since every relying party here
// shares the loopback host with Fire ID and each other.
func (rp *relyingParty) connect(cfg client.Config, cookie string) {
	rp.t.Helper()
	cfg.Issuer = rp.e.issuer
	cfg.RedirectURL = rp.callbackURL()
	cfg.HTTPClient = &http.Client{Transport: &countingTransport{base: http.DefaultTransport, path: "/keys", n: &rp.keyFetches}}
	c, err := client.New(context.Background(), cfg)
	if err != nil {
		rp.t.Fatal(err)
	}
	rp.cfg, rp.c = cfg, c

	flow := client.FlowConfig{
		CookieName: cookie,
		OnLogin: func(w http.ResponseWriter, r *http.Request, res *client.LoginResult) error {
			rp.mu.Lock()
			rp.logins = append(rp.logins, res)
			rp.mu.Unlock()
			http.Redirect(w, r, res.ReturnTo, http.StatusFound)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			rp.mu.Lock()
			rp.errs = append(rp.errs, err)
			rp.mu.Unlock()
			w.WriteHeader(client.ErrorStatus(err))
		},
	}
	none := flow
	none.AuthOptions = []client.AuthOption{client.WithPrompt("none")}
	callback := c.CallbackHandler(flow)
	logout := c.BackchannelLogoutHandler(func(ctx context.Context, lt *client.LogoutToken) error {
		rp.mu.Lock()
		rp.logouts = append(rp.logouts, lt)
		rp.mu.Unlock()
		return nil
	})
	rp.mux.Handle("/login", c.LoginHandler(flow))
	rp.mux.Handle("/login-none", c.LoginHandler(none))
	rp.mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		rp.mu.Lock()
		rp.callbacks = append(rp.callbacks, r.URL.Query())
		rp.mu.Unlock()
		callback.ServeHTTP(w, r)
	})
	rp.mux.HandleFunc("/backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rp.mu.Lock()
		rp.rawLogouts = append(rp.rawLogouts, url.Values(mustParseQuery(rp.t, string(body))).Get("logout_token"))
		rp.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		logout.ServeHTTP(w, r)
	})
	rp.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "page:"+r.URL.Path)
	})
}

// login starts a login at path (/login or /login-none) and follows it
// through Fire ID. When Fire ID asks for credentials, alice signs in with
// her password on the form, as a person would. It returns the final answer.
func (rp *relyingParty) login(c *http.Client, path, ret string) (int, string) {
	rp.t.Helper()
	resp, err := c.Get(rp.srv.URL + path + "?return=" + url.QueryEscape(ret))
	if err != nil {
		rp.t.Fatal(err)
	}
	if resp.Request.URL.Path == "/sign-in" {
		resp.Body.Close()
		resp, err = c.PostForm(rp.e.issuer+"/oidc/login", url.Values{
			"auth_req_id": {resp.Request.URL.Query().Get("auth_req_id")},
			"username":    {"alice"}, "password": {testPassword},
		})
		if err != nil {
			rp.t.Fatal(err)
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (rp *relyingParty) lastLogin() *client.LoginResult {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if len(rp.logins) == 0 {
		rp.t.Fatalf("no login recorded (errors: %v)", rp.errs)
	}
	return rp.logins[len(rp.logins)-1]
}

func (rp *relyingParty) lastErr() error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if len(rp.errs) == 0 {
		return nil
	}
	return rp.errs[len(rp.errs)-1]
}

func (rp *relyingParty) lastCallback() url.Values {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if len(rp.callbacks) == 0 {
		rp.t.Fatal("no callback recorded")
	}
	return rp.callbacks[len(rp.callbacks)-1]
}

func (rp *relyingParty) loginCount() int {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return len(rp.logins)
}

// countingTransport counts requests to one path.
type countingTransport struct {
	base http.RoundTripper
	path string
	n    *atomic.Int32
}

func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == t.path {
		t.n.Add(1)
	}
	return t.base.RoundTrip(r)
}

// following is a cookie-carrying client that follows redirects, which is
// what the hop from the relying party to Fire ID and back needs. The jar
// keys cookies by host, so Fire ID's and the relying party's cookies share
// it; their names differ, and each server ignores the other's.
func following(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

// noFollow shares c's cookies but stops at the first redirect.
func noFollow(c *http.Client) *http.Client {
	return &http.Client{Jar: c.Jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func mustParseQuery(t *testing.T, s string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// jwsKID reads the kid header of a compact JWS without verifying it.
func jwsKID(t *testing.T, raw string) string {
	t.Helper()
	hdr, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatal(err)
	}
	return h.Kid
}

func TestClientCodeFlowConfidential(t *testing.T) {
	e := newOIDCEnv(t)
	rp := newRelyingParty(t, e)
	app, secret := rp.register("rpweb", store.AuthBasic)
	rp.connect(client.Config{ClientID: app.ClientID, ClientSecret: secret,
		Scopes: []string{"openid", "profile", "email", "offline_access"}}, "rp_web")
	ctx := context.Background()
	sub := strconv.FormatInt(e.user.ID, 10)

	c := following(t)
	status, body := rp.login(c, "/login", "/dash")
	if status != http.StatusOK || body != "page:/dash" {
		t.Fatalf("login landed on %d %q (last error %v)", status, body, rp.lastErr())
	}
	res := rp.lastLogin()
	cl := res.Claims
	switch {
	case res.ReturnTo != "/dash":
		t.Errorf("ReturnTo %q", res.ReturnTo)
	case cl.Issuer != e.issuer, cl.Subject != sub:
		t.Errorf("iss %q sub %q, want %q %q", cl.Issuer, cl.Subject, e.issuer, sub)
	case cl.SID == "":
		t.Error("no sid")
	case cl.ACR != store.ACRLoA1:
		t.Errorf("acr %q", cl.ACR)
	case len(cl.AMR) != 1 || cl.AMR[0] != "pwd":
		t.Errorf("amr %v", cl.AMR)
	case cl.AuthTime.IsZero():
		t.Error("no auth_time")
	case cl.Nonce == "":
		t.Error("no nonce")
	case cl.Email != "alice@example.com", cl.PreferredUsername != "alice", cl.Name != "Alice":
		t.Errorf("profile claims %q %q %q", cl.Email, cl.PreferredUsername, cl.Name)
	case res.Tokens.AccessToken == "", res.Tokens.RefreshToken == "", res.Tokens.IDToken == "":
		t.Errorf("tokens %+v", res.Tokens)
	}
	// at_hash was present and checked inside Exchange; its presence is what
	// can be asserted here.
	if ah, _ := cl.Raw["at_hash"].(string); ah == "" {
		t.Error("id_token has no at_hash")
	}
	if cb := rp.lastCallback(); cb.Get("iss") != e.issuer || cb.Get("code") == "" {
		t.Errorf("callback query %v", cb)
	}

	t.Run("userinfo", func(t *testing.T) {
		ui, err := rp.c.UserInfoFor(ctx, res.Tokens.AccessToken, sub)
		if err != nil {
			t.Fatal(err)
		}
		if ui.Subject != sub || ui.Email != "alice@example.com" || ui.PreferredUsername != "alice" || ui.Name != "Alice" {
			t.Fatalf("userinfo %+v", ui)
		}
		if _, err := rp.c.UserInfoFor(ctx, res.Tokens.AccessToken, "0"); !errors.Is(err, client.ErrInvalidToken) {
			t.Fatalf("userinfo for another subject: %v", err)
		}
	})

	t.Run("refresh", func(t *testing.T) {
		fresh, err := rp.c.Refresh(ctx, res.Tokens.RefreshToken, client.WithExpectedSubject(sub))
		if err != nil {
			t.Fatal(err)
		}
		if fresh.RefreshToken == "" || fresh.RefreshToken == res.Tokens.RefreshToken {
			t.Fatal("refresh token was not rotated")
		}
		if fresh.Claims == nil || fresh.Claims.Subject != sub || fresh.Claims.SID != cl.SID {
			t.Fatalf("refreshed claims %+v", fresh.Claims)
		}
		if _, err := rp.c.UserInfoFor(ctx, fresh.AccessToken, sub); err != nil {
			t.Fatalf("userinfo with the refreshed access token: %v", err)
		}
		var te *client.TokenError
		if _, err := rp.c.Refresh(ctx, res.Tokens.RefreshToken); !errors.As(err, &te) || te.Code != "invalid_grant" {
			t.Fatalf("replay of the old refresh token: %v", err)
		}
	})

	t.Run("signed-in browser goes straight through", func(t *testing.T) {
		status, body := rp.login(c, "/login", "/again")
		if status != http.StatusOK || body != "page:/again" || rp.loginCount() != 2 {
			t.Fatalf("second login: %d %q, %d logins", status, body, rp.loginCount())
		}
	})

	t.Run("prompt=none without a session", func(t *testing.T) {
		status, _ := rp.login(following(t), "/login-none", "/dash")
		var ae *client.AuthError
		if err := rp.lastErr(); !errors.As(err, &ae) || ae.Code != "login_required" {
			t.Fatalf("error %v", err)
		}
		if status != client.ErrorStatus(&client.AuthError{Code: "login_required"}) {
			t.Fatalf("status %d", status)
		}
		// The error redirect carried iss too (RFC 9207 section 2).
		if cb := rp.lastCallback(); cb.Get("iss") != e.issuer || cb.Get("error") != "login_required" {
			t.Fatalf("callback query %v", cb)
		}
	})

	t.Run("end_session", func(t *testing.T) {
		raw, err := rp.c.EndSessionURL(res.Tokens.IDToken, rp.srv.URL+"/bye", "x")
		if err != nil {
			t.Fatal(err)
		}
		resp, err := noFollow(c).Get(raw)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc := location(t, resp, http.StatusFound)
		if loc.Host != strings.TrimPrefix(rp.srv.URL, "http://") || loc.Path != "/bye" || loc.Query().Get("state") != "x" {
			t.Fatalf("end_session redirected to %s", loc)
		}
		// The browser is signed out at Fire ID: a silent login now fails.
		rp.login(c, "/login-none", "/dash")
		var ae *client.AuthError
		if err := rp.lastErr(); !errors.As(err, &ae) || ae.Code != "login_required" {
			t.Fatalf("after end_session: %v", err)
		}
	})
}

func TestClientCodeFlowPublic(t *testing.T) {
	e := newOIDCEnv(t)
	rp := newRelyingParty(t, e)
	// The cli app is registered for http://127.0.0.1/callback; a native
	// client may use any loopback port (RFC 8252 section 7.3), so the
	// relying party's port needs no registration. No secret: PKCE alone.
	rp.connect(client.Config{ClientID: e.native.ClientID, Scopes: []string{"openid"}}, "rp_cli")
	sub := strconv.FormatInt(e.user.ID, 10)

	c := following(t)
	e.passwordSignIn(c, "alice")
	status, body := rp.login(c, "/login", "/home")
	if status != http.StatusOK || body != "page:/home" {
		t.Fatalf("login landed on %d %q (last error %v)", status, body, rp.lastErr())
	}
	res := rp.lastLogin()
	if res.Claims.Subject != sub || res.Claims.SID == "" || res.Claims.AuthTime.IsZero() {
		t.Fatalf("claims %+v", res.Claims)
	}
	// Only openid was asked for: no profile or email claims, no refresh token.
	if res.Claims.Email != "" || res.Claims.PreferredUsername != "" || res.Tokens.RefreshToken != "" {
		t.Fatalf("more than openid granted: %+v %q", res.Claims, res.Tokens.RefreshToken)
	}
	if cb := rp.lastCallback(); cb.Get("iss") != e.issuer {
		t.Fatalf("callback query %v", cb)
	}
}

func TestClientAccessDenied(t *testing.T) {
	e := newOIDCEnv(t)
	rp := newRelyingParty(t, e)
	// alice is not a member of the closed app. Its redirect URIs need the
	// relying party's callback beside the one the harness registered.
	if err := e.st.UpdateApp(e.closed.ID, store.AppUpdate{RedirectURIs: []string{rpCallback, rp.callbackURL()}}); err != nil {
		t.Fatal(err)
	}
	rp.connect(client.Config{ClientID: e.closed.ClientID, ClientSecret: e.closedSecret, Scopes: []string{"openid"}}, "rp_closed")

	c := following(t)
	e.passwordSignIn(c, "alice")
	status, _ := rp.login(c, "/login", "/secret")
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (error %v)", status, rp.lastErr())
	}
	var ae *client.AuthError
	if err := rp.lastErr(); !errors.As(err, &ae) || ae.Code != "access_denied" {
		t.Fatalf("error %v", err)
	}
	if cb := rp.lastCallback(); cb.Get("iss") != e.issuer || cb.Get("error") != "access_denied" {
		t.Fatalf("callback query %v", cb)
	}
	if rp.loginCount() != 0 {
		t.Fatal("OnLogin ran for a denied user")
	}
}

func TestClientKeyRotation(t *testing.T) {
	e := newOIDCEnv(t)
	rp := newRelyingParty(t, e)
	app, secret := rp.register("rpkeys", store.AuthPost)
	rp.connect(client.Config{ClientID: app.ClientID, ClientSecret: secret, AuthMethod: client.AuthMethodPost}, "rp_keys")
	ctx := context.Background()
	root := e.sessionFor(e.root)
	kids := e.jwksKIDs()
	if len(kids) != 1 {
		t.Fatalf("initial JWKS %v", kids)
	}
	old := kids[0]

	c := following(t)
	if status, body := rp.login(c, "/login", "/"); status != http.StatusOK {
		t.Fatalf("first login: %d %q (%v)", status, body, rp.lastErr())
	}
	first := rp.lastLogin()
	if jwsKID(t, first.Tokens.IDToken) != old || rp.keyFetches.Load() != 1 {
		t.Fatalf("first token kid %s, %d key fetches", jwsKID(t, first.Tokens.IDToken), rp.keyFetches.Load())
	}

	st, body := e.send(root, http.MethodPost, "/api/admin/signing-keys/rotate", map[string]any{})
	wantStatus(t, "rotate", st, http.StatusCreated, body)
	fresh, _ := body["kid"].(string)

	// The next token is under the new key: the cached client fetches the
	// key set once more and verifies it.
	if status, _ := rp.login(c, "/login", "/"); status != http.StatusOK {
		t.Fatalf("login after rotation: %d (%v)", status, rp.lastErr())
	}
	second := rp.lastLogin()
	if jwsKID(t, second.Tokens.IDToken) != fresh {
		t.Fatalf("token after rotation signed with %s, want %s", jwsKID(t, second.Tokens.IDToken), fresh)
	}
	if n := rp.keyFetches.Load(); n != 2 {
		t.Fatalf("%d key fetches after rotation, want 2", n)
	}
	if status, _ := rp.login(c, "/login", "/"); status != http.StatusOK || rp.keyFetches.Load() != 2 {
		t.Fatalf("third login: %d, %d key fetches (want 2, cached)", status, rp.keyFetches.Load())
	}

	st, body = e.send(root, http.MethodPost, "/api/admin/signing-keys/"+old+"/retire", map[string]any{})
	wantStatus(t, "retire", st, http.StatusNoContent, body)
	if got := e.jwksKIDs(); len(got) != 1 || got[0] != fresh {
		t.Fatalf("JWKS after retiring %v", got)
	}

	// The client that cached the old key keeps verifying tokens under it
	// until its cache ages out, which is why retiring must wait for the
	// ID-token lifetime. A client that starts now only knows the new key.
	if _, err := rp.c.VerifyIDToken(ctx, first.Tokens.IDToken, ""); err != nil {
		t.Fatalf("cached client, old-key token: %v", err)
	}
	newcomer, err := client.New(ctx, rp.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = newcomer.VerifyIDToken(ctx, first.Tokens.IDToken, "")
	if !errors.Is(err, client.ErrInvalidToken) || !strings.Contains(err.Error(), "unknown key id") {
		t.Fatalf("fresh client, old-key token: %v", err)
	}
	if _, err := newcomer.VerifyIDToken(ctx, second.Tokens.IDToken, ""); err != nil {
		t.Fatalf("fresh client, new-key token: %v", err)
	}
}

func TestClientBackchannelLogout(t *testing.T) {
	e := newOIDCEnv(t)
	rp := newRelyingParty(t, e)
	app, secret := rp.register("rpbc", store.AuthBasic)
	rp.connect(client.Config{ClientID: app.ClientID, ClientSecret: secret}, "rp_bc")
	uri := rp.srv.URL + "/backchannel-logout"
	if err := e.st.UpdateApp(app.ID, store.AppUpdate{BackchannelLogoutURI: &uri}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sub := strconv.FormatInt(e.user.ID, 10)

	c := following(t)
	if status, _ := rp.login(c, "/login", "/"); status != http.StatusOK {
		t.Fatalf("login: %d (%v)", status, rp.lastErr())
	}
	sid := rp.lastLogin().Claims.SID

	// Signing out at Fire ID queues one notification for the app; the
	// worker delivers it to the client's handler.
	if st, body := e.postJSON(c, "/api/auth/logout", map[string]any{}); st != http.StatusNoContent {
		t.Fatalf("logout: %d %v", st, body)
	}
	if n, _ := e.st.PendingBackchannel(app.ID); n != 1 {
		t.Fatalf("pending notifications %d, want 1", n)
	}
	backchannelWorker(t, e).Flush(ctx)
	rp.mu.Lock()
	logouts, raws := rp.logouts, rp.rawLogouts
	rp.mu.Unlock()
	if len(logouts) != 1 || len(raws) != 1 {
		t.Fatalf("handler saw %d logouts, %d raw tokens", len(logouts), len(raws))
	}
	lt := logouts[0]
	if lt.Issuer != e.issuer || lt.Subject != sub || lt.SID != sid || lt.JTI == "" || lt.Expiry.Before(lt.IssuedAt) {
		t.Fatalf("logout token %+v (want sid %s)", lt, sid)
	}
	if n, _ := e.st.PendingBackchannel(app.ID); n != 0 {
		t.Fatalf("pending after delivery %d: the handler's answer was not a 2xx", n)
	}
	if typ := typHeader(t, raws[0]); typ != "logout+jwt" {
		t.Fatalf("logout token typ %q", typ)
	}

	// The handler used the jti: the same token is a replay for this client.
	if _, err := rp.c.VerifyLogoutToken(ctx, raws[0]); !errors.Is(err, client.ErrInvalidToken) || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replay through the same client: %v", err)
	}
	// A client that has not seen it verifies it exactly once.
	other, err := client.New(ctx, rp.cfg)
	if err != nil {
		t.Fatal(err)
	}
	lt2, err := other.VerifyLogoutToken(ctx, raws[0])
	if err != nil {
		t.Fatal(err)
	}
	if lt2.SID != sid || lt2.Subject != sub {
		t.Fatalf("verified logout token %+v", lt2)
	}
	if _, err := other.VerifyLogoutToken(ctx, raws[0]); !errors.Is(err, client.ErrInvalidToken) {
		t.Fatalf("second verification: %v", err)
	}
}

func TestClientTrustedHeaders(t *testing.T) {
	e := newForwardEnv(t, store.AccessAllUsers)
	group, err := e.st.CreateGroup("staff", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetUserGroups(e.user.ID, []int64{group.ID}); err != nil {
		t.Fatal(err)
	}
	sub := strconv.FormatInt(e.user.ID, 10)

	c := e.browser()
	e.passwordSignIn(c, "alice")
	e.signInToSite(c, siteOrigin+"/docs")
	authz := e.viaProxy(c, "/api/authz/forward", siteOrigin+"/docs")
	if authz.StatusCode != http.StatusNoContent {
		t.Fatalf("forward: %d", authz.StatusCode)
	}

	// The backend behind nginx: bound to loopback, so what the proxy
	// forwards comes from a trusted address. The identity headers are
	// copied from the subrequest's answer, as the location snippet does.
	var seen struct {
		sync.Mutex
		id *client.HeaderIdentity
	}
	mw := client.TrustedHeaders{Required: true}.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := client.IdentityFrom(r.Context())
		seen.Lock()
		seen.id = id
		seen.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	backend := httptest.NewServer(mw)
	defer backend.Close()
	identityHeaders := []string{"X-FireID-User", "X-FireID-Email", "X-FireID-Name", "X-FireID-Groups", "X-FireID-Sub"}
	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/docs", nil)
	for _, h := range identityHeaders {
		req.Header.Set(h, authz.Header.Get(h))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("backend: %d", resp.StatusCode)
	}
	seen.Lock()
	id := seen.id
	seen.Unlock()
	if id == nil || id.Subject != sub || id.Username != "alice" || id.Email != "alice@example.com" || id.Name != "Alice" ||
		len(id.Groups) != 1 || id.Groups[0] != "staff" {
		t.Fatalf("identity %+v", id)
	}

	// The same headers from anywhere but the proxy are stripped, and with
	// Required the request is refused.
	forged := httptest.NewRequest(http.MethodGet, "/docs", nil)
	forged.RemoteAddr = "203.0.113.5:4040"
	for _, h := range identityHeaders {
		forged.Header.Set(h, authz.Header.Get(h))
	}
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, forged)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged identity from off-host: %d", rec.Code)
	}
}
