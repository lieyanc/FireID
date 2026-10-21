package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/config"
	"github.com/lieyanc/FireID/internal/secretbox"
	"github.com/lieyanc/FireID/internal/store"
)

// The RFC 7636 appendix B example.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	rpCallback    = "https://rp.example/cb"
	nativeLoop    = "http://127.0.0.1/callback"
	testPassword  = "correct horse battery staple"
)

// oidcEnv is a running Fire ID with a user and three apps.
type oidcEnv struct {
	t      *testing.T
	ts     *httptest.Server
	issuer string
	st     *store.Store
	auth   *auth.Service
	mailer *fakeMailer
	// logs holds what the server logged at Info and above.
	logs *logBuffer
	user *store.User
	root *store.User

	// web is a confidential client_secret_post app like new-api.
	web       *store.App
	webSecret string
	// native is a public PKCE app.
	native *store.App
	// closed is an app the user is not a member of.
	closed       *store.App
	closedSecret string
}

func newOIDCEnv(t *testing.T) *oidcEnv {
	t.Helper()
	return newEnvWith(t, nil)
}

// newEnvWith is newOIDCEnv with a hook to change the authentication policy.
func newEnvWith(t *testing.T, tweak func(*auth.Config)) *oidcEnv {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	issuer := "http://" + ts.Listener.Addr().String()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := fmt.Sprintf(`{"server":{"host":"127.0.0.1","port":8099,"publicUrl":%q},"dataDir":%q}`,
		issuer, filepath.Join(dir, "data"))
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgStore, _, err := config.Open(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	master, err := cfgStore.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	box, err := secretbox.New(master)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfgStore.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logs := &logBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	authCfg := auth.Config{SessionTTL: time.Hour, PasswordMinLength: 10}
	if tweak != nil {
		tweak(&authCfg)
	}
	authSvc, err := auth.New(st, box, authCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	authSvc.SetIssuer(issuer)
	mailer := &fakeMailer{enabled: true}
	authSvc.SetMailer(mailer)
	t.Cleanup(authSvc.WaitForMail)

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	env := &oidcEnv{t: t, ts: ts, issuer: issuer, st: st, auth: authSvc, mailer: mailer, logs: logs}
	env.user, err = st.CreateUser(store.NewUser{Username: "alice", Email: "alice@example.com",
		DisplayName: "Alice", PasswordHash: hash, Status: store.UserActive})
	if err != nil {
		t.Fatal(err)
	}
	// The super admin owns the apps: an owner is a member, and alice must
	// reach each app only through its access rules.
	root, err := st.CreateUser(store.NewUser{Username: "root", Email: "root@example.com",
		PasswordHash: hash, Status: store.UserActive, IsSuperAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	env.root = root

	env.web, env.webSecret, err = st.CreateApp(store.NewApp{
		Slug: "web", Name: "Web", OwnerUserID: root.ID, TEAuthMethod: store.AuthPost,
		RedirectURIs: []string{rpCallback}, PostLogoutRedirectURIs: []string{"https://rp.example/bye"},
		Scopes:        []string{"openid", "profile", "email"},
		DefaultAccess: store.AccessAllUsers,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.native, _, err = st.CreateApp(store.NewApp{
		Slug: "cli", Name: "CLI", OwnerUserID: root.ID, ClientType: store.ClientPublic,
		TEAuthMethod: store.AuthNone, RedirectURIs: []string{nativeLoop},
		DefaultAccess: store.AccessAllUsers,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.closed, env.closedSecret, err = st.CreateApp(store.NewApp{
		Slug: "closed", Name: "Closed", OwnerUserID: root.ID,
		RedirectURIs: []string{rpCallback}, DefaultAccess: store.AccessMembersOnly,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Deps{Store: st, Auth: authSvc, Config: cfgStore, SecretBox: box, Log: log,
		PublicBase: issuer, Started: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	return env
}

// browser is a cookie-carrying client that does not follow redirects.
func (e *oidcEnv) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func (e *oidcEnv) get(c *http.Client, path string) *http.Response {
	e.t.Helper()
	resp, err := c.Get(e.abs(path))
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func (e *oidcEnv) abs(path string) string {
	if strings.HasPrefix(path, "http") {
		return path
	}
	return e.issuer + path
}

// postForm sends a form as a same-origin browser would.
func (e *oidcEnv) postForm(c *http.Client, path string, form url.Values, basicUser, basicPass string) (*http.Response, map[string]any) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.abs(path), strings.NewReader(form.Encode()))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(url.QueryEscape(basicUser), url.QueryEscape(basicPass))
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &body)
	return resp, body
}

func location(t *testing.T, resp *http.Response, wantStatus int) *url.URL {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s: status %d, want %d", resp.Request.URL.Path, resp.StatusCode, wantStatus)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !u.IsAbs() {
		u = resp.Request.URL.ResolveReference(u)
	}
	return u
}

// authorize runs the browser part of the flow and returns the redirect the
// client receives. When signIn is set the browser signs in through the form.
func (e *oidcEnv) authorize(c *http.Client, params url.Values, signIn bool) *url.URL {
	e.t.Helper()
	params.Set("response_type", "code")
	loc := location(e.t, e.get(c, "/authorize?"+params.Encode()), http.StatusFound)
	if loc.Path != "/login" {
		return loc // an error sent straight back to the client
	}
	authReqID := loc.Query().Get("auth_req_id")
	loc = location(e.t, e.get(c, loc.String()), http.StatusFound)
	if loc.Path == "/sign-in" {
		if !signIn {
			e.t.Fatalf("login required but signIn is false")
		}
		if loc.Query().Get("auth_req_id") != authReqID {
			e.t.Fatalf("login page lost the request id")
		}
		resp, _ := e.postForm(c, "/oidc/login", url.Values{
			"auth_req_id": {authReqID}, "username": {"alice"}, "password": {testPassword},
		}, "", "")
		loc = location(e.t, resp, http.StatusSeeOther)
	}
	if loc.Path != "/authorize/callback" {
		return loc
	}
	return location(e.t, e.get(c, loc.String()), http.StatusFound)
}

func (e *oidcEnv) webParams(scope string) url.Values {
	return url.Values{"client_id": {e.web.ClientID}, "redirect_uri": {rpCallback},
		"scope": {scope}, "state": {"st-1"}, "nonce": {"n-1"}}
}

func (e *oidcEnv) exchangeWeb(code string) (*http.Response, map[string]any) {
	return e.postForm(http.DefaultClient, "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback},
		"client_id": {e.web.ClientID}, "client_secret": {e.webSecret},
	}, "", "")
}

func (e *oidcEnv) userinfo(accessToken string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// verifyIDToken checks the signature against /keys and returns the claims.
func (e *oidcEnv) verifyIDToken(raw string) map[string]any {
	e.t.Helper()
	resp, err := http.Get(e.issuer + "/keys")
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	keysRaw, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(keysRaw), `"d"`) {
		e.t.Fatalf("JWKS contains private key material: %s", keysRaw)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(keysRaw, &set); err != nil {
		e.t.Fatal(err)
	}
	sig, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		e.t.Fatal(err)
	}
	keys := set.Key(sig.Signatures[0].Header.KeyID)
	if len(keys) != 1 {
		e.t.Fatalf("kid %q: %d keys in JWKS", sig.Signatures[0].Header.KeyID, len(keys))
	}
	payload, err := sig.Verify(keys[0])
	if err != nil {
		e.t.Fatalf("id_token signature: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		e.t.Fatal(err)
	}
	return claims
}

func audContains(claims map[string]any, clientID string) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == clientID
	case []any:
		for _, a := range aud {
			if a == clientID {
				return true
			}
		}
	}
	return false
}

func TestOIDCDiscovery(t *testing.T) {
	e := newOIDCEnv(t)
	resp, err := http.Get(e.issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != e.issuer {
		t.Errorf("issuer %v, want %s", doc["issuer"], e.issuer)
	}
	if got := fmt.Sprint(doc["response_types_supported"]); got != "[code]" {
		t.Errorf("response_types_supported %s, want [code]", got)
	}
	if got := fmt.Sprint(doc["grant_types_supported"]); got != "[authorization_code refresh_token]" {
		t.Errorf("grant_types_supported %s", got)
	}
	if doc["authorization_response_iss_parameter_supported"] != true {
		t.Error("iss parameter not advertised")
	}
	if _, ok := doc["device_authorization_endpoint"]; ok {
		t.Error("device endpoint advertised but not offered")
	}
	if got := fmt.Sprint(doc["token_endpoint_auth_methods_supported"]); strings.Contains(got, "private_key_jwt") {
		t.Errorf("private_key_jwt advertised: %s", got)
	}
	if e.get(http.DefaultClient, "/device_authorization").StatusCode != http.StatusNotFound {
		t.Error("device endpoint reachable")
	}
}

func TestOIDCCodeFlowConfidential(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.browser()

	cb := e.authorize(c, e.webParams("openid profile email"), true)
	q := cb.Query()
	if cb.Host != "rp.example" || q.Get("code") == "" {
		t.Fatalf("callback %s", cb)
	}
	if q.Get("state") != "st-1" || q.Get("iss") != e.issuer {
		t.Fatalf("callback state=%q iss=%q", q.Get("state"), q.Get("iss"))
	}

	resp, tok := e.exchangeWeb(q.Get("code"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	if _, ok := tok["refresh_token"]; ok {
		t.Error("refresh token issued without offline_access")
	}

	claims := e.verifyIDToken(tok["id_token"].(string))
	sub := strconv.FormatInt(e.user.ID, 10)
	switch {
	case claims["iss"] != e.issuer:
		t.Errorf("iss %v", claims["iss"])
	case !audContains(claims, e.web.ClientID):
		t.Errorf("aud %v", claims["aud"])
	case claims["nonce"] != "n-1":
		t.Errorf("nonce %v", claims["nonce"])
	case claims["sub"] != sub:
		t.Errorf("sub %v, want %s", claims["sub"], sub)
	case claims["email"] != "alice@example.com":
		t.Errorf("email %v", claims["email"])
	case claims["acr"] != store.ACRLoA1:
		t.Errorf("acr %v", claims["acr"])
	case claims["auth_time"] == nil:
		t.Error("auth_time missing")
	}

	status, info := e.userinfo(tok["access_token"].(string))
	if status != http.StatusOK {
		t.Fatalf("userinfo: %d", status)
	}
	if info["sub"] != sub || info["email"] != "alice@example.com" ||
		info["preferred_username"] != "alice" || info["name"] != "Alice" {
		t.Fatalf("userinfo %v", info)
	}

	t.Run("code replay is refused and revokes the first exchange", func(t *testing.T) {
		resp, body := e.exchangeWeb(q.Get("code"))
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("replay: %d %v", resp.StatusCode, body)
		}
		if status, _ := e.userinfo(tok["access_token"].(string)); status == http.StatusOK {
			t.Fatal("access token survived a code replay")
		}
	})

	t.Run("signed-in browser goes straight through", func(t *testing.T) {
		cb := e.authorize(c, e.webParams("openid"), false)
		if cb.Query().Get("code") == "" {
			t.Fatalf("callback %s", cb)
		}
	})

	t.Run("prompt=none without a session returns login_required", func(t *testing.T) {
		p := e.webParams("openid")
		p.Set("prompt", "none")
		cb := e.authorize(e.browser(), p, false)
		if cb.Query().Get("error") != "login_required" || cb.Query().Get("state") != "st-1" {
			t.Fatalf("callback %s", cb)
		}
	})

	t.Run("prompt=login forces a new sign-in", func(t *testing.T) {
		p := e.webParams("openid")
		p.Set("prompt", "login")
		loc := location(t, e.get(c, "/authorize?"+url.Values{"response_type": {"code"}}.Encode()+"&"+p.Encode()), http.StatusFound)
		loc = location(t, e.get(c, loc.String()), http.StatusFound)
		if loc.Path != "/sign-in" || loc.Query().Get("reauth") != "1" {
			t.Fatalf("prompt=login skipped the sign-in: %s", loc)
		}
	})

	t.Run("wrong client secret", func(t *testing.T) {
		cb := e.authorize(c, e.webParams("openid"), false)
		resp, body := e.postForm(http.DefaultClient, "/oauth/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {rpCallback},
			"client_id": {e.web.ClientID}, "client_secret": {"wrong"},
		}, "", "")
		if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Fatalf("got %d %v", resp.StatusCode, body)
		}
	})
}

func TestOIDCRefreshRotation(t *testing.T) {
	e := newOIDCEnv(t)
	// The default grant types of a new app include refresh_token.
	if err := e.st.SetMembership(e.web.ID, e.user.ID, store.RoleMember, store.MemberActive, 0); err != nil {
		t.Fatal(err)
	}
	c := e.browser()
	cb := e.authorize(c, e.webParams("openid email offline_access"), true)
	resp, tok := e.exchangeWeb(cb.Query().Get("code"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	first, _ := tok["refresh_token"].(string)
	if first == "" {
		t.Fatal("no refresh token")
	}

	refresh := func(rt string) (*http.Response, map[string]any) {
		return e.postForm(http.DefaultClient, "/oauth/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt},
			"client_id": {e.web.ClientID}, "client_secret": {e.webSecret},
		}, "", "")
	}
	resp, next := refresh(first)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", resp.StatusCode, next)
	}
	second := next["refresh_token"].(string)
	if second == first {
		t.Fatal("refresh token was not rotated")
	}
	claims := e.verifyIDToken(next["id_token"].(string))
	if claims["sub"] != strconv.FormatInt(e.user.ID, 10) || claims["auth_time"] == nil {
		t.Fatalf("refreshed id_token claims %v", claims)
	}

	resp, body := refresh(first)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", resp.StatusCode, body)
	}
	if resp, body := refresh(second); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("descendant survived a replay: %d %v", resp.StatusCode, body)
	}

	t.Run("revocation ends the grant", func(t *testing.T) {
		cb := e.authorize(c, e.webParams("openid offline_access"), false)
		_, tok := e.exchangeWeb(cb.Query().Get("code"))
		rt := tok["refresh_token"].(string)
		at := tok["access_token"].(string)
		resp, _ := e.postForm(http.DefaultClient, "/revoke", url.Values{"token": {rt}}, e.web.ClientID, e.webSecret)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke: %d", resp.StatusCode)
		}
		if resp, _ := refresh(rt); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("revoked token refreshed: %d", resp.StatusCode)
		}
		if status, _ := e.userinfo(at); status == http.StatusOK {
			t.Fatal("access token from a revoked grant still works")
		}
	})

	t.Run("blocked membership stops refresh", func(t *testing.T) {
		cb := e.authorize(c, e.webParams("openid offline_access"), false)
		_, tok := e.exchangeWeb(cb.Query().Get("code"))
		if err := e.st.SetMembership(e.web.ID, e.user.ID, store.RoleMember, store.MemberBlocked, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = e.st.SetMembership(e.web.ID, e.user.ID, store.RoleMember, store.MemberActive, 0) }()
		if resp, _ := refresh(tok["refresh_token"].(string)); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("blocked user refreshed: %d", resp.StatusCode)
		}
		if status, _ := e.userinfo(tok["access_token"].(string)); status == http.StatusOK {
			t.Fatal("blocked user read userinfo")
		}
	})
}

func TestOIDCPublicClientPKCE(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.browser()
	params := func() url.Values {
		return url.Values{"client_id": {e.native.ClientID}, "scope": {"openid"},
			// Any loopback port is accepted for a native client (RFC 8252).
			"redirect_uri": {"http://127.0.0.1:53682/callback"}, "state": {"s"}}
	}

	t.Run("loopback host must match the registration", func(t *testing.T) {
		p := params()
		p.Set("redirect_uri", "http://localhost:53682/callback")
		p.Set("code_challenge", pkceChallenge)
		p.Set("code_challenge_method", "S256")
		resp := e.get(c, "/authorize?response_type=code&"+p.Encode())
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Fatalf("got %d, Location %q; want 400 without a redirect", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("missing challenge is refused", func(t *testing.T) {
		cb := e.authorize(c, params(), true)
		if cb.Query().Get("error") != "invalid_request" {
			t.Fatalf("callback %s", cb)
		}
	})

	t.Run("plain challenge is refused", func(t *testing.T) {
		p := params()
		p.Set("code_challenge", pkceVerifier)
		p.Set("code_challenge_method", "plain")
		cb := e.authorize(c, p, true)
		if cb.Query().Get("error") != "invalid_request" {
			t.Fatalf("callback %s", cb)
		}
	})

	exchange := func(code, verifier string) (*http.Response, map[string]any) {
		return e.postForm(http.DefaultClient, "/oauth/token", url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {"http://127.0.0.1:53682/callback"},
			"client_id":    {e.native.ClientID}, "code_verifier": {verifier},
		}, "", "")
	}
	withChallenge := func() url.Values {
		p := params()
		p.Set("code_challenge", pkceChallenge)
		p.Set("code_challenge_method", "S256")
		return p
	}

	t.Run("wrong verifier is refused and burns the code", func(t *testing.T) {
		code := e.authorize(c, withChallenge(), true).Query().Get("code")
		if resp, body := exchange(code, strings.Repeat("a", 43)); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("wrong verifier: %d %v", resp.StatusCode, body)
		}
		if resp, _ := exchange(code, pkceVerifier); resp.StatusCode != http.StatusBadRequest {
			t.Fatal("code usable after a failed exchange")
		}
	})

	t.Run("RFC 7636 vector", func(t *testing.T) {
		code := e.authorize(c, withChallenge(), true).Query().Get("code")
		resp, tok := exchange(code, pkceVerifier)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("token: %d %v", resp.StatusCode, tok)
		}
		claims := e.verifyIDToken(tok["id_token"].(string))
		if !audContains(claims, e.native.ClientID) {
			t.Fatalf("aud %v", claims["aud"])
		}
		// No email scope: the claim must not appear.
		if _, ok := claims["email"]; ok {
			t.Fatal("email claim without the email scope")
		}
	})
}

func TestOIDCAccessDenied(t *testing.T) {
	e := newOIDCEnv(t)
	cb := e.authorize(e.browser(), url.Values{"client_id": {e.closed.ClientID}, "redirect_uri": {rpCallback},
		"scope": {"openid"}, "state": {"s"}}, true)
	if cb.Query().Get("error") != "access_denied" || cb.Query().Get("iss") != e.issuer {
		t.Fatalf("callback %s", cb)
	}
}

func TestOIDCIntrospection(t *testing.T) {
	e := newOIDCEnv(t)
	cb := e.authorize(e.browser(), e.webParams("openid"), true)
	_, tok := e.exchangeWeb(cb.Query().Get("code"))
	at := tok["access_token"].(string)

	resp, body := e.postForm(http.DefaultClient, "/oauth/introspect", url.Values{"token": {at}}, e.web.ClientID, e.webSecret)
	if resp.StatusCode != http.StatusOK || body["active"] != true || body["client_id"] != e.web.ClientID {
		t.Fatalf("own token: %d %v", resp.StatusCode, body)
	}
	_, body = e.postForm(http.DefaultClient, "/oauth/introspect", url.Values{"token": {at}}, e.closed.ClientID, e.closedSecret)
	if body["active"] != false {
		t.Fatalf("another client's token reported active: %v", body)
	}
	_, body = e.postForm(http.DefaultClient, "/oauth/introspect",
		url.Values{"token": {base64.RawURLEncoding.EncodeToString([]byte("forged"))}}, e.web.ClientID, e.webSecret)
	if body["active"] != false {
		t.Fatalf("forged token reported active: %v", body)
	}
}

func TestOIDCEndSession(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.browser()
	cb := e.authorize(c, e.webParams("openid"), true)
	_, tok := e.exchangeWeb(cb.Query().Get("code"))

	t.Run("without a hint the browser stays signed in", func(t *testing.T) {
		loc := location(t, e.get(c, "/end_session"), http.StatusFound)
		if loc.String() != e.issuer+"/" {
			t.Fatalf("redirect %s", loc)
		}
		if cb := e.authorize(c, e.webParams("openid"), false); cb.Query().Get("code") == "" {
			t.Fatalf("session lost: %s", cb)
		}
	})

	t.Run("with a hint the browser is signed out", func(t *testing.T) {
		q := url.Values{"id_token_hint": {tok["id_token"].(string)},
			"post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {"x"}}
		loc := location(t, e.get(c, "/end_session?"+q.Encode()), http.StatusFound)
		if loc.Host != "rp.example" || loc.Query().Get("state") != "x" {
			t.Fatalf("redirect %s", loc)
		}
		p := e.webParams("openid")
		p.Set("prompt", "none")
		if cb := e.authorize(c, p, false); cb.Query().Get("error") != "login_required" {
			t.Fatalf("still signed in: %s", cb)
		}
	})

	t.Run("unregistered post-logout redirect is refused", func(t *testing.T) {
		q := url.Values{"client_id": {e.web.ClientID}, "post_logout_redirect_uri": {"https://evil.example/"}}
		if resp := e.get(c, "/end_session?"+q.Encode()); resp.StatusCode == http.StatusFound &&
			strings.Contains(resp.Header.Get("Location"), "evil.example") {
			t.Fatal("open redirect on logout")
		}
	})
}
