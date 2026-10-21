package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lieyanc/FireID/client"
	"github.com/lieyanc/FireID/internal/store"
)

// These tests follow the OpenID Foundation conformance suite's OP test
// plans: oidcc-basic-certification-test-plan, oidcc-config-certification-
// test-plan, oidcc-rp-initiated-logout-certification-test-plan and
// oidcc-backchannel-rp-initiated-logout-certification-test-plan. Each test
// names the plan items it stands in for; docs/conformance.md has the map.

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// --- Discovery: oidcc-discovery-endpoint-verification, config plan ---

func TestConformanceDiscovery(t *testing.T) {
	e := newOIDCEnv(t)
	r := e.fetch(http.DefaultClient, "/.well-known/openid-configuration")
	if r.status != http.StatusOK || !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
		t.Fatalf("discovery: %d %q", r.status, r.header.Get("Content-Type"))
	}
	doc := e.discoveryDoc()

	t.Run("issuer equals the base URL", func(t *testing.T) {
		if doc["issuer"] != e.issuer {
			t.Fatalf("issuer %v, want %s", doc["issuer"], e.issuer)
		}
		// The client module refuses a document whose issuer differs from
		// the URL it was fetched from, as OIDC Discovery 4.3 asks.
		if _, err := client.Discover(context.Background(), e.issuer); err != nil {
			t.Fatalf("client discovery: %v", err)
		}
	})

	endpoints := []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
		"end_session_endpoint", "revocation_endpoint", "introspection_endpoint"}
	t.Run("endpoints are under the issuer and resolve", func(t *testing.T) {
		for _, name := range endpoints {
			raw, ok := doc[name].(string)
			if !ok || !strings.HasPrefix(raw, e.issuer+"/") {
				t.Errorf("%s = %v, want a URL under %s", name, doc[name], e.issuer)
				continue
			}
			// No parameters: every endpoint must answer with its own error,
			// not a 404 or a server error.
			method := http.MethodGet
			if name == "token_endpoint" || name == "revocation_endpoint" || name == "introspection_endpoint" {
				method = http.MethodPost
			}
			req, _ := http.NewRequest(method, raw, strings.NewReader(""))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			got := e.do(e.browser(), req)
			if got.status == http.StatusNotFound || got.status >= 500 {
				t.Errorf("%s %s: %d", method, name, got.status)
			}
		}
	})

	t.Run("metadata members have the right type", func(t *testing.T) {
		lists := []string{"response_types_supported", "subject_types_supported",
			"id_token_signing_alg_values_supported", "scopes_supported", "claims_supported",
			"token_endpoint_auth_methods_supported", "grant_types_supported", "response_modes_supported",
			"code_challenge_methods_supported"}
		for _, name := range lists {
			arr, ok := doc[name].([]any)
			if !ok || len(arr) == 0 {
				t.Errorf("%s = %v, want a non-empty array", name, doc[name])
				continue
			}
			for _, v := range arr {
				if _, ok := v.(string); !ok {
					t.Errorf("%s holds %T", name, v)
				}
			}
		}
		for _, name := range []string{"request_parameter_supported", "request_uri_parameter_supported",
			"claims_parameter_supported", "backchannel_logout_supported", "backchannel_logout_session_supported",
			"authorization_response_iss_parameter_supported"} {
			if v, ok := doc[name]; ok {
				if _, isBool := v.(bool); !isBool {
					t.Errorf("%s = %v, want a boolean", name, v)
				}
			}
		}
	})

	strs := func(name string) []string {
		var out []string
		for _, v := range doc[name].([]any) {
			out = append(out, v.(string))
		}
		return out
	}
	t.Run("advertises only what is implemented", func(t *testing.T) {
		checks := []struct {
			name    string
			allowed []string
			need    []string
		}{
			{"response_types_supported", []string{"code"}, []string{"code"}},
			{"response_modes_supported", []string{"query"}, []string{"query"}},
			{"subject_types_supported", []string{"public"}, []string{"public"}},
			{"grant_types_supported", []string{"authorization_code", "refresh_token"}, []string{"authorization_code"}},
			{"code_challenge_methods_supported", []string{"S256"}, []string{"S256"}},
			{"token_endpoint_auth_methods_supported", []string{"client_secret_basic", "client_secret_post", "none"},
				[]string{"client_secret_basic", "client_secret_post"}},
			{"id_token_signing_alg_values_supported", []string{"ES256", "RS256"}, nil},
			{"scopes_supported", []string{"openid", "profile", "email", "offline_access"}, []string{"openid"}},
		}
		for _, c := range checks {
			got := strs(c.name)
			for _, v := range got {
				if !slices.Contains(c.allowed, v) {
					t.Errorf("%s advertises %q", c.name, v)
				}
			}
			for _, v := range c.need {
				if !slices.Contains(got, v) {
					t.Errorf("%s lacks %q", c.name, v)
				}
			}
		}
		for _, claim := range []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid"} {
			if !slices.Contains(strs("claims_supported"), claim) {
				t.Errorf("claims_supported lacks %s", claim)
			}
		}
		if doc["request_parameter_supported"] != false || doc["request_uri_parameter_supported"] != false {
			t.Errorf("request objects advertised: %v %v", doc["request_parameter_supported"], doc["request_uri_parameter_supported"])
		}
	})

	t.Run("JWKS serves the advertised public keys", func(t *testing.T) {
		r := e.fetch(http.DefaultClient, doc["jwks_uri"].(string))
		if r.status != http.StatusOK || !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
			t.Fatalf("jwks: %d %q", r.status, r.header.Get("Content-Type"))
		}
		var set struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal([]byte(r.body), &set); err != nil || len(set.Keys) == 0 {
			t.Fatalf("jwks %s: %v", r.body, err)
		}
		advertised := strs("id_token_signing_alg_values_supported")
		seen := map[string]bool{}
		for _, k := range set.Keys {
			kid, _ := k["kid"].(string)
			alg, _ := k["alg"].(string)
			if kid == "" || seen[kid] {
				t.Errorf("key without a unique kid: %v", k)
			}
			seen[kid] = true
			if !slices.Contains(advertised, alg) {
				t.Errorf("key %s alg %q not advertised in %v", kid, alg, advertised)
			}
			if use, ok := k["use"]; ok && use != "sig" {
				t.Errorf("key %s use %v", kid, use)
			}
			for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
				if _, ok := k[private]; ok {
					t.Errorf("key %s publishes private member %s", kid, private)
				}
			}
		}
	})

	t.Run("an ID token verifies against the JWKS", func(t *testing.T) {
		tok := e.webTokens(e.browser(), "openid")
		raw := tok["id_token"].(string)
		e.verifyIDToken(raw)
		if alg := jwsHeader(t, raw)["alg"]; !slices.Contains(strs("id_token_signing_alg_values_supported"), alg.(string)) {
			t.Fatalf("id_token alg %v not advertised", alg)
		}
	})

	t.Run("RS256 is advertised (OIDC Core 15.1)", func(t *testing.T) {
		if !slices.Contains(strs("id_token_signing_alg_values_supported"), "RS256") {
			knownGap(t, "id_token_signing_alg_values_supported is %v; OIDC Core 15.1 makes RS256 mandatory to implement, "+
				"and the default oidc.signingAlgorithm is ES256", strs("id_token_signing_alg_values_supported"))
		}
	})
}

// --- Authorization request validation ---

// authzErrorCase is an authorization request the provider must answer with
// an error at the redirect URI.
type authzErrorCase struct {
	name   string
	mutate func(url.Values)
	want   []string // acceptable error codes
}

func authzErrorCases() []authzErrorCase {
	set := func(k, v string) func(url.Values) { return func(p url.Values) { p.Set(k, v) } }
	// Implicit and hybrid are not offered. The requests carry no nonce,
	// which those flows would require; either way they must not succeed.
	refused := []string{"unsupported_response_type", "unauthorized_client"}
	return []authzErrorCase{
		{"response_type missing", func(p url.Values) { p.Del("response_type") }, []string{"invalid_request"}},
		{"response_type unknown", set("response_type", "bogus"), refused},
		{"implicit token without nonce", func(p url.Values) { p.Set("response_type", "token"); p.Del("nonce") }, refused},
		{"hybrid code id_token without nonce", func(p url.Values) { p.Set("response_type", "code id_token"); p.Del("nonce") }, refused},
		{"hybrid code token", set("response_type", "code token"), refused},
		{"hybrid code id_token token", set("response_type", "code id_token token"), refused},
		{"scope without openid", set("scope", "profile email"), []string{"invalid_scope", "invalid_request"}},
		{"scope missing", func(p url.Values) { p.Del("scope") }, []string{"invalid_scope", "invalid_request"}},
		{"request object", set("request", "eyJhbGciOiJub25lIn0.e30."), []string{"request_not_supported"}},
	}
}

func (e *oidcEnv) codeParams() url.Values {
	p := e.webParams("openid")
	p.Set("response_type", "code")
	return p
}

// wantAuthzError checks an error response at the web app's redirect URI.
func wantAuthzError(t *testing.T, e *oidcEnv, r reply, want []string, state string) url.Values {
	t.Helper()
	if r.status != http.StatusFound {
		t.Fatalf("status %d, want 302 to the client (body %q)", r.status, r.body)
	}
	loc := r.location(t)
	q := loc.Query()
	if loc.Scheme+"://"+loc.Host+loc.Path != rpCallback {
		t.Fatalf("redirect to %s, want %s", loc, rpCallback)
	}
	if !slices.Contains(want, q.Get("error")) {
		t.Fatalf("error %q, want one of %v (%s)", q.Get("error"), want, loc)
	}
	if q.Get("state") != state || q.Get("iss") != e.issuer || q.Has("code") {
		t.Fatalf("state=%q iss=%q code=%q", q.Get("state"), q.Get("iss"), q.Get("code"))
	}
	if leaksInternals(q.Get("error_description")) {
		t.Fatalf("error_description leaks internals: %q", q.Get("error_description"))
	}
	return q
}

// pageErrorCases are requests whose redirect URI cannot be trusted: the
// error must be shown in the browser, never redirected (RFC 6749 4.1.2.1).
func pageErrorCases(e *oidcEnv) []struct {
	name   string
	mutate func(url.Values)
} {
	set := func(k, v string) func(url.Values) { return func(p url.Values) { p.Set(k, v) } }
	return []struct {
		name   string
		mutate func(url.Values)
	}{
		{"unknown client_id", set("client_id", "no-such-client")},
		{"client_id missing", func(p url.Values) { p.Del("client_id") }},
		{"client_id with markup", set("client_id", "<script>alert(1)</script>")},
		{"unregistered redirect_uri", set("redirect_uri", "https://evil.example/cb")},
		{"redirect_uri with an added query", set("redirect_uri", rpCallback+"?x=1")},
		{"redirect_uri with a fragment", set("redirect_uri", rpCallback+"#frag")},
		{"redirect_uri with a different path case", set("redirect_uri", "https://rp.example/CB")},
		{"redirect_uri with a trailing slash", set("redirect_uri", rpCallback+"/")},
		{"redirect_uri missing", func(p url.Values) { p.Del("redirect_uri") }},
		{"another client's redirect_uri", func(p url.Values) { p.Set("redirect_uri", nativeLoop) }},
	}
}

func TestConformanceAuthorizationRequest(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.signedIn()

	// oidcc-response-type-missing and the request checks of OIDC Core
	// 3.1.2.2. The redirect_uri checks are in TestConformanceErrorResponses.
	for _, tc := range authzErrorCases() {
		t.Run("error to the client: "+tc.name, func(t *testing.T) {
			p := e.codeParams()
			tc.mutate(p)
			q := wantAuthzError(t, e, e.authorizeRaw(c, p), tc.want, "st-1")
			if q.Get("error_description") == "" {
				knownGap(t, "%s has no error_description (optional in RFC 6749 4.1.2.1)", q.Get("error"))
			}
		})
	}

	t.Run("implicit id_token without nonce is refused", func(t *testing.T) {
		p := e.codeParams()
		p.Set("response_type", "id_token")
		p.Del("nonce")
		r := e.authorizeRaw(c, p)
		loc := r.location(t)
		// The default response mode of id_token is fragment, so the error
		// travels there (OAuth 2.0 Multiple Response Types, section 5).
		frag, _ := url.ParseQuery(loc.Fragment)
		if r.status != http.StatusFound || loc.Host != "rp.example" || frag.Get("error") == "" ||
			frag.Get("state") != "st-1" || frag.Has("id_token") || loc.Query().Has("code") {
			t.Fatalf("%d %s", r.status, loc)
		}
		if frag.Get("iss") != e.issuer {
			knownGap(t, "iss is added to the query (%q) while the error is in the fragment; RFC 9207 puts it beside the "+
				"other response parameters (internal/oidc/provider.go addIssuer)", loc.RawQuery)
		}
	})

	t.Run("request_uri is refused", func(t *testing.T) {
		p := e.codeParams()
		p.Set("request_uri", "https://rp.example/request.jwt")
		r := e.authorizeRaw(c, p)
		if loc := r.location(t); loc.Query().Get("error") != "request_uri_not_supported" {
			knownGap(t, "request_uri is ignored (answer %d %s); OIDC Core 6.2 expects request_uri_not_supported", r.status, loc)
		}
	})

	accepted := []struct {
		name   string
		mutate func(url.Values)
	}{
		// oidcc-ensure-request-without-nonce-succeeds-for-code-flow
		{"without nonce", func(p url.Values) { p.Del("nonce") }},
		// oidcc-ensure-other-scope-order-succeeds
		{"other scope order", func(p url.Values) { p.Set("scope", "email openid") }},
		// oidcc-ensure-request-with-unknown-parameter-succeeds
		{"unknown parameter", func(p url.Values) { p.Set("extra", "foobar") }},
		// oidcc-display-page, oidcc-display-popup
		{"display=page", func(p url.Values) { p.Set("display", "page") }},
		{"display=popup", func(p url.Values) { p.Set("display", "popup") }},
		// oidcc-ui-locales, oidcc-claims-locales, oidcc-login-hint
		{"ui_locales", func(p url.Values) { p.Set("ui_locales", "se") }},
		{"claims_locales", func(p url.Values) { p.Set("claims_locales", "se") }},
		{"login_hint", func(p url.Values) { p.Set("login_hint", "alice") }},
		// oidcc-ensure-request-with-acr-values-succeeds
		{"unknown acr_values", func(p url.Values) { p.Set("acr_values", "1 2") }},
		// oidcc-claims-essential
		{"claims parameter", func(p url.Values) { p.Set("claims", `{"userinfo":{"name":{"essential":true}}}`) }},
		// oidcc-max-age-10000
		{"max_age=10000", func(p url.Values) { p.Set("max_age", "10000") }},
		// oidcc-prompt-none-logged-in
		{"prompt=none with a session", func(p url.Values) { p.Set("prompt", "none") }},
	}
	for _, tc := range accepted {
		t.Run("accepted: "+tc.name, func(t *testing.T) {
			p := e.webParams("openid")
			tc.mutate(p)
			cb := e.authorize(c, p, false)
			if cb.Query().Get("code") == "" || cb.Query().Get("state") != "st-1" {
				t.Fatalf("callback %s", cb)
			}
		})
	}

	t.Run("state is echoed unchanged", func(t *testing.T) {
		for _, state := range []string{"a b&c=d/é+%25?#", strings.Repeat("s", 512)} {
			p := e.webParams("openid")
			p.Set("state", state)
			if got := e.authorize(c, p, false).Query().Get("state"); got != state {
				t.Fatalf("state %q, want %q", got, state)
			}
		}
		p := e.webParams("openid")
		p.Del("state")
		if cb := e.authorize(c, p, false); cb.Query().Has("state") || cb.Query().Get("code") == "" {
			t.Fatalf("callback without state %s", cb)
		}
	})

	// oidcc-ensure-post-request-succeeds
	t.Run("authorization request by POST", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, e.issuer+"/authorize", strings.NewReader(e.codeParams().Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r := e.do(c, req)
		if r.status != http.StatusFound || r.location(t).Path != "/login" {
			t.Fatalf("POST /authorize: %d %s", r.status, r.header.Get("Location"))
		}
		loc := location(t, e.get(c, r.header.Get("Location")), http.StatusFound)
		loc = location(t, e.get(c, loc.String()), http.StatusFound)
		if loc.Host != "rp.example" || loc.Query().Get("code") == "" {
			t.Fatalf("callback %s", loc)
		}
	})

	t.Run("unsupported response_mode falls back to query", func(t *testing.T) {
		for _, mode := range []string{"fragment", "form_post", "bogus"} {
			p := e.webParams("openid")
			p.Set("response_mode", mode)
			cb := e.authorize(c, p, false)
			if cb.Query().Get("code") == "" || cb.Fragment != "" {
				t.Fatalf("response_mode=%s: %s", mode, cb)
			}
		}
	})

	// oidcc-prompt-none-not-logged-in: no page is shown, the error goes
	// straight back with the state.
	t.Run("prompt=none without a session", func(t *testing.T) {
		fresh := e.browser()
		p := e.codeParams()
		p.Set("prompt", "none")
		r := e.authorizeRaw(fresh, p)
		hops := 0
		for r.status == http.StatusFound && r.location(t).Host != "rp.example" {
			if hops++; hops > 3 || strings.HasPrefix(r.location(t).Path, "/sign-in") {
				t.Fatalf("interaction on prompt=none: %s", r.header.Get("Location"))
			}
			r = e.fetch(fresh, r.location(t).String())
		}
		q := wantAuthzError(t, e, r, []string{"login_required"}, "st-1")
		if q.Get("error_description") == "" {
			t.Error("no error_description")
		}
	})

	// oidcc-id-token-hint
	t.Run("prompt=none with the id_token_hint of the signed-in user", func(t *testing.T) {
		tok := e.webTokens(c, "openid")
		p := e.webParams("openid")
		p.Set("prompt", "none")
		p.Set("id_token_hint", tok["id_token"].(string))
		if cb := e.authorize(c, p, false); cb.Query().Get("code") == "" {
			t.Fatalf("callback %s", cb)
		}
	})

	// oidcc-max-age-1: an older session must sign in again, and auth_time
	// reports the new sign-in.
	t.Run("max_age=1 after the session aged", func(t *testing.T) {
		first := e.verifyIDToken(e.webTokens(c, "openid")["id_token"].(string))
		e.shiftClock(5 * time.Second)
		p := e.codeParams()
		p.Set("max_age", "1")
		r := e.authorizeRaw(c, p)
		loc := location(t, e.get(c, r.header.Get("Location")), http.StatusFound)
		if loc.Path != "/sign-in" {
			t.Fatalf("max_age=1 skipped the sign-in: %s", loc)
		}
		p.Del("response_type")
		cb := e.authorize(c, p, true)
		_, tok := e.exchangeWeb(cb.Query().Get("code"))
		second := e.verifyIDToken(tok["id_token"].(string))
		if second["auth_time"].(float64) <= first["auth_time"].(float64) {
			t.Fatalf("auth_time %v not after %v", second["auth_time"], first["auth_time"])
		}
	})
}

// --- PKCE (RFC 7636) ---

func TestConformancePKCE(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.signedIn()
	const loopback = "http://127.0.0.1:53682/callback"
	params := func(challenge, method string) url.Values {
		p := url.Values{"client_id": {e.native.ClientID}, "scope": {"openid"},
			"redirect_uri": {loopback}, "state": {"s"}}
		if challenge != "" {
			p.Set("code_challenge", challenge)
		}
		if method != "" {
			p.Set("code_challenge_method", method)
		}
		return p
	}
	exchange := func(code string, verifier *string) (*http.Response, map[string]any) {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {loopback}, "client_id": {e.native.ClientID}}
		if verifier != nil {
			form.Set("code_verifier", *verifier)
		}
		return e.postForm(http.DefaultClient, "/oauth/token", form, "", "")
	}
	ptr := func(s string) *string { return &s }

	refused := []struct{ name, challenge, method string }{
		{"public client without code_challenge", "", ""},
		{"plain method", pkceVerifier, "plain"},
		{"unknown method", pkceChallenge, "S512"},
		{"challenge without a method (defaults to plain)", pkceChallenge, ""},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			cb := e.authorize(c, params(tc.challenge, tc.method), false)
			if cb.Query().Get("error") != "invalid_request" || cb.Query().Get("state") != "s" || cb.Query().Has("code") {
				t.Fatalf("callback %s", cb)
			}
		})
	}

	// RFC 7636 4.6: a verifier that does not match is invalid_grant; a
	// missing one is a malformed request.
	redemptions := []struct {
		name     string
		verifier *string
		want     []string
	}{
		{"wrong verifier", ptr(strings.Repeat("a", 43)), []string{"invalid_grant"}},
		{"missing verifier", nil, []string{"invalid_grant", "invalid_request"}},
		{"verifier equal to the challenge", ptr(pkceChallenge), []string{"invalid_grant"}},
	}
	for _, tc := range redemptions {
		t.Run(tc.name, func(t *testing.T) {
			code := e.authorize(c, params(pkceChallenge, "S256"), false).Query().Get("code")
			resp, body := exchange(code, tc.verifier)
			if errCode, _ := body["error"].(string); resp.StatusCode != http.StatusBadRequest || !slices.Contains(tc.want, errCode) {
				t.Fatalf("%d %v", resp.StatusCode, body)
			}
		})
	}

	// oidcc-codereuse: a replayed code fails and revokes what the first
	// redemption produced.
	t.Run("code replayed after success", func(t *testing.T) {
		code := e.authorize(c, params(pkceChallenge, "S256"), false).Query().Get("code")
		resp, tok := exchange(code, ptr(pkceVerifier))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("first redemption: %d %v", resp.StatusCode, tok)
		}
		resp, body := exchange(code, ptr(pkceVerifier))
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("replay: %d %v", resp.StatusCode, body)
		}
		if st, _ := e.userinfo(tok["access_token"].(string)); st == http.StatusOK {
			t.Fatal("access token survived the replay")
		}
	})

	// oidcc-ensure-request-with-valid-pkce-succeeds, for a confidential
	// client that chooses to use PKCE.
	t.Run("confidential client with PKCE", func(t *testing.T) {
		p := e.webParams("openid")
		p.Set("code_challenge", pkceChallenge)
		p.Set("code_challenge_method", "S256")
		redeem := func(verifier string) (*http.Response, map[string]any) {
			code := e.authorize(c, p, false).Query().Get("code")
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback},
				"client_id": {e.web.ClientID}, "client_secret": {e.webSecret}}
			if verifier != "" {
				form.Set("code_verifier", verifier)
			}
			return e.postForm(http.DefaultClient, "/oauth/token", form, "", "")
		}
		if resp, body := redeem(pkceVerifier); resp.StatusCode != http.StatusOK {
			t.Fatalf("with verifier: %d %v", resp.StatusCode, body)
		}
		if resp, body := redeem(""); resp.StatusCode != http.StatusBadRequest ||
			(body["error"] != "invalid_grant" && body["error"] != "invalid_request") {
			t.Fatalf("without verifier: %d %v", resp.StatusCode, body)
		}
	})
}

// --- Token endpoint ---

func TestConformanceTokenEndpoint(t *testing.T) {
	e := newOIDCEnv(t)
	basic, basicSecret, err := e.st.CreateApp(store.NewApp{
		Slug: "basic", Name: "Basic", OwnerUserID: e.root.ID, TEAuthMethod: store.AuthBasic,
		RedirectURIs: []string{rpCallback}, Scopes: []string{"openid", "profile", "email"},
		DefaultAccess: store.AccessAllUsers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetMembership(e.web.ID, e.user.ID, store.RoleMember, store.MemberActive, 0); err != nil {
		t.Fatal(err)
	}
	c := e.signedIn()
	codeFor := func(app *store.App) string {
		p := e.webParams("openid")
		p.Set("client_id", app.ClientID)
		return e.authorize(c, p, false).Query().Get("code")
	}
	webCode := func() string { return codeFor(e.web) }
	type creds struct{ basicUser, basicPass string }
	token := func(form url.Values, cr creds) (*http.Response, map[string]any) {
		return e.postForm(http.DefaultClient, "/oauth/token", form, cr.basicUser, cr.basicPass)
	}
	codeForm := func(code string, extra ...string) url.Values {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}}
		for i := 0; i+1 < len(extra); i += 2 {
			f.Set(extra[i], extra[i+1])
		}
		return f
	}

	// oidcc-server (client_secret_basic), oidcc-server-client-secret-post,
	// and a public client with none.
	t.Run("client authentication methods", func(t *testing.T) {
		cases := []struct {
			name  string
			issue func() (url.Values, creds)
		}{
			{"client_secret_basic", func() (url.Values, creds) {
				return codeForm(codeFor(basic)), creds{basic.ClientID, basicSecret}
			}},
			{"client_secret_post", func() (url.Values, creds) {
				return codeForm(webCode(), "client_id", e.web.ClientID, "client_secret", e.webSecret), creds{}
			}},
			{"none with PKCE", func() (url.Values, creds) {
				p := url.Values{"client_id": {e.native.ClientID}, "scope": {"openid"}, "redirect_uri": {nativeLoop},
					"code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"}}
				code := e.authorize(c, p, false).Query().Get("code")
				return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {nativeLoop},
					"client_id": {e.native.ClientID}, "code_verifier": {pkceVerifier}}, creds{}
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				form, cr := tc.issue()
				resp, tok := token(form, cr)
				if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
					t.Fatalf("%d %q %v", resp.StatusCode, resp.Header.Get("Content-Type"), tok)
				}
				if tt, _ := tok["token_type"].(string); !strings.EqualFold(tt, "Bearer") {
					t.Errorf("token_type %v", tok["token_type"])
				}
				if exp, _ := tok["expires_in"].(float64); exp <= 0 {
					t.Errorf("expires_in %v", tok["expires_in"])
				}
				if at, _ := tok["access_token"].(string); at == "" {
					t.Error("no access_token")
				}
				if idt, _ := tok["id_token"].(string); idt == "" {
					t.Error("no id_token")
				}
			})
		}
	})

	// RFC 6749 5.1 and OIDC Core 3.1.3.3: a token response must not be
	// cached.
	t.Run("token response carries Cache-Control: no-store", func(t *testing.T) {
		resp, _ := e.exchangeWeb(webCode())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("token: %d", resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
			t.Fatalf("token response Cache-Control %q, want no-store", resp.Header.Get("Cache-Control"))
		}
	})

	// RFC 6749 3.2: parameters go in the POST body. In the URL a code or a
	// secret would reach access logs.
	t.Run("credentials in the URL are refused", func(t *testing.T) {
		q := codeForm(webCode(), "client_id", e.web.ClientID, "client_secret", e.webSecret).Encode()
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req, _ := http.NewRequest(method, e.issuer+"/oauth/token?"+q, nil)
			if r := e.do(http.DefaultClient, req); r.status != http.StatusBadRequest {
				t.Errorf("%s /oauth/token?…: %d %s", method, r.status, r.body)
			}
		}
	})

	failures := []struct {
		name   string
		issue  func() (url.Values, creds)
		status int
		errs   []string
	}{
		{"wrong secret, client_secret_post", func() (url.Values, creds) {
			return codeForm(webCode(), "client_id", e.web.ClientID, "client_secret", "wrong"), creds{}
		}, http.StatusUnauthorized, []string{"invalid_client"}},
		{"wrong secret, client_secret_basic", func() (url.Values, creds) {
			return codeForm(codeFor(basic)), creds{basic.ClientID, "wrong"}
		}, http.StatusUnauthorized, []string{"invalid_client"}},
		{"no client authentication", func() (url.Values, creds) {
			return codeForm(webCode(), "client_id", e.web.ClientID), creds{}
		}, http.StatusUnauthorized, []string{"invalid_client"}},
		{"wrong redirect_uri on redemption", func() (url.Values, creds) {
			f := codeForm(webCode(), "client_id", e.web.ClientID, "client_secret", e.webSecret)
			f.Set("redirect_uri", "https://rp.example/other")
			return f, creds{}
		}, http.StatusBadRequest, []string{"invalid_grant"}},
		{"redirect_uri missing on redemption", func() (url.Values, creds) {
			f := codeForm(webCode(), "client_id", e.web.ClientID, "client_secret", e.webSecret)
			f.Del("redirect_uri")
			return f, creds{}
		}, http.StatusBadRequest, []string{"invalid_grant", "invalid_request"}},
		{"code issued to another client", func() (url.Values, creds) {
			return codeForm(webCode()), creds{basic.ClientID, basicSecret}
		}, http.StatusBadRequest, []string{"invalid_grant"}},
		{"unknown code", func() (url.Values, creds) {
			return codeForm("not-a-code", "client_id", e.web.ClientID, "client_secret", e.webSecret), creds{}
		}, http.StatusBadRequest, []string{"invalid_grant"}},
		{"grant_type missing", func() (url.Values, creds) {
			f := codeForm(webCode(), "client_id", e.web.ClientID, "client_secret", e.webSecret)
			f.Del("grant_type")
			return f, creds{}
		}, http.StatusBadRequest, []string{"invalid_request"}},
		{"password grant", func() (url.Values, creds) {
			return url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {testPassword}},
				creds{basic.ClientID, basicSecret}
		}, http.StatusBadRequest, []string{"unsupported_grant_type"}},
		{"client_credentials grant", func() (url.Values, creds) {
			return url.Values{"grant_type": {"client_credentials"}}, creds{basic.ClientID, basicSecret}
		}, http.StatusBadRequest, []string{"unsupported_grant_type", "unauthorized_client"}},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			form, cr := tc.issue()
			resp, body := token(form, cr)
			if resp.StatusCode != tc.status || !slices.Contains(tc.errs, body["error"].(string)) {
				t.Fatalf("%d %v, want %d %v", resp.StatusCode, body, tc.status, tc.errs)
			}
			if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
				t.Errorf("Content-Type %q", resp.Header.Get("Content-Type"))
			}
			if d, _ := body["error_description"].(string); leaksInternals(d) {
				t.Errorf("error_description leaks internals: %q", d)
			}
		})
	}

	// RFC 6749 5.2: a failed Basic authentication is answered with a
	// challenge for the scheme the client used.
	t.Run("failed Basic authentication carries WWW-Authenticate", func(t *testing.T) {
		resp, _ := token(codeForm(codeFor(basic)), creds{basic.ClientID, "wrong"})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
			knownGap(t, "401 invalid_client without WWW-Authenticate: Basic (RFC 6749 5.2)")
		}
	})

	t.Run("expired code", func(t *testing.T) {
		code := webCode()
		e.st.SetClock(func() time.Time { return time.Now().Add(2 * time.Minute) })
		defer e.st.SetClock(time.Now)
		resp, body := e.exchangeWeb(code)
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("%d %v", resp.StatusCode, body)
		}
	})

	// oidcc-refresh-token
	t.Run("refresh token rotation and reuse detection", func(t *testing.T) {
		cb := e.authorize(c, e.webParams("openid offline_access"), false)
		_, tok := e.exchangeWeb(cb.Query().Get("code"))
		original := e.verifyIDToken(tok["id_token"].(string))
		refresh := func(rt string, id, secret string) (*http.Response, map[string]any) {
			return e.postForm(http.DefaultClient, "/oauth/token", url.Values{
				"grant_type": {"refresh_token"}, "refresh_token": {rt},
				"client_id": {id}, "client_secret": {secret},
			}, "", "")
		}
		first := tok["refresh_token"].(string)

		// Another client may not use it, and the attempt does not burn it.
		if resp, body := refresh(first, e.closed.ClientID, e.closedSecret); resp.StatusCode != http.StatusBadRequest ||
			body["error"] != "invalid_grant" {
			t.Fatalf("other client: %d %v", resp.StatusCode, body)
		}
		resp, next := refresh(first, e.web.ClientID, e.webSecret)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh: %d %v", resp.StatusCode, next)
		}
		second, _ := next["refresh_token"].(string)
		if second == "" || second == first {
			t.Fatalf("not rotated: %v", next)
		}

		// OIDC Core 12.2: same iss, sub, aud and auth_time; no nonce.
		renewed := e.verifyIDToken(next["id_token"].(string))
		for _, claim := range []string{"iss", "sub", "auth_time", "azp"} {
			if renewed[claim] != original[claim] {
				t.Errorf("refreshed %s %v, original %v", claim, renewed[claim], original[claim])
			}
		}
		if !audContains(renewed, e.web.ClientID) {
			t.Errorf("refreshed aud %v", renewed["aud"])
		}
		if _, ok := renewed["nonce"]; ok {
			t.Errorf("refreshed id_token carries nonce %v", renewed["nonce"])
		}

		// Reuse of the rotated token fails and revokes the family.
		if resp, body := refresh(first, e.web.ClientID, e.webSecret); resp.StatusCode != http.StatusBadRequest ||
			body["error"] != "invalid_grant" {
			t.Fatalf("reuse: %d %v", resp.StatusCode, body)
		}
		if resp, body := refresh(second, e.web.ClientID, e.webSecret); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("family survived the reuse: %d %v", resp.StatusCode, body)
		}
		t.Run("access tokens of the family are revoked", func(t *testing.T) {
			for _, at := range []any{tok["access_token"], next["access_token"]} {
				if st, _ := e.userinfo(at.(string)); st == http.StatusOK {
					t.Fatal("an access token of the replayed family still works")
				}
			}
		})
	})
}

// --- ID token (OIDC Core 3.1.3.6, 3.1.3.7) ---

func TestConformanceIDToken(t *testing.T) {
	e := newOIDCEnv(t)
	ctx := context.Background()
	c := e.signedIn()
	cb := e.authorize(c, e.webParams("openid email"), false)
	code := cb.Query().Get("code")
	before := time.Now().Add(-time.Second)
	resp, tok := e.exchangeWeb(code)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	raw := tok["id_token"].(string)
	at := tok["access_token"].(string)
	doc := e.discoveryDoc()

	t.Run("header", func(t *testing.T) {
		h := jwsHeader(t, raw)
		var algs []string
		for _, a := range doc["id_token_signing_alg_values_supported"].([]any) {
			algs = append(algs, a.(string))
		}
		if alg, _ := h["alg"].(string); (alg != "ES256" && alg != "RS256") || !slices.Contains(algs, alg) {
			t.Errorf("alg %v, advertised %v", h["alg"], algs)
		}
		if kid, _ := h["kid"].(string); kid == "" || !slices.Contains(e.jwksKIDs(), kid) {
			t.Errorf("kid %v not in JWKS %v", h["kid"], e.jwksKIDs())
		}
		if h["typ"] != "JWT" {
			t.Errorf("typ %v", h["typ"])
		}
	})

	t.Run("verifies with the client module", func(t *testing.T) {
		rp := e.relyingClient(e.web, e.webSecret, client.AuthMethodPost)
		claims, err := rp.VerifyIDTokenWithAccessToken(ctx, raw, "n-1", at)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if claims.Subject != strconv.FormatInt(e.user.ID, 10) || claims.SID == "" {
			t.Fatalf("claims %+v", claims)
		}
		if _, err := rp.VerifyIDTokenWithAccessToken(ctx, raw, "n-1", at+"x"); err == nil {
			t.Error("at_hash accepted another access token")
		}
		if _, err := rp.VerifyIDToken(ctx, raw, "other-nonce"); err == nil {
			t.Error("nonce mismatch accepted")
		}
		parts := strings.Split(raw, ".")
		sig := []byte(parts[2])
		sig[3] ^= 1
		if _, err := rp.VerifyIDToken(ctx, parts[0]+"."+parts[1]+"."+string(sig), ""); err == nil {
			t.Error("tampered signature accepted")
		}
		other := e.relyingClient(e.closed, e.closedSecret, client.AuthMethodBasic)
		if _, err := other.VerifyIDToken(ctx, raw, ""); err == nil {
			t.Error("another client accepted the token (aud)")
		}
	})

	t.Run("claims", func(t *testing.T) {
		cl := e.verifyIDToken(raw)
		num := func(name string) time.Time {
			v, ok := cl[name].(float64)
			if !ok {
				t.Fatalf("%s = %v, want a number", name, cl[name])
			}
			return time.Unix(int64(v), 0)
		}
		iat, exp, authTime := num("iat"), num("exp"), num("auth_time")
		_, info := e.userinfo(at)
		switch {
		case cl["iss"] != e.issuer:
			t.Errorf("iss %v", cl["iss"])
		case !audContains(cl, e.web.ClientID):
			t.Errorf("aud %v", cl["aud"])
		case cl["azp"] != nil && cl["azp"] != e.web.ClientID:
			t.Errorf("azp %v", cl["azp"])
		case cl["sub"] != strconv.FormatInt(e.user.ID, 10) || cl["sub"] != info["sub"]:
			t.Errorf("sub %v, userinfo sub %v", cl["sub"], info["sub"])
		case cl["nonce"] != "n-1":
			t.Errorf("nonce %v", cl["nonce"])
		case cl["sid"] == nil || cl["sid"] == "":
			t.Error("no sid")
		// The provider back-dates iat by its 30-second clock skew
		// (internal/oidc/client.go ClockSkew), so allow a minute.
		case iat.Before(before.Add(-time.Minute)) || iat.After(time.Now().Add(time.Second)):
			t.Errorf("iat %v not now (exchange at %v)", iat, before)
		case !exp.After(time.Now()) || !exp.After(iat):
			t.Errorf("exp %v, iat %v", exp, iat)
		case authTime.After(time.Now().Add(time.Second)) || authTime.Before(time.Now().Add(-time.Minute)):
			t.Errorf("auth_time %v", authTime)
		case cl["at_hash"] != leftHalfHash(at):
			t.Errorf("at_hash %v, want %s", cl["at_hash"], leftHalfHash(at))
		case cl["c_hash"] != nil && cl["c_hash"] != leftHalfHash(code):
			t.Errorf("c_hash %v, want %s", cl["c_hash"], leftHalfHash(code))
		}
	})
}

// --- Userinfo (OIDC Core 5.3, RFC 6750) ---

func TestConformanceUserinfo(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.signedIn()
	tok := e.webTokens(c, "openid email")
	at := tok["access_token"].(string)
	sub := e.verifyIDToken(tok["id_token"].(string))["sub"]
	call := func(method, target, body string, bearer string) reply {
		req, _ := http.NewRequest(method, e.abs(target), strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		return e.do(http.DefaultClient, req)
	}

	// oidcc-userinfo-get, oidcc-userinfo-post-header, oidcc-userinfo-post-body
	accepted := []struct{ name, method, body, bearer string }{
		{"GET with the header", http.MethodGet, "", at},
		{"POST with the header", http.MethodPost, "", at},
		{"POST with the token in the body", http.MethodPost, "access_token=" + url.QueryEscape(at), ""},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			r := call(tc.method, "/userinfo", tc.body, tc.bearer)
			if r.status != http.StatusOK || !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
				t.Fatalf("%d %q %s", r.status, r.header.Get("Content-Type"), r.body)
			}
			var info map[string]any
			_ = json.Unmarshal([]byte(r.body), &info)
			if info["sub"] != sub {
				t.Fatalf("sub %v, id_token sub %v", info["sub"], sub)
			}
		})
	}

	t.Run("token in the query string is refused", func(t *testing.T) {
		// RFC 6750 2.3 advises against it: the token would reach access
		// logs and Referer headers.
		if r := call(http.MethodGet, "/userinfo?access_token="+url.QueryEscape(at), "", ""); r.status == http.StatusOK {
			t.Fatalf("/userinfo accepted access_token in the query: %s", r.body)
		}
	})

	// oidcc-scope-email, oidcc-scope-profile: only the requested scopes'
	// claims come back.
	scopes := []struct {
		scope      string
		want, deny []string
	}{
		{"openid", nil, []string{"email", "email_verified", "name", "preferred_username"}},
		{"openid email", []string{"email", "email_verified"}, []string{"name", "preferred_username"}},
		{"openid profile", []string{"name", "preferred_username"}, []string{"email", "email_verified"}},
		{"openid profile email", []string{"email", "name", "preferred_username"}, nil},
	}
	for _, tc := range scopes {
		t.Run("claims for scope "+tc.scope, func(t *testing.T) {
			_, info := e.userinfo(e.webTokens(c, tc.scope)["access_token"].(string))
			if info["sub"] != sub {
				t.Fatalf("sub %v", info["sub"])
			}
			for _, k := range tc.want {
				if _, ok := info[k]; !ok {
					t.Errorf("missing %s: %v", k, info)
				}
			}
			for _, k := range tc.deny {
				if _, ok := info[k]; ok {
					t.Errorf("unrequested %s: %v", k, info)
				}
			}
		})
	}

	revoked := e.webTokens(c, "openid")["access_token"].(string)
	if resp, _ := e.postForm(http.DefaultClient, "/revoke", url.Values{"token": {revoked},
		"client_id": {e.web.ClientID}, "client_secret": {e.webSecret}}, "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	expiring := e.webTokens(c, "openid")["access_token"].(string)
	rejected := []struct {
		name   string
		bearer string
		before func()
	}{
		{"no token", "", nil},
		{"malformed token", "not-a-token", nil},
		{"revoked token", revoked, nil},
		{"expired token", expiring, func() { e.shiftClock(2 * time.Hour) }},
	}
	for _, tc := range rejected {
		t.Run("rejected: "+tc.name, func(t *testing.T) {
			if tc.before != nil {
				tc.before()
			}
			r := call(http.MethodGet, "/userinfo", "", tc.bearer)
			if r.status == http.StatusOK {
				t.Fatalf("accepted: %s", r.body)
			}
			if leaksInternals(r.body) {
				t.Errorf("body leaks internals: %q", r.body)
			}
			if r.status != http.StatusUnauthorized {
				knownGap(t, "status %d, RFC 6750 3.1 wants 401 invalid_token (zitadel/oidc op.Userinfo answers 403 when "+
					"SetUserinfoFromToken fails)", r.status)
				return
			}
			if !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Bearer") {
				knownGap(t, "401 without WWW-Authenticate: Bearer (RFC 6750 3, OIDC Core 5.3.3)")
			}
		})
	}
}

// --- Revocation (RFC 7009) ---

func TestConformanceRevocation(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.signedIn()
	revoke := func(form url.Values, id, secret string) (*http.Response, map[string]any) {
		return e.postForm(http.DefaultClient, "/revoke", form, id, secret)
	}

	t.Run("revoked access token stops working", func(t *testing.T) {
		at := e.webTokens(c, "openid")["access_token"].(string)
		if resp, body := revoke(url.Values{"token": {at}, "token_type_hint": {"access_token"}}, e.web.ClientID, e.webSecret); resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke: %d %v", resp.StatusCode, body)
		}
		if st, _ := e.userinfo(at); st == http.StatusOK {
			t.Fatal("userinfo accepted a revoked token")
		}
	})

	t.Run("a wrong token_type_hint does not stop the revocation", func(t *testing.T) {
		at := e.webTokens(c, "openid")["access_token"].(string)
		if resp, _ := revoke(url.Values{"token": {at}, "token_type_hint": {"refresh_token"}}, e.web.ClientID, e.webSecret); resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke: %d", resp.StatusCode)
		}
		if st, _ := e.userinfo(at); st == http.StatusOK {
			t.Fatal("token survived")
		}
	})

	t.Run("unknown token answers 200", func(t *testing.T) {
		if resp, body := revoke(url.Values{"token": {"no-such-token"}}, e.web.ClientID, e.webSecret); resp.StatusCode != http.StatusOK {
			t.Fatalf("%d %v", resp.StatusCode, body)
		}
	})

	t.Run("another client's token is left alone", func(t *testing.T) {
		at := e.webTokens(c, "openid")["access_token"].(string)
		if resp, _ := revoke(url.Values{"token": {at}}, e.closed.ClientID, e.closedSecret); resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke: %d", resp.StatusCode)
		}
		if st, _ := e.userinfo(at); st != http.StatusOK {
			t.Fatalf("another client revoked the token: userinfo %d", st)
		}
	})

	t.Run("client authentication is required", func(t *testing.T) {
		at := e.webTokens(c, "openid")["access_token"].(string)
		resp, body := revoke(url.Values{"token": {at}}, e.web.ClientID, "wrong")
		if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Fatalf("%d %v", resp.StatusCode, body)
		}
		if st, _ := e.userinfo(at); st != http.StatusOK {
			t.Fatal("unauthenticated revocation took effect")
		}
	})

	t.Run("token parameter is required", func(t *testing.T) {
		resp, body := revoke(url.Values{}, e.web.ClientID, e.webSecret)
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
			knownGap(t, "a revocation request without token answers %d %v; RFC 7009 2.1 makes token required "+
				"(invalid_request)", resp.StatusCode, body)
		}
	})
}

// --- RP-initiated logout: oidcc-rp-initiated-logout-* ---

func TestConformanceRPInitiatedLogout(t *testing.T) {
	e := newOIDCEnv(t)
	if err := e.st.SetMembership(e.web.ID, e.user.ID, store.RoleMember, store.MemberActive, 0); err != nil {
		t.Fatal(err)
	}
	const bye = "https://rp.example/bye"
	if _, ok := e.discoveryDoc()["end_session_endpoint"].(string); !ok {
		t.Fatal("no end_session_endpoint")
	}
	endSession := func(c *http.Client, q url.Values) reply { return e.fetch(c, "/end_session?"+q.Encode()) }
	signedIn := func(c *http.Client) bool { return e.fetch(c, "/api/auth/me").status == http.StatusOK }
	session := func() (*http.Client, string) {
		c := e.signedIn()
		return c, e.webTokens(c, "openid")["id_token"].(string)
	}

	t.Run("logout with hint, redirect and state", func(t *testing.T) {
		c := e.signedIn()
		tok := e.webTokens(c, "openid offline_access")
		r := endSession(c, url.Values{"id_token_hint": {tok["id_token"].(string)},
			"post_logout_redirect_uri": {bye}, "state": {"a b&c/é"}})
		if r.status != http.StatusFound {
			t.Fatalf("status %d", r.status)
		}
		loc := r.location(t)
		if loc.Scheme+"://"+loc.Host+loc.Path != bye || loc.Query().Get("state") != "a b&c/é" {
			t.Fatalf("redirect %s", loc)
		}
		if signedIn(c) {
			t.Fatal("session still alive")
		}
		// The next authorization shows a login.
		first := location(t, e.get(c, "/authorize?"+e.codeParams().Encode()), http.StatusFound)
		if next := location(t, e.get(c, first.String()), http.StatusFound); next.Path != "/sign-in" {
			t.Fatalf("authorize after logout went to %s", next)
		}
		resp, _ := e.postForm(http.DefaultClient, "/oauth/token", url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {tok["refresh_token"].(string)}, "client_id": {e.web.ClientID},
			"client_secret": {e.webSecret}}, "", "")
		if resp.StatusCode == http.StatusOK {
			t.Error("refresh token survived the logout")
		}
		if st, _ := e.userinfo(tok["access_token"].(string)); st == http.StatusOK {
			t.Error("access token survived the logout")
		}
	})

	// oidcc-rp-initiated-logout-no-post-logout-redirect-uri
	t.Run("hint without a redirect stays at the provider", func(t *testing.T) {
		c, idt := session()
		r := endSession(c, url.Values{"id_token_hint": {idt}})
		if r.status != http.StatusFound || r.header.Get("Location") != e.issuer+"/" {
			t.Fatalf("%d %s", r.status, r.header.Get("Location"))
		}
		if signedIn(c) {
			t.Fatal("session still alive")
		}
	})

	tamper := func(idt string) string {
		parts := strings.Split(idt, ".")
		sig := []byte(parts[2])
		sig[3] ^= 1
		return parts[0] + "." + parts[1] + "." + string(sig)
	}
	refused := []struct {
		name  string
		query func(idt string) url.Values
	}{
		// oidcc-rp-initiated-logout-bad-id-token-hint
		{"garbage id_token_hint", func(string) url.Values {
			return url.Values{"id_token_hint": {"abc.def.ghi"}, "post_logout_redirect_uri": {bye}, "state": {"x"}}
		}},
		// oidcc-rp-initiated-logout-modified-id-token-hint
		{"id_token_hint with a modified signature", func(idt string) url.Values {
			return url.Values{"id_token_hint": {tamper(idt)}, "post_logout_redirect_uri": {bye}, "state": {"x"}}
		}},
		// oidcc-rp-initiated-logout-bad-post-logout-redirect-uri
		{"unregistered post_logout_redirect_uri", func(idt string) url.Values {
			return url.Values{"id_token_hint": {idt}, "post_logout_redirect_uri": {"https://evil.example/"}, "state": {"x"}}
		}},
		// oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri
		{"query added to post_logout_redirect_uri", func(idt string) url.Values {
			return url.Values{"id_token_hint": {idt}, "post_logout_redirect_uri": {bye + "?x=1"}, "state": {"x"}}
		}},
		{"client_id that does not match the hint", func(idt string) url.Values {
			return url.Values{"id_token_hint": {idt}, "client_id": {e.closed.ClientID},
				"post_logout_redirect_uri": {bye}, "state": {"x"}}
		}},
	}
	for _, tc := range refused {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			c, idt := session()
			r := endSession(c, tc.query(idt))
			if r.status == http.StatusFound && !strings.HasPrefix(r.header.Get("Location"), e.issuer+"/") {
				t.Fatalf("redirected to %s", r.header.Get("Location"))
			}
			if r.status >= 500 || leaksInternals(r.body) {
				t.Fatalf("%d %q", r.status, r.body)
			}
			if !signedIn(c) {
				t.Fatal("an invalid logout request ended the session")
			}
		})
	}

	// oidcc-rp-initiated-logout-no-params, -only-state, -no-id-token-hint:
	// without a hint nobody is signed out, since any page could send the
	// request. The suite judges the page shown by screenshot.
	unhinted := []struct {
		name  string
		query url.Values
		to    string
	}{
		{"no parameters", url.Values{}, e.issuer + "/"},
		{"only state", url.Values{"state": {"x"}}, e.issuer + "/?state=x"},
		{"client_id and redirect without a hint", url.Values{"client_id": {"CLIENT"},
			"post_logout_redirect_uri": {bye}, "state": {"x"}}, bye + "?state=x"},
	}
	for _, tc := range unhinted {
		t.Run("without a hint: "+tc.name, func(t *testing.T) {
			c, _ := session()
			q := url.Values{}
			for k, v := range tc.query {
				q[k] = slices.Clone(v)
			}
			if q.Get("client_id") == "CLIENT" {
				q.Set("client_id", e.web.ClientID)
			}
			r := endSession(c, q)
			if r.status != http.StatusFound || r.header.Get("Location") != tc.to {
				t.Fatalf("%d %s, want %s", r.status, r.header.Get("Location"), tc.to)
			}
			if !signedIn(c) {
				t.Fatal("signed out without an id_token_hint")
			}
		})
	}
}

// --- Back-channel logout: oidcc-backchannel-rp-initiated-logout ---

// logoutCapture records each back-channel request in full.
type logoutCapture struct {
	mu   sync.Mutex
	reqs []capturedLogout
}

type capturedLogout struct {
	method, contentType string
	form                url.Values
}

func TestConformanceBackchannelLogout(t *testing.T) {
	e := newOIDCEnv(t)
	capture := &logoutCapture{}
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capture.mu.Lock()
		capture.reqs = append(capture.reqs, capturedLogout{r.Method, r.Header.Get("Content-Type"), r.PostForm})
		capture.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
	}))
	t.Cleanup(rp.Close)
	uri := rp.URL + "/backchannel"
	if err := e.st.UpdateApp(e.web.ID, store.AppUpdate{BackchannelLogoutURI: &uri}); err != nil {
		t.Fatal(err)
	}
	doc := e.discoveryDoc()
	if doc["backchannel_logout_supported"] != true || doc["backchannel_logout_session_supported"] != true {
		t.Fatalf("discovery: %v %v", doc["backchannel_logout_supported"], doc["backchannel_logout_session_supported"])
	}

	c := e.signedIn()
	idt := e.webTokens(c, "openid")["id_token"].(string)
	sid := e.verifyIDToken(idt)["sid"]
	r := e.fetch(c, "/end_session?"+url.Values{"id_token_hint": {idt}, "post_logout_redirect_uri": {"https://rp.example/bye"}}.Encode())
	if r.status != http.StatusFound {
		t.Fatalf("end_session: %d", r.status)
	}
	backchannelWorker(t, e).Flush(context.Background())

	capture.mu.Lock()
	reqs := slices.Clone(capture.reqs)
	capture.mu.Unlock()
	if len(reqs) != 1 {
		t.Fatalf("%d logout requests, want 1", len(reqs))
	}
	req := reqs[0]
	if req.method != http.MethodPost || !strings.HasPrefix(req.contentType, "application/x-www-form-urlencoded") {
		t.Fatalf("logout request %s %q", req.method, req.contentType)
	}
	if len(req.form) != 1 || req.form.Get("logout_token") == "" {
		t.Fatalf("logout request form %v", req.form)
	}
	raw := req.form.Get("logout_token")

	t.Run("header", func(t *testing.T) {
		h := jwsHeader(t, raw)
		if h["typ"] != "logout+jwt" || h["kid"] == nil || !slices.Contains(e.jwksKIDs(), h["kid"].(string)) {
			t.Fatalf("header %v", h)
		}
		if alg := h["alg"]; alg != "ES256" && alg != "RS256" {
			t.Fatalf("alg %v", alg)
		}
	})

	t.Run("claims", func(t *testing.T) {
		cl := e.verifyIDToken(raw)
		iat, _ := cl["iat"].(float64)
		exp, _ := cl["exp"].(float64)
		now := float64(time.Now().Unix())
		switch {
		case cl["iss"] != e.issuer:
			t.Errorf("iss %v", cl["iss"])
		case !audContains(cl, e.web.ClientID):
			t.Errorf("aud %v", cl["aud"])
		case iat == 0 || iat > now+1:
			t.Errorf("iat %v", cl["iat"])
		case exp <= iat || exp <= now:
			t.Errorf("exp %v, iat %v", cl["exp"], cl["iat"])
		case cl["jti"] == nil || cl["jti"] == "":
			t.Error("no jti")
		case cl["sid"] != sid:
			t.Errorf("sid %v, id_token sid %v", cl["sid"], sid)
		case cl["sub"] != strconv.FormatInt(e.user.ID, 10):
			t.Errorf("sub %v", cl["sub"])
		case cl["nonce"] != nil:
			t.Errorf("nonce %v", cl["nonce"])
		}
		events, _ := cl["events"].(map[string]any)
		if member, ok := events[backchannelEvent].(map[string]any); !ok || len(member) != 0 {
			t.Errorf("events %v, want {%q: {}}", cl["events"], backchannelEvent)
		}
	})

	t.Run("verifies with client.VerifyLogoutToken", func(t *testing.T) {
		rpc := e.relyingClient(e.web, e.webSecret, client.AuthMethodPost)
		lt, err := rpc.VerifyLogoutToken(context.Background(), raw)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if lt.SID != sid || lt.Issuer != e.issuer {
			t.Fatalf("logout token %+v", lt)
		}
		if _, err := rpc.VerifyLogoutToken(context.Background(), raw); err == nil {
			t.Error("replayed logout token accepted")
		}
		if _, err := rpc.VerifyIDToken(context.Background(), raw, ""); err == nil {
			t.Error("logout token accepted as an ID token")
		}
	})
}

// --- Error responses ---

func TestConformanceErrorResponses(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.signedIn()

	// Errors found before sign-in (bad response_type, scope, request object)
	// are in TestConformanceAuthorizationRequest, through wantAuthzError,
	// which checks error, state, iss and error_description.
	t.Run("errors decided after sign-in are redirected too", func(t *testing.T) {
		p := e.webParams("openid")
		p.Set("client_id", e.closed.ClientID)
		cb := e.authorize(c, p, false)
		if q := cb.Query(); q.Get("error") != "access_denied" || q.Get("error_description") == "" ||
			q.Get("state") != "st-1" || q.Get("iss") != e.issuer || leaksInternals(q.Get("error_description")) {
			t.Fatalf("callback %s", cb)
		}
	})

	// oidcc-ensure-registered-redirect-uri and the redirect_uri checks of
	// OIDC Core 3.1.2.1.
	t.Run("errors with an untrusted redirect_uri are shown, not redirected", func(t *testing.T) {
		for _, tc := range pageErrorCases(e) {
			t.Run(tc.name, func(t *testing.T) {
				p := e.codeParams()
				p.Set("state", "st-1")
				tc.mutate(p)
				r := e.authorizeRaw(c, p)
				if r.status != http.StatusBadRequest || r.header.Get("Location") != "" {
					t.Fatalf("%d Location %q", r.status, r.header.Get("Location"))
				}
				if leaksInternals(r.body) || strings.Contains(r.body, "<script") || strings.Contains(r.body, "evil.example") {
					t.Fatalf("page body %q", r.body)
				}
				if ct := r.header.Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
					t.Fatalf("error page served as %s", ct)
				}
			})
		}
	})
}
