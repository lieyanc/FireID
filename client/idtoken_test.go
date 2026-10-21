package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyIDTokenAlgorithms(t *testing.T) {
	for _, alg := range []string{algES256, algRS256, algPS256, algEdDSA} {
		t.Run(alg, func(t *testing.T) {
			clk := newClock()
			fp := newFakeProvider(t, clk)
			fp.rotate(newSigningKey(t, "k-"+alg, alg))
			c := newTestClient(t, fp, nil)
			claims, err := c.VerifyIDToken(context.Background(), fp.idToken(nil), "n-1")
			if err != nil {
				t.Fatal(err)
			}
			if claims.Subject != "42" || claims.SID != "sess-1" || claims.ACR != "urn:fireid:loa:2" ||
				len(claims.AMR) != 1 || claims.AMR[0] != "webauthn" || claims.Email != "ann@example.test" ||
				!claims.EmailVerified || claims.Name != "Ann Example" || claims.PreferredUsername != "ann" ||
				claims.Nonce != "n-1" || len(claims.Audience) != 1 || claims.Audience[0] != "app-1" {
				t.Fatalf("claims %+v", claims)
			}
			if !claims.Expiry.Equal(clk.now().Add(5*time.Minute)) || !claims.IssuedAt.Equal(clk.now()) ||
				!claims.AuthTime.Equal(clk.now().Add(-time.Minute)) {
				t.Fatalf("times %v %v %v", claims.Expiry, claims.IssuedAt, claims.AuthTime)
			}
			if claims.Raw["sid"] != "sess-1" {
				t.Fatalf("raw %v", claims.Raw)
			}
		})
	}
}

func TestVerifyIDTokenRules(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	c := newTestClient(t, fp, nil)
	ctx := context.Background()
	good := fp.idToken(nil)
	parts := strings.Split(good, ".")
	key := fp.current()
	otherKey := newSigningKey(t, "k1", algES256) // same kid, different key
	payloadJSON, err := json.Marshal(fp.idClaims(nil))
	if err != nil {
		t.Fatal(err)
	}
	withPayload := func(payload string) string {
		return signSegments(t, key, parts[0], b64.EncodeToString([]byte(payload)))
	}

	cases := map[string]struct {
		raw   string
		nonce string
		at    string
		want  string
	}{
		"tampered payload": {
			raw:  tamperSegment(good, 1, b64.EncodeToString([]byte(`{"iss":"`+fp.issuer+`","sub":"1","aud":"app-1","exp":9999999999,"iat":1}`))),
			want: "signature does not verify",
		},
		"tampered signature": {raw: tamperSegment(good, 2, flipFirst(parts[2])), want: "signature does not verify"},
		"other key same kid": {raw: otherKey.sign(t, nil, fp.idClaims(nil)), want: "signature does not verify"},
		"unknown kid":        {raw: key.sign(t, map[string]any{"kid": "nope"}, fp.idClaims(nil)), want: `unknown key id "nope"`},
		"wrong iss":          {raw: fp.idToken(map[string]any{"iss": fp.issuer + "/"}), want: "iss"},
		"wrong aud":          {raw: fp.idToken(map[string]any{"aud": "other"}), want: "aud does not contain"},
		"aud array with us":  {raw: fp.idToken(map[string]any{"aud": []string{"other", "app-1"}, "azp": "app-1"})},
		"aud array no azp":   {raw: fp.idToken(map[string]any{"aud": []string{"other", "app-1"}}), want: "no azp"},
		"aud array bad azp":  {raw: fp.idToken(map[string]any{"aud": []string{"other", "app-1"}, "azp": "other"}), want: "azp"},
		"single aud bad azp": {raw: fp.idToken(map[string]any{"azp": "other"}), want: "azp"},
		"aud number":         {raw: fp.idToken(map[string]any{"aud": 7}), want: "aud is neither"},
		"aud null":           {raw: withPayload(strings.Replace(string(payloadJSON), `"aud":"app-1"`, `"aud":null`, 1)), want: "aud is neither"},
		"expired":            {raw: fp.idToken(map[string]any{"exp": clk.now().Add(-2 * time.Minute).Unix()}), want: "expired"},
		"expired in skew":    {raw: fp.idToken(map[string]any{"exp": clk.now().Add(-30 * time.Second).Unix()})},
		"no exp":             {raw: fp.idToken(map[string]any{"exp": nil}), want: "no exp"},
		"exp string":         {raw: fp.idToken(map[string]any{"exp": "soon"}), want: "date is not a number"},
		"iat future":         {raw: fp.idToken(map[string]any{"iat": clk.now().Add(2 * time.Minute).Unix()}), want: "iat"},
		"iat future in skew": {raw: fp.idToken(map[string]any{"iat": clk.now().Add(30 * time.Second).Unix()})},
		"no iat":             {raw: fp.idToken(map[string]any{"iat": nil}), want: "no iat"},
		"nbf future":         {raw: fp.idToken(map[string]any{"nbf": clk.now().Add(5 * time.Minute).Unix()}), want: "not valid before"},
		"no sub":             {raw: fp.idToken(map[string]any{"sub": nil}), want: "no sub"},
		"nonce mismatch":     {raw: good, nonce: "n-2", want: "nonce mismatch"},
		"nonce absent":       {raw: fp.idToken(map[string]any{"nonce": nil}), nonce: "n-1", want: "nonce mismatch"},
		"nonce ignored":      {raw: good, nonce: ""},
		// Claim names are exact: NONCE is not nonce, for the typed claims
		// as for the raw map, and ISS beside iss is an unknown claim.
		"nonce in other case": {raw: fp.idToken(map[string]any{"nonce": nil, "NONCE": "n-1"}), nonce: "n-1", want: "nonce mismatch"},
		"iss in other case":   {raw: fp.idToken(map[string]any{"ISS": "https://evil.test"})},
		"claim twice":         {raw: withPayload(strings.TrimSuffix(string(payloadJSON), "}") + `,"aud":"other"}`), want: `has member "aud" twice`},
		"at_hash ok":          {raw: fp.idToken(map[string]any{"at_hash": leftHalfHash(algES256, "tok")}), at: "tok"},
		"at_hash mismatch":    {raw: fp.idToken(map[string]any{"at_hash": leftHalfHash(algES256, "tok")}), at: "other", want: "at_hash"},
		"at_hash absent":      {raw: good, at: "tok"},
		"typ logout":          {raw: key.sign(t, map[string]any{"typ": "logout+jwt"}, fp.idClaims(nil)), want: "typ"},
		"typ at+jwt":          {raw: key.sign(t, map[string]any{"typ": "application/at+jwt"}, fp.idClaims(nil)), want: "typ"},
		"typ JWT":             {raw: key.sign(t, map[string]any{"typ": "JWT"}, fp.idClaims(nil))},
		"events claim":        {raw: fp.idToken(map[string]any{"events": map[string]any{logoutEvent: map[string]any{}}}), want: "events"},
		"crit":                {raw: key.sign(t, map[string]any{"crit": []string{"b64"}, "b64": false}, fp.idClaims(nil)), want: "crit"},
		"alg none": {
			raw:  b64.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`)) + "." + parts[1] + ".sig",
			want: `alg "none"`,
		},
		"alg shadowed": {
			raw:  b64.EncodeToString([]byte(`{"alg":"none","ALG":"ES256","kid":"k1"}`)) + "." + parts[1] + ".sig",
			want: `alg "none"`,
		},
		"empty": {raw: "", want: "not a compact JWS"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			nonce := tc.nonce
			if nonce == "" && tc.want != "nonce mismatch" && name != "nonce ignored" {
				nonce = "n-1"
			}
			_, err := c.VerifyIDTokenWithAccessToken(ctx, tc.raw, nonce, tc.at)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted; want error containing %q", tc.want)
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("error %v is not ErrInvalidToken", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// flipFirst changes the first character of a base64url segment to another
// alphabet character, which changes the decoded bytes while the segment
// stays well-formed (the last character also carries padding bits).
func flipFirst(seg string) string {
	repl := byte('A')
	if seg[0] == 'A' {
		repl = 'B'
	}
	return string(repl) + seg[1:]
}

func TestKeyRotationAndRefetchLimit(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	c := newTestClient(t, fp, nil)
	ctx := context.Background()

	if _, err := c.VerifyIDToken(ctx, fp.idToken(nil), "n-1"); err != nil {
		t.Fatal(err)
	}
	if n := fp.fetches(); n != 1 {
		t.Fatalf("fetches after first verification: %d", n)
	}
	// A second token with the known key uses the cache.
	if _, err := c.VerifyIDToken(ctx, fp.idToken(nil), "n-1"); err != nil {
		t.Fatal(err)
	}
	if n := fp.fetches(); n != 1 {
		t.Fatalf("fetches after cached verification: %d", n)
	}

	// Rotation: the new kid is unknown, one refetch picks it up.
	fp.rotate(newSigningKey(t, "k2", algRS256))
	if _, err := c.VerifyIDToken(ctx, fp.idToken(nil), "n-1"); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if n := fp.fetches(); n != 2 {
		t.Fatalf("fetches after rotation: %d", n)
	}

	// A second rotation within 30 s is not fetched for: the miss is
	// rate-limited and the token fails.
	clk.advance(10 * time.Second)
	fp.rotate(newSigningKey(t, "k3", algES256))
	if _, err := c.VerifyIDToken(ctx, fp.idToken(nil), "n-1"); err == nil || !strings.Contains(err.Error(), `unknown key id "k3"`) {
		t.Fatalf("within the limit: %v", err)
	}
	if n := fp.fetches(); n != 2 {
		t.Fatalf("fetches within the limit: %d", n)
	}
	// Made-up kids do not add fetches either.
	for i := 0; i < 5; i++ {
		_, _ = c.VerifyIDToken(ctx, fp.current().sign(t, map[string]any{"kid": "junk"}, fp.idClaims(nil)), "n-1")
	}
	if n := fp.fetches(); n != 2 {
		t.Fatalf("fetches after junk kids: %d", n)
	}
	// Once the interval has passed, the refetch happens and k3 works.
	clk.advance(jwksRefetchInterval)
	if _, err := c.VerifyIDToken(ctx, fp.idToken(nil), "n-1"); err != nil {
		t.Fatalf("after the limit: %v", err)
	}
	if n := fp.fetches(); n != 3 {
		t.Fatalf("fetches after the limit: %d", n)
	}

	// A retired key keeps verifying from the cache until the set ages out.
	old := newSigningKey(t, "k2", algRS256)
	old.priv = rsaTestKey()
	retiredToken := old.sign(t, nil, fp.idClaims(nil))
	fp.retire("k2")
	if _, err := c.VerifyIDToken(ctx, retiredToken, "n-1"); err != nil {
		t.Fatalf("retired key still cached: %v", err)
	}
	clk.advance(jwksMaxAge + time.Second)
	retiredToken = old.sign(t, nil, fp.idClaims(nil)) // fresh times, old key
	if _, err := c.VerifyIDToken(ctx, retiredToken, "n-1"); err == nil || !strings.Contains(err.Error(), `unknown key id "k2"`) {
		t.Fatalf("retired key after max age: %v", err)
	}
	if n := fp.fetches(); n != 4 {
		t.Fatalf("fetches after max age: %d", n)
	}
}

func TestKeySetFailureKeepsCache(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	c := newTestClient(t, fp, nil)
	ctx := context.Background()
	if _, err := c.VerifyIDToken(ctx, fp.idToken(nil), "n-1"); err != nil {
		t.Fatal(err)
	}
	// The provider goes away: the cached set still serves known kids after
	// the max age, and an unknown kid reports the fetch failure.
	c.keys.url = fp.issuer + "/gone"
	clk.advance(jwksMaxAge + time.Second)
	if _, err := c.VerifyIDToken(ctx, fp.idToken(nil), "n-1"); err != nil {
		t.Fatalf("stale cache after a failed refresh: %v", err)
	}
	_, err := c.VerifyIDToken(ctx, fp.current().sign(t, map[string]any{"kid": "k9"}, fp.idClaims(nil)), "n-1")
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("unknown kid with the provider down: %v", err)
	}
}

// TestKeySetFailedRefreshBackoff has the provider go down with a stale set
// cached: the set keeps serving, the refresh is attempted once per
// interval rather than once per verification, and the next attempt after
// the provider is back picks up a rotation.
func TestKeySetFailedRefreshBackoff(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	c := newTestClient(t, fp, nil)
	ctx := context.Background()
	if _, err := c.VerifyIDToken(ctx, fp.idToken(nil), "n-1"); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	c.keys.url = down.URL
	clk.advance(jwksMaxAge + time.Second)

	known := fp.idToken(nil)
	for i := 0; i < 5; i++ {
		if _, err := c.VerifyIDToken(ctx, known, "n-1"); err != nil {
			t.Fatalf("verification %d against the stale set: %v", i, err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("fetch attempts after 5 verifications: %d", n)
	}
	// An unknown kid reports the failed refresh without another attempt.
	fp.rotate(newSigningKey(t, "k2", algES256))
	unknown := fp.idToken(nil)
	if _, err := c.VerifyIDToken(ctx, unknown, "n-1"); !errors.Is(err, ErrProvider) {
		t.Fatalf("unknown kid while the refresh fails: %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("fetch attempts after an unknown kid: %d", n)
	}
	// After the interval one more attempt is made.
	clk.advance(jwksRefetchInterval)
	if _, err := c.VerifyIDToken(ctx, known, "n-1"); err != nil {
		t.Fatal(err)
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("fetch attempts after the interval: %d", n)
	}
	// The provider comes back; the interval still holds, then the rotation
	// is picked up.
	c.keys.url = fp.issuer + "/keys"
	if _, err := c.VerifyIDToken(ctx, unknown, "n-1"); !errors.Is(err, ErrProvider) {
		t.Fatalf("within the interval after the last failure: %v", err)
	}
	clk.advance(jwksRefetchInterval)
	if _, err := c.VerifyIDToken(ctx, unknown, "n-1"); err != nil {
		t.Fatalf("after the provider is back: %v", err)
	}
}

// TestKeySetRefreshOutsideLock holds a refresh open and checks that cached
// keys are served meanwhile, that a token under a new key waits for that
// refresh instead of failing or starting another, and that there is one
// fetch in all.
func TestKeySetRefreshOutsideLock(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	c := newTestClient(t, fp, nil)
	ctx := context.Background()
	if _, err := c.VerifyIDToken(ctx, fp.idToken(nil), "n-1"); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var hits atomic.Int32
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		fp.jwks(w, r)
	}))
	defer gate.Close()
	c.keys.url = gate.URL
	clk.advance(jwksMaxAge + time.Second)
	known := fp.idToken(nil)
	fp.rotate(newSigningKey(t, "k2", algES256))
	unknown := fp.idToken(nil)

	// The first verification against the stale set starts the refresh.
	first := make(chan error, 1)
	go func() {
		_, err := c.VerifyIDToken(ctx, known, "n-1")
		first <- err
	}()
	<-entered
	// Cached keys are served while it runs. Were the mutex held across the
	// fetch, these would block until the gate opens.
	served := make(chan error, 1)
	go func() {
		for i := 0; i < 5; i++ {
			if _, err := c.VerifyIDToken(ctx, known, "n-1"); err != nil {
				served <- err
				return
			}
		}
		served <- nil
	}()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("known kid during the refresh: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("verifications of a cached kid waited for the refresh")
	}
	// A token under the new key waits for the refresh in progress. The
	// pause gives it time to reach the wait; without it the check is only
	// weaker, never wrong.
	second := make(chan error, 1)
	go func() {
		_, err := c.VerifyIDToken(ctx, unknown, "n-1")
		second <- err
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("the refreshing caller: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("the waiting caller: %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("fetches: %d", n)
	}
}

func TestExpiresIn(t *testing.T) {
	year := seconds(maxExpiresIn / time.Second)
	cases := map[string]seconds{
		`3600`: 3600, `"3600"`: 3600, `3600.9`: 3600, `0`: 0, `-5`: 0, `null`: 0, `""`: 0,
		`1e308`: year, `1e400`: year, `-1e400`: 0, `9223372036854775807`: year, `"NaN"`: 0, `31536000`: year,
	}
	for in, want := range cases {
		var s seconds
		if err := json.Unmarshal([]byte(in), &s); err != nil || s != want {
			t.Errorf("expires_in %s = %d, %v; want %d", in, s, err, want)
		}
	}
	for _, in := range []string{`"abc"`, `true`, `[1]`} {
		var s seconds
		if err := json.Unmarshal([]byte(in), &s); err == nil {
			t.Errorf("expires_in %s accepted", in)
		}
	}
}

func TestDiscover(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	ctx := context.Background()

	p, err := Discover(ctx, fp.issuer, WithHTTPClient(fp.srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if p.Issuer != fp.issuer || p.TokenEndpoint != fp.issuer+"/oauth/token" || p.JWKSURI != fp.issuer+"/keys" ||
		p.UserInfoEndpoint != fp.issuer+"/userinfo" || p.EndSessionEndpoint != fp.issuer+"/end_session" ||
		p.IssuerParameterSupported || !p.BackchannelLogoutSupported {
		t.Fatalf("provider %+v", p)
	}

	t.Run("trailing slash is a different issuer", func(t *testing.T) {
		_, err := Discover(ctx, fp.issuer+"/", WithHTTPClient(fp.srv.Client()))
		if !errors.Is(err, ErrIssuerMismatch) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("document names another issuer", func(t *testing.T) {
		fp.mu.Lock()
		fp.docIssuer = "https://other.example.test"
		fp.mu.Unlock()
		defer func() {
			fp.mu.Lock()
			fp.docIssuer = fp.issuer
			fp.mu.Unlock()
		}()
		_, err := Discover(ctx, fp.issuer, WithHTTPClient(fp.srv.Client()))
		if !errors.Is(err, ErrIssuerMismatch) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("http off loopback", func(t *testing.T) {
		_, err := Discover(ctx, "http://id.example.test")
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("query in issuer", func(t *testing.T) {
		_, err := Discover(ctx, fp.issuer+"?x=1", WithHTTPClient(fp.srv.Client()))
		if err == nil || !strings.Contains(err.Error(), "without query") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		_, err := Discover(ctx, "http://127.0.0.1:1", WithHTTPClient(fp.srv.Client()))
		if !errors.Is(err, ErrProvider) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestNewValidatesConfig(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	ctx := context.Background()
	base := func() Config {
		return Config{Issuer: fp.issuer, ClientID: "app-1", ClientSecret: "s", RedirectURL: "https://app.example.test/cb", HTTPClient: fp.srv.Client()}
	}
	cases := map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"missing client id": {func(c *Config) { c.ClientID = "" }, "required"},
		"relative redirect": {func(c *Config) { c.RedirectURL = "/cb" }, "RedirectURL"},
		"no openid":         {func(c *Config) { c.Scopes = []string{"profile"} }, "openid"},
		"basic no secret":   {func(c *Config) { c.ClientSecret = ""; c.AuthMethod = AuthMethodBasic }, "needs a ClientSecret"},
		"none with secret":  {func(c *Config) { c.AuthMethod = AuthMethodNone }, "cannot be combined"},
		"unknown method":    {func(c *Config) { c.AuthMethod = "private_key_jwt" }, "unknown AuthMethod"},
		"negative skew":     {func(c *Config) { c.ClockSkew = -time.Second }, "ClockSkew"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			_, err := New(ctx, cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("defaults", func(t *testing.T) {
		c, err := New(ctx, base())
		if err != nil {
			t.Fatal(err)
		}
		if c.cfg.AuthMethod != AuthMethodBasic || c.cfg.ClockSkew != time.Minute || strings.Join(c.cfg.Scopes, " ") != "openid profile email" || !c.secure {
			t.Fatalf("config %+v", c.cfg)
		}
		cfg := base()
		cfg.ClientSecret = ""
		c, err = New(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if c.cfg.AuthMethod != AuthMethodNone {
			t.Fatalf("public client auth method %q", c.cfg.AuthMethod)
		}
	})
}

func TestAuthCodeURL(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	c := newTestClient(t, fp, nil)
	verifier := NewPKCEVerifier()
	if len(verifier) != 43 {
		t.Fatalf("verifier length %d", len(verifier))
	}
	raw := c.AuthCodeURL("st", "no", verifier,
		WithPrompt("login"), WithMaxAge(5*time.Minute), WithACRValues("urn:fireid:loa:2"),
		WithLoginHint("ann"), WithExtra("ui_locales", "en"), WithExtra("client_id", "evil"), WithExtra("redirect_uri", "https://evil.test"))
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": "app-1", "redirect_uri": fp.redirectURI,
		"scope": "openid profile email", "state": "st", "nonce": "no",
		"code_challenge": pkceChallenge(verifier), "code_challenge_method": "S256",
		"prompt": "login", "max_age": "300", "acr_values": "urn:fireid:loa:2", "login_hint": "ann", "ui_locales": "en",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if !strings.HasPrefix(raw, fp.issuer+"/authorize?") {
		t.Errorf("url %s", raw)
	}
	if appendQuery("https://x/a?b=1", url.Values{"c": {"2"}}) != "https://x/a?b=1&c=2" {
		t.Error("appendQuery with an existing query")
	}
}

// authorize drives the fake provider's authorization endpoint for c and
// returns the code it issued.
func authorize(t *testing.T, fp *fakeProvider, c *Client, state, nonce, verifier string) string {
	t.Helper()
	hc := fp.srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Get(c.AuthCodeURL(state, nonce, verifier))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != state {
		t.Fatalf("state %q", loc.Query().Get("state"))
	}
	return loc.Query().Get("code")
}

func TestExchangeRefreshUserInfo(t *testing.T) {
	for _, method := range []string{AuthMethodBasic, AuthMethodPost, AuthMethodNone} {
		t.Run(method, func(t *testing.T) {
			clk := newClock()
			fp := newFakeProvider(t, clk)
			fp.authMethod = method
			if method == AuthMethodNone {
				fp.clientSecret = ""
			}
			c := newTestClient(t, fp, nil)
			ctx := context.Background()
			verifier := NewPKCEVerifier()
			code := authorize(t, fp, c, "st-1", "nonce-1", verifier)

			tokens, err := c.Exchange(ctx, code, verifier, WithNonce("nonce-1"))
			if err != nil {
				t.Fatal(err)
			}
			if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" || tokens.TokenType != "Bearer" {
				t.Fatalf("tokens %+v", tokens)
			}
			if !tokens.Expiry.Equal(clk.now().Add(time.Hour)) {
				t.Fatalf("expiry %v", tokens.Expiry)
			}
			if tokens.Claims == nil || tokens.Claims.Subject != "42" || tokens.Claims.Nonce != "nonce-1" {
				t.Fatalf("claims %+v", tokens.Claims)
			}

			// The code is single-use at the provider.
			_, err = c.Exchange(ctx, code, verifier, WithNonce("nonce-1"))
			var te *TokenError
			if !errors.As(err, &te) || te.Code != "invalid_grant" {
				t.Fatalf("second exchange: %v", err)
			}
			if ErrorStatus(err) != http.StatusBadGateway {
				t.Fatalf("status for TokenError %d", ErrorStatus(err))
			}

			// A wrong verifier is refused by the provider.
			code = authorize(t, fp, c, "st-2", "nonce-2", verifier)
			if _, err := c.Exchange(ctx, code, NewPKCEVerifier(), WithNonce("nonce-2")); !errors.As(err, &te) {
				t.Fatalf("wrong verifier: %v", err)
			}

			// A wrong nonce is refused by the client even though the
			// provider's answer is fine.
			code = authorize(t, fp, c, "st-3", "nonce-3", verifier)
			if _, err := c.Exchange(ctx, code, verifier, WithNonce("other")); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("wrong nonce: %v", err)
			}

			ui, err := c.UserInfoFor(ctx, tokens.AccessToken, tokens.Claims.Subject)
			if err != nil {
				t.Fatal(err)
			}
			if ui.Subject != "42" || ui.Email != "ann@example.test" || !ui.EmailVerified || ui.PreferredUsername != "ann" || ui.Raw["name"] != "Ann Example" {
				t.Fatalf("userinfo %+v", ui)
			}
			if _, err := c.UserInfoFor(ctx, tokens.AccessToken, "43"); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("userinfo sub mismatch: %v", err)
			}
			if _, err := c.UserInfo(ctx, "bogus"); !errors.As(err, &te) || te.Code != "invalid_token" {
				t.Fatalf("userinfo with a bad token: %v", err)
			}

			refreshed, err := c.Refresh(ctx, tokens.RefreshToken, WithExpectedSubject("42"))
			if err != nil {
				t.Fatal(err)
			}
			if refreshed.RefreshToken == tokens.RefreshToken || refreshed.Claims == nil || refreshed.Claims.Subject != "42" || refreshed.Claims.Nonce != "" {
				t.Fatalf("refreshed %+v %+v", refreshed, refreshed.Claims)
			}
			// The old refresh token was rotated out.
			if _, err := c.Refresh(ctx, tokens.RefreshToken); !errors.As(err, &te) {
				t.Fatalf("rotated refresh token: %v", err)
			}
			// A refreshed token about someone else is refused.
			fp.mu.Lock()
			fp.sub = "43"
			fp.mu.Unlock()
			if _, err := c.Refresh(ctx, refreshed.RefreshToken, WithExpectedSubject("42")); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("subject change on refresh: %v", err)
			}
		})
	}
}

func TestEndSessionURL(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	c := newTestClient(t, fp, nil)
	raw, err := c.EndSessionURL("id.tok.en", "https://app.example.test/", "s1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if u.Path != "/end_session" || q.Get("id_token_hint") != "id.tok.en" || q.Get("post_logout_redirect_uri") != "https://app.example.test/" ||
		q.Get("state") != "s1" || q.Get("client_id") != "app-1" {
		t.Fatalf("url %s", raw)
	}
	fp.mu.Lock()
	fp.endSession = false
	fp.mu.Unlock()
	c = newTestClient(t, fp, nil)
	if _, err := c.EndSessionURL("x", "", ""); err == nil {
		t.Fatal("no end_session_endpoint must be an error")
	}
}
