package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a settable time source shared by the fake provider and the
// client under test, so expiry and rate limits are tested without sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// signingKey is one of the fake provider's keys, with everything needed to
// sign a token and to publish the public half.
type signingKey struct {
	kid  string
	alg  string
	priv crypto.Signer
}

// rsaTestKey is generated once: 2048-bit generation is slow and the tests
// need many clients.
var rsaTestKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

func newSigningKey(t *testing.T, kid, alg string) *signingKey {
	t.Helper()
	k := &signingKey{kid: kid, alg: alg}
	var err error
	switch alg {
	case algRS256, algPS256:
		k.priv = rsaTestKey()
	case algES256:
		k.priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case algEdDSA:
		_, k.priv, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("no test key for alg %s", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// jwk is the public half as the provider publishes it. The alg is stated,
// as Fire ID does.
func (k *signingKey) jwk() map[string]any {
	j := map[string]any{"kid": k.kid, "alg": k.alg, "use": "sig"}
	switch pub := k.priv.Public().(type) {
	case *rsa.PublicKey:
		j["kty"] = "RSA"
		j["n"] = b64.EncodeToString(pub.N.Bytes())
		j["e"] = b64.EncodeToString([]byte{1, 0, 1})
	case *ecdsa.PublicKey:
		x, y := make([]byte, 32), make([]byte, 32)
		pub.X.FillBytes(x)
		pub.Y.FillBytes(y)
		j["kty"], j["crv"] = "EC", "P-256"
		j["x"], j["y"] = b64.EncodeToString(x), b64.EncodeToString(y)
	case ed25519.PublicKey:
		j["kty"], j["crv"] = "OKP", "Ed25519"
		j["x"] = b64.EncodeToString(pub)
	}
	return j
}

// sign makes a compact JWS over claims. header may add or override header
// members; alg and kid are filled in from the key when absent.
func (k *signingKey) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": k.alg, "kid": k.kid}
	for name, v := range header {
		h[name] = v
	}
	hj, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	pj, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signSegments(t, k, b64.EncodeToString(hj), b64.EncodeToString(pj))
}

// signSegments signs already-encoded header and payload segments.
func signSegments(t *testing.T, k *signingKey, header, payload string) string {
	t.Helper()
	input := []byte(header + "." + payload)
	var sig []byte
	var err error
	switch priv := k.priv.(type) {
	case *rsa.PrivateKey:
		h := sha256.Sum256(input)
		if k.alg == algPS256 {
			sig, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
		}
	case *ecdsa.PrivateKey:
		h := sha256.Sum256(input)
		var r, s interface{ FillBytes([]byte) []byte }
		r, s, err = ecdsa.Sign(rand.Reader, priv, h[:])
		if err == nil {
			sig = make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(priv, input)
	}
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + payload + "." + b64.EncodeToString(sig)
}

// authRequest is what the fake provider remembers about an issued code.
type authRequest struct {
	nonce       string
	challenge   string
	redirectURI string
}

// fakeProvider is an OpenID provider for tests: discovery, JWKS,
// authorization code with PKCE, token, userinfo. It approves every
// authorization request at once for one fixed user.
type fakeProvider struct {
	t      *testing.T
	clock  *clock
	srv    *httptest.Server
	issuer string

	clientID     string
	clientSecret string
	redirectURI  string
	authMethod   string // what the token endpoint demands

	mu            sync.Mutex
	keys          []*signingKey // published; keys[0] signs
	jwksHits      int
	issParam      bool
	backchannel   bool
	endSession    bool
	docIssuer     string // issuer written into the discovery document
	codes         map[string]authRequest
	accessTokens  map[string]string // token -> sub
	refreshTokens map[string]string
	sub           string
}

func newFakeProvider(t *testing.T, clk *clock) *fakeProvider {
	t.Helper()
	fp := &fakeProvider{
		t:             t,
		clock:         clk,
		clientID:      "app-1",
		clientSecret:  "s3cret",
		authMethod:    AuthMethodBasic,
		keys:          []*signingKey{newSigningKey(t, "k1", algES256)},
		endSession:    true,
		backchannel:   true,
		codes:         map[string]authRequest{},
		accessTokens:  map[string]string{},
		refreshTokens: map[string]string{},
		sub:           "42",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", fp.discovery)
	mux.HandleFunc("GET /keys", fp.jwks)
	mux.HandleFunc("GET /authorize", fp.authorize)
	mux.HandleFunc("POST /oauth/token", fp.token)
	mux.HandleFunc("GET /userinfo", fp.userinfo)
	fp.srv = httptest.NewServer(mux)
	t.Cleanup(fp.srv.Close)
	fp.issuer = fp.srv.URL
	fp.docIssuer = fp.srv.URL
	fp.redirectURI = "https://app.example.test/callback"
	return fp
}

// current is the key that signs.
func (fp *fakeProvider) current() *signingKey {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.keys[0]
}

// rotate publishes k and makes it the signing key; the old ones stay.
func (fp *fakeProvider) rotate(k *signingKey) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.keys = append([]*signingKey{k}, fp.keys...)
}

// retire removes a key from the published set.
func (fp *fakeProvider) retire(kid string) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	var keep []*signingKey
	for _, k := range fp.keys {
		if k.kid != kid {
			keep = append(keep, k)
		}
	}
	fp.keys = keep
}

func (fp *fakeProvider) fetches() int {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.jwksHits
}

func (fp *fakeProvider) discovery(w http.ResponseWriter, r *http.Request) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	doc := map[string]any{
		"issuer":                 fp.docIssuer,
		"authorization_endpoint": fp.issuer + "/authorize",
		"token_endpoint":         fp.issuer + "/oauth/token",
		"userinfo_endpoint":      fp.issuer + "/userinfo",
		"jwks_uri":               fp.issuer + "/keys",
		"authorization_response_iss_parameter_supported": fp.issParam,
		"backchannel_logout_supported":                   fp.backchannel,
	}
	if fp.endSession {
		doc["end_session_endpoint"] = fp.issuer + "/end_session"
	}
	writeJSON(w, http.StatusOK, doc)
}

func (fp *fakeProvider) jwks(w http.ResponseWriter, r *http.Request) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.jwksHits++
	keys := make([]map[string]any, 0, len(fp.keys))
	for _, k := range fp.keys {
		keys = append(keys, k.jwk())
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (fp *fakeProvider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != fp.clientID || q.Get("redirect_uri") != fp.redirectURI ||
		q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || !strings.Contains(q.Get("scope"), "openid") {
		http.Error(w, "bad authorization request: "+r.URL.RawQuery, http.StatusBadRequest)
		return
	}
	code := "code-" + RandomString()
	fp.mu.Lock()
	fp.codes[code] = authRequest{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri")}
	issParam := fp.issParam
	fp.mu.Unlock()
	u, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	if issParam {
		v.Set("iss", fp.issuer)
	}
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// authenticated checks client authentication the way the provider was told
// to expect it.
func (fp *fakeProvider) authenticated(r *http.Request) bool {
	switch fp.authMethod {
	case AuthMethodBasic:
		id, secret, ok := r.BasicAuth()
		if !ok {
			return false
		}
		id, err1 := url.QueryUnescape(id)
		secret, err2 := url.QueryUnescape(secret)
		return err1 == nil && err2 == nil && id == fp.clientID && secret == fp.clientSecret &&
			r.PostForm.Get("client_secret") == ""
	case AuthMethodPost:
		return r.PostForm.Get("client_id") == fp.clientID && r.PostForm.Get("client_secret") == fp.clientSecret
	default:
		_, _, basic := r.BasicAuth()
		return !basic && r.PostForm.Get("client_id") == fp.clientID && r.PostForm.Get("client_secret") == ""
	}
}

func (fp *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	if !fp.authenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		fp.mu.Lock()
		ar, ok := fp.codes[r.PostForm.Get("code")]
		delete(fp.codes, r.PostForm.Get("code"))
		fp.mu.Unlock()
		if !ok || ar.redirectURI != r.PostForm.Get("redirect_uri") ||
			pkceChallenge(r.PostForm.Get("code_verifier")) != ar.challenge {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "code, redirect_uri or verifier"})
			return
		}
		fp.issue(w, ar.nonce)
	case "refresh_token":
		fp.mu.Lock()
		_, ok := fp.refreshTokens[r.PostForm.Get("refresh_token")]
		delete(fp.refreshTokens, r.PostForm.Get("refresh_token"))
		fp.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			return
		}
		fp.issue(w, "")
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
	}
}

// issue writes a token response with a fresh ID token; a refreshed one
// carries no nonce.
func (fp *fakeProvider) issue(w http.ResponseWriter, nonce string) {
	at, rt := "at-"+RandomString(), "rt-"+RandomString()
	fp.mu.Lock()
	fp.accessTokens[at] = fp.sub
	fp.refreshTokens[rt] = fp.sub
	fp.mu.Unlock()
	over := map[string]any{"at_hash": leftHalfHash(fp.current().alg, at), "nonce": nil}
	if nonce != "" {
		over["nonce"] = nonce
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  at,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": rt,
		"id_token":      fp.idToken(over),
	})
}

func (fp *fakeProvider) userinfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	fp.mu.Lock()
	sub, ok := fp.accessTokens[token]
	fp.mu.Unlock()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="unknown token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub": sub, "email": "ann@example.test", "email_verified": true,
		"name": "Ann Example", "preferred_username": "ann",
	})
}

// idClaims are the claims of a valid ID token for the client, with over
// applied on top. A nil value in over removes the claim.
func (fp *fakeProvider) idClaims(over map[string]any) map[string]any {
	now := fp.clock.now()
	cl := map[string]any{
		"iss": fp.issuer, "sub": fp.sub, "aud": fp.clientID,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "auth_time": now.Add(-time.Minute).Unix(),
		"nonce": "n-1", "acr": "urn:fireid:loa:2", "amr": []string{"webauthn"}, "sid": "sess-1",
		"email": "ann@example.test", "email_verified": true, "name": "Ann Example", "preferred_username": "ann",
	}
	return applyOver(cl, over)
}

// logoutClaims are the claims of a valid logout token, with over applied.
func (fp *fakeProvider) logoutClaims(over map[string]any) map[string]any {
	now := fp.clock.now()
	cl := map[string]any{
		"iss": fp.issuer, "sub": fp.sub, "aud": fp.clientID,
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti":    "jti-" + RandomString(),
		"sid":    "sess-1",
		"events": map[string]any{logoutEvent: map[string]any{}},
	}
	return applyOver(cl, over)
}

func applyOver(cl, over map[string]any) map[string]any {
	for k, v := range over {
		if v == nil {
			delete(cl, k)
		} else {
			cl[k] = v
		}
	}
	return cl
}

// idToken signs idClaims(over) with the current key.
func (fp *fakeProvider) idToken(over map[string]any) string {
	return fp.current().sign(fp.t, nil, fp.idClaims(over))
}

// logoutToken signs logoutClaims(over) with the current key and typ logout+jwt.
func (fp *fakeProvider) logoutToken(over map[string]any) string {
	return fp.current().sign(fp.t, map[string]any{"typ": "logout+jwt"}, fp.logoutClaims(over))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// newTestClient builds a Client against fp, on fp's clock. mutate may
// adjust the Config first.
func newTestClient(t *testing.T, fp *fakeProvider, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		Issuer:       fp.issuer,
		ClientID:     fp.clientID,
		ClientSecret: fp.clientSecret,
		RedirectURL:  fp.redirectURI,
		AuthMethod:   fp.authMethod,
		HTTPClient:   fp.srv.Client(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.now = fp.clock.now
	c.keys.now = fp.clock.now
	return c
}

// tamperSegment replaces segment i of a compact JWS.
func tamperSegment(raw string, i int, with string) string {
	parts := strings.Split(raw, ".")
	parts[i] = with
	return strings.Join(parts, ".")
}
