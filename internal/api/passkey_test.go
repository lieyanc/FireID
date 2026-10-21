package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"github.com/lieyanc/FireID/internal/store"
)

// The tests play the authenticator themselves: they build the bytes a browser
// and a platform authenticator would produce, independently of the library
// under test, so a regression in how the server reads them shows up here.

var (
	testKeyOnce sync.Once
	testKeyVal  *ecdsa.PrivateKey
)

// testKey is the P-256 key of the software authenticator, shared by a test run.
func testKey() *ecdsa.PrivateKey {
	testKeyOnce.Do(func() {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		testKeyVal = k
	})
	return testKeyVal
}

func testCredentialID() []byte { return []byte("test-passkey-credential-00001") }

// testCOSEKey encodes the public key as a COSE_Key: kty EC2, alg ES256, crv P-256.
func testCOSEKey(key *ecdsa.PrivateKey) []byte {
	raw, err := key.PublicKey.Bytes() // 0x04 || x || y
	if err != nil {
		panic(err)
	}
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	if err != nil {
		panic(err)
	}
	return cose
}

// testAttestedData is AAGUID (zero) || credentialId length || credentialId || COSE key.
func testAttestedData(credentialID, publicKey []byte) []byte {
	out := make([]byte, 16, 18+len(credentialID)+len(publicKey))
	out = binary.BigEndian.AppendUint16(out, uint16(len(credentialID)))
	out = append(out, credentialID...)
	return append(out, publicKey...)
}

// testAuthData is rpIdHash || flags || signCount || attested credential data.
func testAuthData(rpid string, flags protocol.AuthenticatorFlags, signCount uint32, attestedData []byte) []byte {
	h := sha256.Sum256([]byte(rpid))
	out := append(h[:], byte(flags))
	out = binary.BigEndian.AppendUint32(out, signCount)
	return append(out, attestedData...)
}

func testClientDataJSON(ceremony, challenge, origin string) []byte {
	raw, _ := json.Marshal(map[string]any{
		"type": ceremony, "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
	return raw
}

// testSign is the assertion signature: ES256 over authData || SHA-256(clientDataJSON), DER.
func testSign(key *ecdsa.PrivateKey, authData, clientDataJSON []byte) []byte {
	cd := sha256.Sum256(clientDataJSON)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cd[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// testAttestationObject is the "none" attestation the server asks for.
func testAttestationObject(authData []byte) []byte {
	raw, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		panic(err)
	}
	return raw
}

var b64 = base64.RawURLEncoding.EncodeToString

func testRegistrationBody(credentialID, attestationObject, clientDataJSON []byte) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"id": b64(credentialID), "rawId": b64(credentialID), "type": "public-key",
		"response": map[string]any{
			"attestationObject": b64(attestationObject), "clientDataJSON": b64(clientDataJSON),
		},
	})
	return raw
}

func testAssertionBody(credentialID, authData, clientDataJSON, signature, userHandle []byte) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"id": b64(credentialID), "rawId": b64(credentialID), "type": "public-key",
		"response": map[string]any{
			"authenticatorData": b64(authData), "clientDataJSON": b64(clientDataJSON),
			"signature": b64(signature), "userHandle": b64(userHandle),
		},
	})
	return raw
}

const (
	flagsUV   = protocol.FlagUserPresent | protocol.FlagUserVerified
	flagsRegV = flagsUV | protocol.FlagAttestedCredentialData
)

// passkeyEnv is an oidcEnv whose issuer is http://localhost:<port>: the
// WebAuthn RP ID must be a host name. Requests still go to 127.0.0.1 and send
// no Origin header, so the API's cross-site check is not involved.
type passkeyEnv struct {
	*oidcEnv
	origin string
}

func newPasskeyEnv(t *testing.T) *passkeyEnv {
	t.Helper()
	e := newOIDCEnv(t)
	origin := fmt.Sprintf("http://localhost:%d", e.ts.Listener.Addr().(*net.TCPAddr).Port)
	e.auth.SetIssuer(origin)
	return &passkeyEnv{oidcEnv: e, origin: origin}
}

// begin starts a ceremony and returns its id and challenge.
func (e *passkeyEnv) begin(c *http.Client, path string, body map[string]any) (ceremonyID, challenge string) {
	e.t.Helper()
	st, resp := e.postJSON(c, path, body)
	wantStatus(e.t, path, st, http.StatusOK, resp)
	pk, _ := resp["publicKey"].(map[string]any)
	ceremonyID, _ = resp["ceremonyId"].(string)
	challenge, _ = pk["challenge"].(string)
	if ceremonyID == "" || challenge == "" || pk["rpId"] != nil && pk["rpId"] != "localhost" {
		e.t.Fatalf("%s: ceremony %v", path, resp)
	}
	return ceremonyID, challenge
}

// registerAs runs a registration with the given origin and flags and returns
// the finish response.
func (e *passkeyEnv) registerAs(c *http.Client, name string, credID []byte, key *ecdsa.PrivateKey, origin string, flags protocol.AuthenticatorFlags) (int, map[string]any) {
	e.t.Helper()
	id, challenge := e.begin(c, "/api/account/passkeys/begin", map[string]any{"password": testPassword})
	cd := testClientDataJSON("webauthn.create", challenge, origin)
	att := testAttestationObject(testAuthData("localhost", flags, 0, testAttestedData(credID, testCOSEKey(key))))
	return e.postJSON(c, "/api/account/passkeys/finish", map[string]any{
		"ceremonyId": id, "name": name, "response": testRegistrationBody(credID, att, cd),
	})
}

// register adds a user-verified passkey to the signed-in account.
func (e *passkeyEnv) register(c *http.Client, name string, credID []byte, key *ecdsa.PrivateKey) map[string]any {
	e.t.Helper()
	st, body := e.registerAs(c, name, credID, key, e.origin, flagsRegV)
	wantStatus(e.t, "register "+name, st, http.StatusCreated, body)
	pk, _ := body["passkey"].(map[string]any)
	if pk == nil {
		e.t.Fatalf("register: %v", body)
	}
	return pk
}

// assertion is what the authenticator answers to a sign-in challenge.
type assertion struct {
	credID []byte
	key    *ecdsa.PrivateKey
	handle []byte
	flags  protocol.AuthenticatorFlags
	count  uint32
	origin string
}

// aliceAssertion is a valid user-verified answer from alice's test passkey.
func (e *passkeyEnv) aliceAssertion(count uint32) assertion {
	e.t.Helper()
	u, err := e.st.UserByID(e.user.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	handle, err := base64.RawURLEncoding.DecodeString(u.WebAuthnID)
	if err != nil || len(handle) == 0 {
		e.t.Fatalf("alice has no user handle (%q)", u.WebAuthnID)
	}
	return assertion{credID: testCredentialID(), key: testKey(), handle: handle,
		flags: flagsUV, count: count, origin: e.origin}
}

func (a assertion) answer(challenge string) json.RawMessage {
	ad := testAuthData("localhost", a.flags, a.count, nil)
	cd := testClientDataJSON("webauthn.get", challenge, a.origin)
	return testAssertionBody(a.credID, ad, cd, testSign(a.key, ad, cd), a.handle)
}

// signIn runs a passkey sign-in in browser c.
func (e *passkeyEnv) signIn(c *http.Client, a assertion) (int, map[string]any) {
	e.t.Helper()
	id, challenge := e.begin(c, "/api/auth/login/passkey/begin", map[string]any{})
	return e.postJSON(c, "/api/auth/login/passkey/finish", map[string]any{
		"ceremonyId": id, "response": a.answer(challenge),
	})
}

func (e *passkeyEnv) listPasskeys(c *http.Client) []map[string]any {
	e.t.Helper()
	st, body := e.send(c, http.MethodGet, "/api/account/passkeys", nil)
	wantStatus(e.t, "list passkeys", st, http.StatusOK, body)
	var out []map[string]any
	for _, x := range body["passkeys"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

// signedInAlice is a browser with a password session and alice's test passkey.
func (e *passkeyEnv) signedInAlice() *http.Client {
	e.t.Helper()
	c := e.browser()
	e.passwordSignIn(c, "alice")
	e.register(c, "Laptop", testCredentialID(), testKey())
	return c
}

func TestPasskeyRegistration(t *testing.T) {
	e := newPasskeyEnv(t)
	owner := e.browser()
	e.passwordSignIn(owner, "alice")

	t.Run("an answer from another origin is refused", func(t *testing.T) {
		st, body := e.registerAs(owner, "x", []byte("evil-cred"), testKey(), "http://evil.example", flagsRegV)
		if st == http.StatusCreated {
			t.Fatalf("registered from a foreign origin: %v", body)
		}
	})

	t.Run("an authenticator that did not verify the person is refused", func(t *testing.T) {
		st, body := e.registerAs(owner, "x", []byte("no-uv-cred"), testKey(), e.origin,
			protocol.FlagUserPresent|protocol.FlagAttestedCredentialData)
		if st == http.StatusCreated {
			t.Fatalf("registered without user verification: %v", body)
		}
	})

	if n, _ := e.st.CountPasskeys(e.user.ID); n != 0 {
		t.Fatalf("%d passkeys stored by refused registrations", n)
	}

	pk := e.register(owner, "Laptop", testCredentialID(), testKey())
	if pk["name"] != "Laptop" || pk["id"] == nil || pk["lastUsedAt"] != "" || pk["createdAt"] == "" {
		t.Fatalf("passkey %v", pk)
	}
	for _, secret := range []string{"publicKey", "credentialId"} {
		if _, leaked := pk[secret]; leaked {
			t.Fatalf("%s in the response", secret)
		}
	}

	list := e.listPasskeys(owner)
	if len(list) != 1 || list[0]["id"] != pk["id"] || list[0]["name"] != "Laptop" {
		t.Fatalf("list %v", list)
	}

	t.Run("the ceremony cannot be finished twice", func(t *testing.T) {
		id, challenge := e.begin(owner, "/api/account/passkeys/begin", map[string]any{"password": testPassword})
		cred := []byte("second-cred")
		cd := testClientDataJSON("webauthn.create", challenge, e.origin)
		att := testAttestationObject(testAuthData("localhost", flagsRegV, 0, testAttestedData(cred, testCOSEKey(testKey()))))
		req := map[string]any{"ceremonyId": id, "name": "Phone", "response": testRegistrationBody(cred, att, cd)}
		st, body := e.postJSON(owner, "/api/account/passkeys/finish", req)
		wantStatus(t, "first finish", st, http.StatusCreated, body)
		st, body = e.postJSON(owner, "/api/account/passkeys/finish", req)
		wantError(t, "second finish", st, http.StatusUnauthorized, body, "invalid_ceremony")
	})

	t.Run("the same credential cannot be registered twice", func(t *testing.T) {
		st, body := e.registerAs(owner, "again", testCredentialID(), testKey(), e.origin, flagsRegV)
		if st == http.StatusCreated {
			t.Fatalf("registered the same credential twice: %v", body)
		}
		if n := len(e.listPasskeys(owner)); n != 2 {
			t.Fatalf("%d passkeys", n)
		}
	})
}

func TestPasskeyLogin(t *testing.T) {
	e := newPasskeyEnv(t)
	owner := e.signedInAlice()

	c := e.browser()
	st, body := e.signIn(c, e.aliceAssertion(1))
	wantStatus(t, "finish", st, http.StatusOK, body)
	if u, _ := body["user"].(map[string]any); u["username"] != "alice" {
		t.Fatalf("signed in as %v", body)
	}
	if body["challenge"] != nil {
		t.Fatalf("a passkey sign-in asked for a second step: %v", body)
	}
	me := e.me(c)
	if me["acr"] != store.ACRLoA2 || strings.Join(stringList(me["amr"]), " ") != "webauthn" {
		t.Fatalf("session acr=%v amr=%v", me["acr"], me["amr"])
	}
	if list := e.listPasskeys(owner); list[0]["lastUsedAt"] == "" {
		t.Fatalf("lastUsedAt not recorded: %v", list[0])
	}

	t.Run("a sign-in started by an app returns to it", func(t *testing.T) {
		c := e.browser()
		params := e.webParams("openid")
		params.Set("response_type", "code")
		loc := location(t, e.get(c, "/authorize?"+params.Encode()), http.StatusFound)
		authReqID := loc.Query().Get("auth_req_id")
		if authReqID == "" {
			t.Fatalf("no auth_req_id in %s", loc)
		}
		id, challenge := e.begin(c, "/api/auth/login/passkey/begin", map[string]any{})
		st, body := e.postJSON(c, "/api/auth/login/passkey/finish", map[string]any{
			"ceremonyId": id, "response": e.aliceAssertion(2).answer(challenge), "authReqId": authReqID,
		})
		wantStatus(t, "finish", st, http.StatusOK, body)
		next, _ := body["redirectTo"].(string)
		if next == "" {
			t.Fatalf("no redirect: %v", body)
		}
		cb := location(t, e.get(c, next), http.StatusFound)
		if cb.Query().Get("code") == "" || cb.Query().Get("state") != "st-1" {
			t.Fatalf("callback %s", cb)
		}
	})
}

// TestPasskeyLoginWithoutUV: the server asks for user verification, and an
// authenticator that skipped it is refused outright rather than downgraded.
func TestPasskeyLoginWithoutUV(t *testing.T) {
	e := newPasskeyEnv(t)
	e.signedInAlice()

	a := e.aliceAssertion(1)
	a.flags = protocol.FlagUserPresent
	c := e.browser()
	st, body := e.signIn(c, a)
	wantError(t, "finish", st, http.StatusUnauthorized, body, "invalid_credentials")
	if resp := e.get(c, "/api/auth/me"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me after a refused sign-in: %d", resp.StatusCode)
	}
}

func TestPasskeyLoginRefusals(t *testing.T) {
	e := newPasskeyEnv(t)
	e.signedInAlice()

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		tweak func(*assertion)
	}{
		{"unknown credential", func(a *assertion) { a.credID = []byte("never-registered") }},
		{"unknown user handle", func(a *assertion) { a.handle = []byte("nobody") }},
		{"signed by another key", func(a *assertion) { a.key = other }},
		{"another origin", func(a *assertion) { a.origin = "http://evil.example" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := e.aliceAssertion(1)
			tc.tweak(&a)
			st, body := e.signIn(e.browser(), a)
			wantError(t, "finish", st, http.StatusUnauthorized, body, "invalid_credentials")
		})
	}

	t.Run("a disabled account cannot sign in", func(t *testing.T) {
		ee := newPasskeyEnv(t)
		ee.signedInAlice()
		if err := ee.st.SetStatus(ee.user.ID, store.UserDisabled); err != nil {
			t.Fatal(err)
		}
		st, body := ee.signIn(ee.browser(), ee.aliceAssertion(1))
		wantError(t, "finish", st, http.StatusUnauthorized, body, "invalid_credentials")
	})

	// The refusals above did not move the stored counter: a valid answer
	// with counter 1 still works.
	st, body := e.signIn(e.browser(), e.aliceAssertion(1))
	wantStatus(t, "valid after refusals", st, http.StatusOK, body)
}

func TestPasskeyCeremonyIsSingleUse(t *testing.T) {
	e := newPasskeyEnv(t)
	e.signedInAlice()

	c := e.browser()
	id, challenge := e.begin(c, "/api/auth/login/passkey/begin", map[string]any{})
	req := map[string]any{"ceremonyId": id, "response": e.aliceAssertion(1).answer(challenge)}
	st, body := e.postJSON(c, "/api/auth/login/passkey/finish", req)
	wantStatus(t, "first", st, http.StatusOK, body)

	// The same answer again, even with a fresh counter, has no ceremony.
	req["response"] = e.aliceAssertion(2).answer(challenge)
	st, body = e.postJSON(e.browser(), "/api/auth/login/passkey/finish", req)
	wantError(t, "reuse", st, http.StatusUnauthorized, body, "invalid_ceremony")

	t.Run("a registration ceremony cannot finish a sign-in", func(t *testing.T) {
		owner := e.browser()
		e.passwordSignIn(owner, "alice")
		id, challenge := e.begin(owner, "/api/account/passkeys/begin", map[string]any{"password": testPassword})
		st, body := e.postJSON(e.browser(), "/api/auth/login/passkey/finish", map[string]any{
			"ceremonyId": id, "response": e.aliceAssertion(3).answer(challenge)})
		wantError(t, "cross-ceremony", st, http.StatusUnauthorized, body, "invalid_ceremony")
	})
}

func TestPasskeyReplay(t *testing.T) {
	e := newPasskeyEnv(t)
	e.signedInAlice()

	st, body := e.signIn(e.browser(), e.aliceAssertion(5))
	wantStatus(t, "counter 5", st, http.StatusOK, body)

	// A copy of the key, or a captured answer re-signed, cannot reuse or go
	// below the counter the server has seen.
	for _, count := range []uint32{5, 4} {
		st, body := e.signIn(e.browser(), e.aliceAssertion(count))
		wantError(t, fmt.Sprintf("counter %d", count), st, http.StatusUnauthorized, body, "invalid_credentials")
	}
	st, body = e.signIn(e.browser(), e.aliceAssertion(6))
	wantStatus(t, "counter 6", st, http.StatusOK, body)
}

// Many synced passkeys always report 0; that is not a replay.
func TestPasskeyZeroCounter(t *testing.T) {
	e := newPasskeyEnv(t)
	e.signedInAlice()
	for i := range 2 {
		st, body := e.signIn(e.browser(), e.aliceAssertion(0))
		wantStatus(t, fmt.Sprintf("sign-in %d", i), st, http.StatusOK, body)
	}
}

func TestPasskeyRename(t *testing.T) {
	e := newPasskeyEnv(t)
	owner := e.signedInAlice()
	id := e.listPasskeys(owner)[0]["id"].(float64)

	st, body := e.postJSON(owner, fmt.Sprintf("/api/account/passkeys/%d/rename", int64(id)),
		map[string]any{"name": "  Work laptop  "})
	wantStatus(t, "rename", st, http.StatusNoContent, body)
	if list := e.listPasskeys(owner); list[0]["name"] != "Work laptop" {
		t.Fatalf("after rename: %v", list[0])
	}

	st, body = e.postJSON(e.browser(), fmt.Sprintf("/api/account/passkeys/%d/rename", int64(id)),
		map[string]any{"name": "x"})
	wantError(t, "anonymous", st, http.StatusUnauthorized, body, "unauthenticated")
}

func TestPasskeyDelete(t *testing.T) {
	e := newPasskeyEnv(t)
	owner := e.signedInAlice()
	e.register(owner, "Phone", []byte("test-passkey-credential-00002"), testKey())

	list := e.listPasskeys(owner)
	if len(list) != 2 {
		t.Fatalf("list %v", list)
	}
	first, second := int64(list[0]["id"].(float64)), int64(list[1]["id"].(float64))
	st, body := e.send(owner, http.MethodDelete, fmt.Sprintf("/api/account/passkeys/%d", first), nil)
	wantStatus(t, "delete", st, http.StatusNoContent, body)
	list = e.listPasskeys(owner)
	if len(list) != 1 || int64(list[0]["id"].(float64)) != second || list[0]["name"] != "Phone" {
		t.Fatalf("after delete: %v", list)
	}

	t.Run("a deleted passkey no longer signs in", func(t *testing.T) {
		st, body := e.signIn(e.browser(), e.aliceAssertion(1))
		wantError(t, "finish", st, http.StatusUnauthorized, body, "invalid_credentials")
	})

	// With no password and no email, the remaining passkey is the only way in.
	if err := e.st.ClearPassword(e.user.ID); err != nil {
		t.Fatal(err)
	}
	e.mailer.mu.Lock()
	e.mailer.enabled = false
	e.mailer.mu.Unlock()
	passkeyOnly := e.sessionFor(e.user) // clearing the password ended owner's session
	last := fmt.Sprintf("/api/account/passkeys/%d", second)
	st, body = e.send(passkeyOnly, http.MethodDelete, last, nil)
	wantError(t, "last", st, http.StatusConflict, body, "last_credential")

	// Email sign-in is a way back in, so then it may go.
	e.mailer.mu.Lock()
	e.mailer.enabled = true
	e.mailer.mu.Unlock()
	st, body = e.send(passkeyOnly, http.MethodDelete, last, nil)
	wantStatus(t, "last with email", st, http.StatusNoContent, body)
}
