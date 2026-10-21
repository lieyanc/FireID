package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lieyanc/FireID/client"
	"github.com/lieyanc/FireID/internal/store"
)

// The conformance tests walk the items of the OpenID Foundation OP test
// plans at the wire level. docs/conformance.md maps each item to its test.

// knownGap records a check the server does not pass yet. It skips, so the
// suite stays green while the gap is open; with FIREID_CONFORMANCE_STRICT set
// it fails instead, which is how to confirm a fix.
func knownGap(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("FIREID_CONFORMANCE_STRICT") != "" {
		t.Errorf("known gap: "+format, args...)
		return
	}
	t.Skipf("known gap (FIREID_CONFORMANCE_STRICT=1 to fail): "+format, args...)
}

// reply is one HTTP response with its body read.
type reply struct {
	status int
	header http.Header
	body   string
}

func (r reply) location(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse(r.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *oidcEnv) do(c *http.Client, req *http.Request) reply {
	e.t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return reply{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

func (e *oidcEnv) fetch(c *http.Client, path string) reply {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.abs(path), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.do(c, req)
}

// authorizeRaw sends an authorization request as is (response_type
// included) and returns the first answer, without following it.
func (e *oidcEnv) authorizeRaw(c *http.Client, params url.Values) reply {
	e.t.Helper()
	return e.fetch(c, "/authorize?"+params.Encode())
}

func (e *oidcEnv) discoveryDoc() map[string]any {
	e.t.Helper()
	r := e.fetch(http.DefaultClient, "/.well-known/openid-configuration")
	if r.status != http.StatusOK {
		e.t.Fatalf("discovery: %d", r.status)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(r.body), &doc); err != nil {
		e.t.Fatal(err)
	}
	return doc
}

// relyingClient is the client module configured for app, as an application
// on github.com/lieyanc/FireID/client would be.
func (e *oidcEnv) relyingClient(app *store.App, secret, method string) *client.Client {
	e.t.Helper()
	c, err := client.New(context.Background(), client.Config{
		Issuer: e.issuer, ClientID: app.ClientID, ClientSecret: secret,
		RedirectURL: rpCallback, AuthMethod: method,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// signedIn is a browser with alice's session.
func (e *oidcEnv) signedIn() *http.Client {
	e.t.Helper()
	c := e.browser()
	if cb := e.authorize(c, e.webParams("openid"), true); cb.Query().Get("code") == "" {
		e.t.Fatalf("sign-in: %s", cb)
	}
	return c
}

// webTokens runs the code flow for the web app and returns the token
// response, failing on anything but 200.
func (e *oidcEnv) webTokens(c *http.Client, scope string) map[string]any {
	e.t.Helper()
	cb := e.authorize(c, e.webParams(scope), true)
	resp, tok := e.exchangeWeb(cb.Query().Get("code"))
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	return tok
}

// shiftClock moves the store clock by d for the rest of the test.
func (e *oidcEnv) shiftClock(d time.Duration) {
	e.st.SetClock(func() time.Time { return time.Now().Add(d) })
	e.t.Cleanup(func() { e.st.SetClock(time.Now) })
}

// leftHalfHash is at_hash and c_hash for the SHA-256 algorithms (OIDC Core
// 3.1.3.6 and 3.3.2.11).
func leftHalfHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// jwsHeader decodes the protected header of a compact JWS without verifying.
func jwsHeader(t *testing.T, raw string) map[string]any {
	t.Helper()
	seg, _, _ := strings.Cut(raw, ".")
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// leaksInternals reports text that has no place in an error a browser or a
// client sees: stack traces, source positions, SQL and Go error chains.
func leaksInternals(s string) bool {
	l := strings.ToLower(s)
	for _, marker := range []string{"goroutine", "panic", ".go:", "runtime.", "sqlite", "sql:", "select ", "store:", "no rows"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}
