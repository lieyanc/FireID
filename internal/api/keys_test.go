package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// jwksKIDs returns the key IDs /keys publishes.
func (e *oidcEnv) jwksKIDs() []string {
	e.t.Helper()
	resp, err := http.Get(e.issuer + "/keys")
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.KeyID)
	}
	return out
}

// signingKeys returns the admin list as kid → entry, and the kids in order.
func (e *oidcEnv) signingKeys(c *http.Client) (map[string]map[string]any, []string) {
	e.t.Helper()
	st, body := e.send(c, http.MethodGet, "/api/admin/signing-keys", nil)
	wantStatus(e.t, "list keys", st, http.StatusOK, body)
	byKID := map[string]map[string]any{}
	var order []string
	for _, x := range body["keys"].([]any) {
		k := x.(map[string]any)
		if k["privateKeyEnc"] != nil || k["publicJwk"] != nil {
			e.t.Fatalf("key material in the list: %v", k)
		}
		byKID[k["kid"].(string)] = k
		order = append(order, k["kid"].(string))
	}
	return byKID, order
}

func TestSigningKeysRequireSuperAdmin(t *testing.T) {
	e := newAdminEnv(t)
	for _, c := range []*http.Client{e.alice, e.bobC} {
		st, body := e.send(c, http.MethodGet, "/api/admin/signing-keys", nil)
		wantError(t, "list", st, http.StatusForbidden, body, "forbidden")
		st, body = e.send(c, http.MethodPost, "/api/admin/signing-keys/rotate", map[string]any{})
		wantError(t, "rotate", st, http.StatusForbidden, body, "forbidden")
		st, body = e.send(c, http.MethodPost, "/api/admin/signing-keys/whatever/retire", map[string]any{})
		wantError(t, "retire", st, http.StatusForbidden, body, "forbidden")
	}
}

func TestSigningKeyRotation(t *testing.T) {
	e := newAdminEnv(t)
	keys, order := e.signingKeys(e.root)
	if len(order) != 1 || keys[order[0]]["current"] != true || keys[order[0]]["retiredAt"] != nil {
		t.Fatalf("initial keys %v", keys)
	}
	old := order[0]

	st, body := e.send(e.root, http.MethodPost, "/api/admin/signing-keys/rotate", map[string]any{})
	wantStatus(t, "rotate", st, http.StatusCreated, body)
	kid, _ := body["kid"].(string)
	if kid == "" || kid == old {
		t.Fatalf("rotate answered %v", body)
	}
	keys, order = e.signingKeys(e.root)
	if len(order) != 2 || order[0] != kid || keys[kid]["current"] != true || keys[old]["current"] != false ||
		keys[old]["retiredAt"] != nil || keys[kid]["alg"] == "" || keys[kid]["activatedAt"] == "" {
		t.Fatalf("keys after rotation %v", keys)
	}
	if got := strings.Join(e.jwksKIDs(), " "); !strings.Contains(got, kid) || !strings.Contains(got, old) {
		t.Fatalf("JWKS after rotation %q, want %s and %s", got, kid, old)
	}

	// New ID tokens are signed with the new key.
	cb := e.authorize(e.browser(), e.webParams("openid"), true)
	resp, tok := e.exchangeWeb(cb.Query().Get("code"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	sig, err := jose.ParseSigned(tok["id_token"].(string), []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	if got := sig.Signatures[0].Header.KeyID; got != kid {
		t.Fatalf("id_token signed with %s, want %s", got, kid)
	}
	e.verifyIDToken(tok["id_token"].(string))

	st, body = e.send(e.root, http.MethodPost, "/api/admin/signing-keys/"+kid+"/retire", map[string]any{})
	wantError(t, "retire current", st, http.StatusBadRequest, body, "invalid")
	st, body = e.send(e.root, http.MethodPost, "/api/admin/signing-keys/nope/retire", map[string]any{})
	wantError(t, "retire unknown", st, http.StatusNotFound, body, "not_found")
	st, body = e.send(e.root, http.MethodPost, "/api/admin/signing-keys/"+old+"/retire", map[string]any{})
	wantStatus(t, "retire old", st, http.StatusNoContent, body)

	if got := e.jwksKIDs(); len(got) != 1 || got[0] != kid {
		t.Fatalf("JWKS after retiring %v", got)
	}
	keys, _ = e.signingKeys(e.root)
	if keys[old]["retiredAt"] == nil || keys[kid]["retiredAt"] != nil {
		t.Fatalf("keys after retiring %v", keys)
	}

	entries, _ := e.auditPage(e.root, "/api/admin/audit?event=key.")
	if len(entries) != 2 || entries[0]["event"] != "key.retire" || entries[1]["event"] != "key.rotate" ||
		entries[0]["detail"].(map[string]any)["kid"] != old || entries[1]["detail"].(map[string]any)["kid"] != kid ||
		entries[0]["severity"] != "warning" || refID(entries[0]["actor"]) != e.oidcEnv.root.ID {
		t.Fatalf("key audit entries %v", entries)
	}
}
