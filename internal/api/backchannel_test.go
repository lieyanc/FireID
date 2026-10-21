package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/lieyanc/FireID/internal/config"
	"github.com/lieyanc/FireID/internal/oidc"
	"github.com/lieyanc/FireID/internal/secretbox"
	"github.com/lieyanc/FireID/internal/store"
)

// backchannelWorker builds the worker main.go runs, from the same data
// directory as the environment's store (its config file sits beside it).
func backchannelWorker(t *testing.T, e *oidcEnv) *oidc.Backchannel {
	t.Helper()
	cfgStore, _, err := config.Open(filepath.Join(filepath.Dir(e.st.DataDir()), "config.json"))
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
	return oidc.NewBackchannel(e.st, box, e.issuer, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// logoutReceiver is a relying party's back-channel endpoint.
type logoutReceiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	tokens []string
}

func newLogoutReceiver(t *testing.T) *logoutReceiver {
	t.Helper()
	rp := &logoutReceiver{}
	rp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rp.mu.Lock()
		defer rp.mu.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != "/backchannel" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		rp.tokens = append(rp.tokens, r.FormValue("logout_token"))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(rp.srv.Close)
	return rp
}

func (rp *logoutReceiver) received() []string {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return append([]string(nil), rp.tokens...)
}

// typHeader returns the typ header of a compact JWS.
func typHeader(t *testing.T, raw string) string {
	t.Helper()
	sig, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	typ, _ := sig.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	return typ
}

func TestBackchannelLogout(t *testing.T) {
	e := newOIDCEnv(t)
	rp := newLogoutReceiver(t)
	uri := rp.srv.URL + "/backchannel"
	if err := e.st.UpdateApp(e.web.ID, store.AppUpdate{BackchannelLogoutURI: &uri}); err != nil {
		t.Fatal(err)
	}

	t.Run("discovery advertises it", func(t *testing.T) {
		resp, err := http.Get(e.issuer + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if doc["backchannel_logout_supported"] != true || doc["backchannel_logout_session_supported"] != true {
			t.Fatalf("discovery: %v %v", doc["backchannel_logout_supported"], doc["backchannel_logout_session_supported"])
		}
		found := false
		for _, c := range doc["claims_supported"].([]any) {
			found = found || c == "sid"
		}
		if !found {
			t.Fatalf("claims_supported lacks sid: %v", doc["claims_supported"])
		}
	})

	c := e.browser()
	cb := e.authorize(c, e.webParams("openid profile offline_access"), true)
	resp, tok := e.exchangeWeb(cb.Query().Get("code"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	claims := e.verifyIDToken(tok["id_token"].(string))
	sid, _ := claims["sid"].(string)
	if sid == "" {
		t.Fatalf("id_token without sid: %v", claims)
	}
	if typ := typHeader(t, tok["id_token"].(string)); typ != "JWT" {
		t.Fatalf("id_token typ %q", typ)
	}
	if status, info := e.userinfo(tok["access_token"].(string)); status != http.StatusOK || info["sid"] != nil {
		t.Fatalf("userinfo: %d %v", status, info)
	}

	t.Run("refresh keeps the sid", func(t *testing.T) {
		resp, next := e.postForm(http.DefaultClient, "/oauth/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)},
			"client_id": {e.web.ClientID}, "client_secret": {e.webSecret},
		}, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh: %d %v", resp.StatusCode, next)
		}
		if got := e.verifyIDToken(next["id_token"].(string))["sid"]; got != sid {
			t.Fatalf("refreshed id_token sid %v, want %s", got, sid)
		}
	})

	// A second browser session to the same app: signing one out must only
	// name that session.
	other := e.browser()
	otherCB := e.authorize(other, e.webParams("openid"), true)
	_, otherTok := e.exchangeWeb(otherCB.Query().Get("code"))
	otherSID := e.verifyIDToken(otherTok["id_token"].(string))["sid"]
	if otherSID == sid {
		t.Fatal("two sessions share a sid")
	}

	if status, _ := e.postJSON(c, "/api/auth/logout", map[string]any{}); status != http.StatusNoContent {
		t.Fatalf("logout: %d", status)
	}
	if n, _ := e.st.PendingBackchannel(e.web.ID); n != 1 {
		t.Fatalf("pending notifications %d, want 1", n)
	}

	backchannelWorker(t, e).Flush(context.Background())
	got := rp.received()
	if len(got) != 1 {
		t.Fatalf("relying party received %d logout tokens, want 1", len(got))
	}
	if n, _ := e.st.PendingBackchannel(e.web.ID); n != 0 {
		t.Fatalf("pending after delivery %d", n)
	}
	if typ := typHeader(t, got[0]); typ != "logout+jwt" {
		t.Fatalf("logout token typ %q", typ)
	}
	lt := e.verifyIDToken(got[0]) // same key set, same check
	if lt["iss"] != e.issuer || lt["sub"] != strconv.FormatInt(e.user.ID, 10) || lt["sid"] != sid ||
		!audContains(lt, e.web.ClientID) {
		t.Fatalf("logout token claims %v", lt)
	}
	if _, ok := lt["events"].(map[string]any)["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("logout token events %v", lt["events"])
	}
	if lt["jti"] == nil || lt["nonce"] != nil {
		t.Fatalf("logout token jti/nonce %v", lt)
	}

	// The other session is still signed in and was not notified.
	if resp := e.get(other, "/api/auth/me"); resp.StatusCode != http.StatusOK {
		t.Fatalf("other session: %d", resp.StatusCode)
	}
}

func TestOIDCAuditEvents(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.browser()

	t.Run("access denied", func(t *testing.T) {
		params := url.Values{"client_id": {e.closed.ClientID}, "redirect_uri": {rpCallback}, "scope": {"openid"}}
		if loc := e.authorize(c, params, true); loc.Query().Get("error") != "access_denied" {
			t.Fatalf("expected access_denied, got %s", loc)
		}
		entries, err := e.st.ListAudit(store.AuditQuery{Event: "oauth.access_denied"})
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].AppID != e.closed.ID || entries[0].UserID != e.user.ID ||
			entries[0].Severity != store.SeverityWarning || entries[0].Detail["reason"] == nil {
			t.Fatalf("audit entries %+v", entries)
		}
	})

	t.Run("refresh replay", func(t *testing.T) {
		cb := e.authorize(c, e.webParams("openid offline_access"), false)
		_, tok := e.exchangeWeb(cb.Query().Get("code"))
		refresh := func(rt string) *http.Response {
			resp, _ := e.postForm(http.DefaultClient, "/oauth/token", url.Values{
				"grant_type": {"refresh_token"}, "refresh_token": {rt},
				"client_id": {e.web.ClientID}, "client_secret": {e.webSecret},
			}, "", "")
			return resp
		}
		first := tok["refresh_token"].(string)
		if resp := refresh(first); resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh: %d", resp.StatusCode)
		}
		if resp := refresh(first); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("replay: %d", resp.StatusCode)
		}
		entries, err := e.st.ListAudit(store.AuditQuery{Event: "oauth.refresh_replay"})
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].AppID != e.web.ID || entries[0].UserID != e.user.ID ||
			entries[0].Severity != store.SeverityCritical || entries[0].ActorType != store.ActorClient {
			t.Fatalf("audit entries %+v", entries)
		}
	})

	t.Run("rp logout", func(t *testing.T) {
		cb := e.authorize(c, e.webParams("openid"), false)
		_, tok := e.exchangeWeb(cb.Query().Get("code"))
		q := url.Values{"id_token_hint": {tok["id_token"].(string)}}
		if resp := e.get(c, "/end_session?"+q.Encode()); resp.StatusCode != http.StatusFound {
			t.Fatalf("end_session: %d", resp.StatusCode)
		}
		entries, err := e.st.ListAudit(store.AuditQuery{Event: "auth.sign_out"})
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("audit entries %+v", entries)
		}
		got := entries[0]
		if got.ActorType != store.ActorUser || got.ActorUserID != e.user.ID || got.UserID != e.user.ID ||
			got.AppID != e.web.ID || got.Detail["via"] != "rp_logout" || got.UserAgent == "" {
			t.Fatalf("audit entry %+v", got)
		}
	})
}
