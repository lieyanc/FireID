package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestVerifyLogoutToken(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	c := newTestClient(t, fp, nil)
	ctx := context.Background()

	lt, err := c.VerifyLogoutToken(ctx, fp.logoutToken(nil))
	if err != nil {
		t.Fatal(err)
	}
	if lt.Issuer != fp.issuer || lt.Subject != "42" || lt.SID != "sess-1" || !strings.HasPrefix(lt.JTI, "jti-") ||
		!lt.IssuedAt.Equal(clk.now()) || !lt.Expiry.Equal(clk.now().Add(2*time.Minute)) || lt.Raw["sid"] != "sess-1" {
		t.Fatalf("token %+v", lt)
	}

	key := fp.current()
	sign := func(header map[string]any, over map[string]any) string {
		h := map[string]any{"typ": "logout+jwt"}
		for k, v := range header {
			h[k] = v
		}
		return key.sign(t, h, fp.logoutClaims(over))
	}
	cases := map[string]struct {
		raw  string
		want string
	}{
		"nonce present":      {fp.logoutToken(map[string]any{"nonce": "n"}), "nonce"},
		"nonce empty string": {fp.logoutToken(map[string]any{"nonce": ""}), "nonce"},
		"no events":          {fp.logoutToken(map[string]any{"events": nil}), "no events"},
		"events string":      {fp.logoutToken(map[string]any{"events": logoutEvent}), "no events"},
		"events wrong member": {
			fp.logoutToken(map[string]any{"events": map[string]any{"http://schemas.openid.net/event/other": map[string]any{}}}), "backchannel-logout member",
		},
		"event value not object": {
			fp.logoutToken(map[string]any{"events": map[string]any{logoutEvent: "yes"}}), "backchannel-logout member",
		},
		"no sub no sid":  {fp.logoutToken(map[string]any{"sub": nil, "sid": nil}), "neither sub nor sid"},
		"no jti":         {fp.logoutToken(map[string]any{"jti": nil}), "no jti"},
		"expired":        {fp.logoutToken(map[string]any{"exp": clk.now().Add(-2 * time.Minute).Unix()}), "expired"},
		"no exp":         {fp.logoutToken(map[string]any{"exp": nil}), "no exp"},
		"no iat":         {fp.logoutToken(map[string]any{"iat": nil}), "no iat"},
		"iat future":     {fp.logoutToken(map[string]any{"iat": clk.now().Add(5 * time.Minute).Unix()}), "iat"},
		"wrong aud":      {fp.logoutToken(map[string]any{"aud": "other"}), "aud"},
		"aud list azp":   {fp.logoutToken(map[string]any{"aud": []string{"app-1", "o"}, "azp": "o"}), "azp"},
		"wrong iss":      {fp.logoutToken(map[string]any{"iss": "https://evil.test"}), "iss"},
		"typ at+jwt":     {sign(map[string]any{"typ": "at+jwt"}, nil), "typ"},
		"typ id_token":   {sign(map[string]any{"typ": "id_token+jwt"}, nil), "typ"},
		"bad signature":  {tamperSegment(fp.logoutToken(nil), 1, b64.EncodeToString([]byte(`{"iss":"x"}`))), "signature"},
		"alg none":       {b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + strings.Split(fp.logoutToken(nil), ".")[1] + ".x", "none"},
		"id token as lt": {fp.idToken(nil), "no events"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.VerifyLogoutToken(ctx, tc.raw)
			if err == nil {
				t.Fatalf("accepted; want %q", tc.want)
			}
			if !errors.Is(err, ErrInvalidToken) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want ErrInvalidToken mentioning %q", err, tc.want)
			}
		})
	}

	t.Run("typ variants accepted", func(t *testing.T) {
		for _, typ := range []any{"JWT", "jwt", "application/logout+jwt", "LOGOUT+JWT", nil} {
			h := map[string]any{}
			if typ != nil {
				h["typ"] = typ
			}
			raw := key.sign(t, h, fp.logoutClaims(nil))
			if typ == nil {
				raw = key.sign(t, map[string]any{}, fp.logoutClaims(nil))
			}
			if _, err := c.VerifyLogoutToken(ctx, raw); err != nil {
				t.Errorf("typ %v: %v", typ, err)
			}
		}
	})

	t.Run("sid only", func(t *testing.T) {
		lt, err := c.VerifyLogoutToken(ctx, fp.logoutToken(map[string]any{"sub": nil}))
		if err != nil || lt.Subject != "" || lt.SID != "sess-1" {
			t.Fatalf("%+v %v", lt, err)
		}
	})

	t.Run("replay", func(t *testing.T) {
		raw := fp.logoutToken(nil)
		if _, err := c.VerifyLogoutToken(ctx, raw); err != nil {
			t.Fatal(err)
		}
		_, err := c.VerifyLogoutToken(ctx, raw)
		if !errors.Is(err, ErrInvalidToken) || !strings.Contains(err.Error(), "already used") {
			t.Fatalf("replay: %v", err)
		}
		// Once the token has expired the jti is forgotten; the token itself
		// is then refused for being expired, so nothing is lost.
		clk.advance(3 * time.Minute)
		defer clk.advance(-3 * time.Minute)
		if _, err := c.VerifyLogoutToken(ctx, raw); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expired replay: %v", err)
		}
	})

	t.Run("replay inside the skew", func(t *testing.T) {
		// Expired 30 s ago, within the minute of skew: accepted once, and
		// the jti is kept for the skew too, not only until exp.
		raw := fp.logoutToken(map[string]any{"exp": clk.now().Add(-30 * time.Second).Unix()})
		if _, err := c.VerifyLogoutToken(ctx, raw); err != nil {
			t.Fatal(err)
		}
		if _, err := c.VerifyLogoutToken(ctx, raw); err == nil || !strings.Contains(err.Error(), "already used") {
			t.Fatalf("replay inside the skew: %v", err)
		}
	})

	t.Run("claim names are exact", func(t *testing.T) {
		// NONCE is not nonce, for the typed claims as for the raw map; and
		// EVENTS is not events, so such a token is not a logout token.
		if _, err := c.VerifyLogoutToken(ctx, fp.logoutToken(map[string]any{"NONCE": "n"})); err != nil {
			t.Fatalf("NONCE: %v", err)
		}
		raw := fp.logoutToken(map[string]any{"events": nil, "EVENTS": map[string]any{logoutEvent: map[string]any{}}})
		if _, err := c.VerifyLogoutToken(ctx, raw); err == nil || !strings.Contains(err.Error(), "no events") {
			t.Fatalf("EVENTS: %v", err)
		}
	})
}

func TestJTICacheBound(t *testing.T) {
	j := newJTICache()
	now := time.Unix(1000, 0)
	for i := 0; i < jtiCacheMax; i++ {
		jti := "j" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
		if !j.remember(jti, now.Add(time.Duration(i+1)*time.Second), now) {
			t.Fatalf("duplicate at %d", i)
		}
	}
	if len(j.seen) != jtiCacheMax {
		t.Fatalf("size %d", len(j.seen))
	}
	// Full: the soonest-expiring entry makes room.
	if !j.remember("new", now.Add(time.Hour), now) {
		t.Fatal("new jti refused")
	}
	if len(j.seen) != jtiCacheMax {
		t.Fatalf("size after eviction %d", len(j.seen))
	}
	if _, ok := j.seen["jaaa"]; ok {
		t.Fatal("the soonest-expiring entry should have been evicted")
	}

	// Expired entries are swept on insert.
	j = newJTICache()
	j.remember("soon", now.Add(time.Second), now)
	j.remember("later", now.Add(time.Hour), now)
	if !j.remember("c", now.Add(2*time.Hour), now.Add(2*time.Second)) {
		t.Fatal("c refused")
	}
	if _, ok := j.seen["soon"]; ok || len(j.seen) != 2 {
		t.Fatalf("after sweep: %v", j.seen)
	}
	// A swept jti counts as new again, though such a token is expired anyway.
	if !j.remember("soon", now.Add(time.Hour), now.Add(2*time.Second)) {
		t.Fatal("swept jti still remembered")
	}
	// A far-away exp is capped.
	j.remember("far", now.Add(1000*time.Hour), now)
	if until := j.seen["far"]; !until.Equal(now.Add(jtiMaxRemember)) {
		t.Fatalf("far remembered until %v", until)
	}
	j.forget("far")
	if _, ok := j.seen["far"]; ok {
		t.Fatal("forget")
	}
}

func TestBackchannelLogoutHandler(t *testing.T) {
	clk := newClock()
	fp := newFakeProvider(t, clk)
	c := newTestClient(t, fp, nil)

	var got []*LogoutToken
	var fail bool
	h := c.BackchannelLogoutHandler(func(ctx context.Context, lt *LogoutToken) error {
		got = append(got, lt)
		if fail {
			return errors.New("db down")
		}
		return nil
	})
	post := func(t *testing.T, contentType, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/backchannel", strings.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Error("answer must carry Cache-Control: no-store")
		}
		return rec
	}
	form := func(token string) string {
		return url.Values{"logout_token": {token}}.Encode()
	}

	rec := post(t, "application/x-www-form-urlencoded", form(fp.logoutToken(nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: %d %s", rec.Code, rec.Body)
	}
	if len(got) != 1 || got[0].SID != "sess-1" {
		t.Fatalf("onLogout saw %+v", got)
	}

	rec = post(t, "application/x-www-form-urlencoded; charset=utf-8", form(fp.logoutToken(map[string]any{"nonce": "n"})))
	if rec.Code != http.StatusBadRequest || strings.TrimSpace(rec.Body.String()) != `{"error":"invalid_request"}` ||
		rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("invalid token: %d %s", rec.Code, rec.Body)
	}
	if rec := post(t, "application/x-www-form-urlencoded", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := post(t, "application/json", `{"logout_token":"x"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("json body: %d", rec.Code)
	}
	if rec := post(t, "application/x-www-form-urlencoded", form(strings.Repeat("a", maxLogoutBody+1))); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/backchannel", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
		t.Fatalf("GET: %d", rec.Code)
	}

	// An onLogout failure is 500 and leaves the jti usable for the retry.
	raw := fp.logoutToken(nil)
	fail = true
	if rec := post(t, "application/x-www-form-urlencoded", form(raw)); rec.Code != http.StatusInternalServerError {
		t.Fatalf("onLogout failure: %d", rec.Code)
	}
	fail = false
	if rec := post(t, "application/x-www-form-urlencoded", form(raw)); rec.Code != http.StatusOK {
		t.Fatalf("retry after failure: %d %s", rec.Code, rec.Body)
	}
	// Now it has been used.
	if rec := post(t, "application/x-www-form-urlencoded", form(raw)); rec.Code != http.StatusBadRequest {
		t.Fatalf("replay: %d", rec.Code)
	}
	if len(got) != 3 {
		t.Fatalf("onLogout calls %d", len(got))
	}

	// Over the wire, through a real server, as the provider would do it.
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/x-www-form-urlencoded", strings.NewReader(form(fp.logoutToken(nil))))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("over the wire: %d", resp.StatusCode)
	}
}
