package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/store"
)

// fakeMailer records messages instead of sending them.
type fakeMailer struct {
	mu      sync.Mutex
	enabled bool
	sent    []sentMail
}

type sentMail struct{ to, subject, body string }

func (m *fakeMailer) Enabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

func (m *fakeMailer) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMail{to, subject, body})
	return nil
}

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

var (
	mailCode  = regexp.MustCompile(`(?m)^\s+(\d{6})$`)
	mailToken = regexp.MustCompile(`/email-login#(\S+)`)
)

// lastMail waits for deliveries and returns the newest message's code and
// link fragment.
func (e *oidcEnv) lastMail() (to, code string, fragment url.Values) {
	e.t.Helper()
	e.auth.WaitForMail()
	e.mailer.mu.Lock()
	defer e.mailer.mu.Unlock()
	if len(e.mailer.sent) == 0 {
		e.t.Fatal("no email was sent")
	}
	m := e.mailer.sent[len(e.mailer.sent)-1]
	c := mailCode.FindStringSubmatch(m.body)
	l := mailToken.FindStringSubmatch(m.body)
	if c == nil || l == nil {
		e.t.Fatalf("email without code or link:\n%s", m.body)
	}
	frag, err := url.ParseQuery(l[1])
	if err != nil {
		e.t.Fatal(err)
	}
	return m.to, c[1], frag
}

// lastNotice waits for deliveries and returns the newest message.
func (e *oidcEnv) lastNotice() (to, subject, body string) {
	e.t.Helper()
	e.auth.WaitForMail()
	e.mailer.mu.Lock()
	defer e.mailer.mu.Unlock()
	if len(e.mailer.sent) == 0 {
		return "", "", ""
	}
	m := e.mailer.sent[len(e.mailer.sent)-1]
	return m.to, m.subject, m.body
}

// postJSON sends a JSON body as the UI would.
func (e *oidcEnv) postJSON(c *http.Client, path string, body any) (int, map[string]any) {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, e.abs(path), strings.NewReader(string(raw)))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (e *oidcEnv) me(c *http.Client) map[string]any {
	e.t.Helper()
	resp, err := c.Get(e.abs("/api/auth/me"))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("me: status %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// totpAt computes the RFC 6238 code for a step, independently of the code
// under test.
func totpAt(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

func nowStep() int64 { return time.Now().Unix() / 30 }

func wantStatus(t *testing.T, what string, got, want int, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status %d, want %d (%v)", what, got, want, body)
	}
}

func wantError(t *testing.T, what string, got, want int, body map[string]any, code string) {
	t.Helper()
	wantStatus(t, what, got, want, body)
	if body["error"] != code {
		t.Fatalf("%s: error %v, want %q", what, body["error"], code)
	}
}

func stringList(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// enrolTOTP turns TOTP on for the signed-in browser and returns the secret,
// the recovery codes and the step of the code that confirmed it.
func (e *oidcEnv) enrolTOTP(c *http.Client) (secret string, recovery []string, step int64) {
	e.t.Helper()
	st, body := e.postJSON(c, "/api/account/totp/enrol", map[string]any{"password": testPassword})
	wantStatus(e.t, "enrol", st, http.StatusOK, body)
	secret, _ = body["secret"].(string)
	if uri, _ := body["uri"].(string); !strings.HasPrefix(uri, "otpauth://totp/127.0.0.1:alice?") || !strings.Contains(uri, secret) {
		e.t.Fatalf("enrol uri %q", uri)
	}
	step = nowStep()
	st, body = e.postJSON(c, "/api/account/totp/confirm", map[string]any{"code": totpAt(e.t, secret, step)})
	wantStatus(e.t, "confirm", st, http.StatusOK, body)
	recovery = stringList(body["recoveryCodes"])
	if len(recovery) != auth.RecoveryCodeCount {
		e.t.Fatalf("got %d recovery codes", len(recovery))
	}
	return secret, recovery, step
}

func (e *oidcEnv) passwordSignIn(c *http.Client, username string) map[string]any {
	e.t.Helper()
	st, body := e.postJSON(c, "/api/auth/login", map[string]any{"username": username, "password": testPassword})
	wantStatus(e.t, "login", st, http.StatusOK, body)
	return body
}

func TestTOTPSignIn(t *testing.T) {
	e := newOIDCEnv(t)
	owner := e.browser()
	e.passwordSignIn(owner, "alice")

	t.Run("enrolment needs the password", func(t *testing.T) {
		st, body := e.postJSON(owner, "/api/account/totp/enrol", map[string]any{"password": "wrong password!"})
		wantError(t, "enrol", st, http.StatusUnauthorized, body, "invalid_credentials")
	})

	secret, recovery, enrolStep := e.enrolTOTP(owner)
	if to, _, _ := e.lastNotice(); to != "alice@example.com" {
		t.Fatalf("no security notice for turning TOTP on (sent to %q)", to)
	}
	if me := e.me(owner); me["recoveryCodesLeft"] != float64(auth.RecoveryCodeCount) {
		t.Fatalf("recoveryCodesLeft = %v", me["recoveryCodesLeft"])
	}

	t.Run("enrolling twice is refused", func(t *testing.T) {
		st, body := e.postJSON(owner, "/api/account/totp/enrol", map[string]any{"password": testPassword})
		wantError(t, "re-enrol", st, http.StatusConflict, body, "totp_enabled")
	})

	t.Run("password alone is a challenge", func(t *testing.T) {
		body := e.passwordSignIn(e.browser(), "alice")
		if body["challenge"] != "totp" || body["user"] != nil {
			t.Fatalf("got %v", body)
		}
	})

	t.Run("the code used for enrolment cannot sign in", func(t *testing.T) {
		st, body := e.postJSON(e.browser(), "/api/auth/login/totp", map[string]any{
			"username": "alice", "password": testPassword, "code": totpAt(t, secret, enrolStep)})
		wantError(t, "replay", st, http.StatusUnauthorized, body, "invalid_code")
	})

	t.Run("a fresh code signs in at loa:2, once", func(t *testing.T) {
		c := e.browser()
		code := totpAt(t, secret, enrolStep+1)
		st, body := e.postJSON(c, "/api/auth/login/totp", map[string]any{
			"username": "alice", "password": testPassword, "code": code})
		wantStatus(t, "totp", st, http.StatusOK, body)
		me := e.me(c)
		if me["acr"] != store.ACRLoA2 || strings.Join(stringList(me["amr"]), " ") != "pwd otp" {
			t.Fatalf("session acr=%v amr=%v", me["acr"], me["amr"])
		}
		st, body = e.postJSON(e.browser(), "/api/auth/login/totp", map[string]any{
			"username": "alice", "password": testPassword, "code": code})
		wantError(t, "same code again", st, http.StatusUnauthorized, body, "invalid_code")
	})

	t.Run("the code does not replace the password", func(t *testing.T) {
		st, body := e.postJSON(e.browser(), "/api/auth/login/totp", map[string]any{
			"username": "alice", "password": "wrong password!", "code": totpAt(t, secret, enrolStep+2)})
		wantError(t, "wrong password", st, http.StatusUnauthorized, body, "invalid_credentials")
	})

	t.Run("a recovery code works once, in any case and without the dash", func(t *testing.T) {
		code := strings.ToUpper(strings.ReplaceAll(recovery[0], "-", ""))
		st, body := e.postJSON(e.browser(), "/api/auth/login/totp", map[string]any{
			"username": "alice", "password": testPassword, "code": code})
		wantStatus(t, "recovery", st, http.StatusOK, body)
		st, body = e.postJSON(e.browser(), "/api/auth/login/totp", map[string]any{
			"username": "alice", "password": testPassword, "code": recovery[0]})
		wantError(t, "recovery again", st, http.StatusUnauthorized, body, "invalid_code")
		if me := e.me(owner); me["recoveryCodesLeft"] != float64(auth.RecoveryCodeCount-1) {
			t.Fatalf("recoveryCodesLeft = %v", me["recoveryCodesLeft"])
		}
	})

	t.Run("regenerating replaces the old codes", func(t *testing.T) {
		st, body := e.postJSON(owner, "/api/account/recovery-codes", map[string]any{"code": recovery[1]})
		wantStatus(t, "regenerate", st, http.StatusOK, body)
		fresh := stringList(body["recoveryCodes"])
		st, body = e.postJSON(e.browser(), "/api/auth/login/totp", map[string]any{
			"username": "alice", "password": testPassword, "code": recovery[2]})
		wantError(t, "old code", st, http.StatusUnauthorized, body, "invalid_code")
		recovery = fresh
	})

	t.Run("turning it off needs a code", func(t *testing.T) {
		st, body := e.postJSON(owner, "/api/account/totp/disable", map[string]any{"code": "000000"})
		wantError(t, "disable", st, http.StatusUnauthorized, body, "invalid_code")
		st, body = e.postJSON(owner, "/api/account/totp/disable", map[string]any{"code": recovery[0]})
		wantStatus(t, "disable", st, http.StatusNoContent, body)
		if body := e.passwordSignIn(e.browser(), "alice"); body["user"] == nil {
			t.Fatalf("password sign-in after disabling: %v", body)
		}
	})
}

func TestAdminMustEnrol(t *testing.T) {
	e := newEnvWith(t, func(c *auth.Config) { c.RequireSecondFactorForAdmins = true })
	login := map[string]any{"username": "root", "password": testPassword}

	if body := e.passwordSignIn(e.browser(), "root"); body["challenge"] != "totp_enrol" {
		t.Fatalf("got %v", body)
	}
	st, body := e.postJSON(e.browser(), "/api/auth/login/totp/enrol", login)
	wantStatus(t, "enrol", st, http.StatusOK, body)
	secret, _ := body["secret"].(string)

	t.Run("a started enrolment does not unlock the password", func(t *testing.T) {
		if body := e.passwordSignIn(e.browser(), "root"); body["challenge"] != "totp_enrol" {
			t.Fatalf("got %v", body)
		}
	})

	t.Run("enrolment without the password is refused", func(t *testing.T) {
		st, body := e.postJSON(e.browser(), "/api/auth/login/totp/enrol",
			map[string]any{"username": "root", "password": "wrong password!"})
		wantError(t, "enrol", st, http.StatusUnauthorized, body, "invalid_credentials")
	})

	c := e.browser()
	st, body = e.postJSON(c, "/api/auth/login/totp", map[string]any{
		"username": "root", "password": testPassword, "code": totpAt(t, secret, nowStep())})
	wantStatus(t, "first code", st, http.StatusOK, body)
	if n := len(stringList(body["recoveryCodes"])); n != auth.RecoveryCodeCount {
		t.Fatalf("sign-in that enrolled returned %d recovery codes", n)
	}
	if body["user"] == nil {
		t.Fatalf("not signed in: %v", body)
	}

	t.Run("policy keeps it on", func(t *testing.T) {
		st, body := e.postJSON(c, "/api/account/totp/disable", map[string]any{"code": totpAt(t, secret, nowStep()+1)})
		wantError(t, "disable", st, http.StatusForbidden, body, "forbidden")
	})

	t.Run("email cannot skip enrolment", func(t *testing.T) {
		ee := newEnvWith(t, func(c *auth.Config) { c.RequireSecondFactorForAdmins = true })
		st, body := ee.postJSON(ee.browser(), "/api/auth/email/start", map[string]any{"email": "root@example.com"})
		wantStatus(t, "start", st, http.StatusAccepted, body)
		_, code, _ := ee.lastMail()
		st, body = ee.postJSON(ee.browser(), "/api/auth/email/verify", map[string]any{
			"email": "root@example.com", "code": code})
		wantError(t, "verify", st, http.StatusForbidden, body, "totp_enrol_required")
	})
}

func TestEmailSignIn(t *testing.T) {
	t.Run("code signs in and verifies the address", func(t *testing.T) {
		e := newOIDCEnv(t)
		if err := e.st.SetStatus(e.user.ID, store.UserPending); err != nil {
			t.Fatal(err)
		}
		st, body := e.postJSON(e.browser(), "/api/auth/email/start",
			map[string]any{"email": "Alice@Example.com", "lang": "zh"})
		wantStatus(t, "start", st, http.StatusAccepted, body)
		to, code, _ := e.lastMail()
		if to != "alice@example.com" {
			t.Fatalf("sent to %q", to)
		}
		if subj := e.mailer.sent[0].subject; !strings.Contains(subj, "登录") {
			t.Fatalf("lang=zh gave subject %q", subj)
		}
		c := e.browser()
		st, body = e.postJSON(c, "/api/auth/email/verify", map[string]any{"email": "alice@example.com", "code": code})
		wantStatus(t, "verify", st, http.StatusOK, body)
		me := e.me(c)
		user, _ := me["user"].(map[string]any)
		if user["status"] != store.UserActive || strings.Join(stringList(me["amr"]), " ") != "email" {
			t.Fatalf("after email sign-in: %v", me)
		}
		st, body = e.postJSON(e.browser(), "/api/auth/email/verify", map[string]any{"email": "alice@example.com", "code": code})
		wantError(t, "reuse", st, http.StatusUnauthorized, body, "invalid_code")
	})

	t.Run("unknown and known addresses look the same", func(t *testing.T) {
		e := newOIDCEnv(t)
		st, body := e.postJSON(e.browser(), "/api/auth/email/start", map[string]any{"email": "nobody@example.com"})
		wantStatus(t, "start", st, http.StatusAccepted, body)
		e.auth.WaitForMail()
		if n := e.mailer.count(); n != 0 {
			t.Fatalf("sent %d messages to an unknown address", n)
		}
	})

	t.Run("five wrong codes spend the token", func(t *testing.T) {
		e := newOIDCEnv(t)
		e.postJSON(e.browser(), "/api/auth/email/start", map[string]any{"email": "alice@example.com"})
		_, code, _ := e.lastMail()
		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		for i := range store.MaxCodeAttempts {
			st, body := e.postJSON(e.browser(), "/api/auth/email/verify", map[string]any{"email": "alice@example.com", "code": wrong})
			wantError(t, fmt.Sprintf("guess %d", i), st, http.StatusUnauthorized, body, "invalid_code")
		}
		st, body := e.postJSON(e.browser(), "/api/auth/email/verify", map[string]any{"email": "alice@example.com", "code": code})
		wantError(t, "right code after the limit", st, http.StatusUnauthorized, body, "invalid_code")
	})

	t.Run("a new email spends the previous one", func(t *testing.T) {
		e := newOIDCEnv(t)
		e.postJSON(e.browser(), "/api/auth/email/start", map[string]any{"email": "alice@example.com"})
		_, _, first := e.lastMail()
		e.postJSON(e.browser(), "/api/auth/email/start", map[string]any{"email": "alice@example.com"})
		_, _, second := e.lastMail()
		st, body := e.postJSON(e.browser(), "/api/auth/email/verify", map[string]any{"token": first.Get("token")})
		wantError(t, "old link", st, http.StatusUnauthorized, body, "invalid_code")
		st, body = e.postJSON(e.browser(), "/api/auth/email/verify", map[string]any{"token": second.Get("token")})
		wantStatus(t, "new link", st, http.StatusOK, body)
	})

	t.Run("sending is rate limited per address", func(t *testing.T) {
		e := newOIDCEnv(t)
		var st int
		var body map[string]any
		for range 4 {
			st, body = e.postJSON(e.browser(), "/api/auth/email/start", map[string]any{"email": "alice@example.com"})
		}
		wantError(t, "fourth email", st, http.StatusTooManyRequests, body, "rate_limited")
	})

	t.Run("TOTP accounts need their code too", func(t *testing.T) {
		e := newOIDCEnv(t)
		owner := e.browser()
		e.passwordSignIn(owner, "alice")
		secret, _, step := e.enrolTOTP(owner)

		e.postJSON(e.browser(), "/api/auth/email/start", map[string]any{"email": "alice@example.com"})
		_, _, frag := e.lastMail()
		proof := map[string]any{"token": frag.Get("token")}
		st, body := e.postJSON(e.browser(), "/api/auth/email/verify", proof)
		wantStatus(t, "link alone", st, http.StatusOK, body)
		if body["challenge"] != "totp" {
			t.Fatalf("link alone: %v", body)
		}
		proof["totp"] = totpAt(t, secret, step+1)
		c := e.browser()
		st, body = e.postJSON(c, "/api/auth/email/verify", proof)
		wantStatus(t, "link and code", st, http.StatusOK, body)
		if me := e.me(c); me["acr"] != store.ACRLoA2 {
			t.Fatalf("acr %v", me["acr"])
		}
	})

	t.Run("a pending account still needs its second factor", func(t *testing.T) {
		e := newOIDCEnv(t)
		owner := e.browser()
		e.passwordSignIn(owner, "alice")
		secret, _, step := e.enrolTOTP(owner)
		if err := e.st.SetStatus(e.user.ID, store.UserPending); err != nil {
			t.Fatal(err)
		}
		e.postJSON(e.browser(), "/api/auth/email/start", map[string]any{"email": "alice@example.com"})
		_, code, _ := e.lastMail()
		proof := map[string]any{"email": "alice@example.com", "code": code}
		st, body := e.postJSON(e.browser(), "/api/auth/email/verify", proof)
		wantStatus(t, "code alone", st, http.StatusOK, body)
		if body["challenge"] != "totp" {
			t.Fatalf("pending account signed in without TOTP: %v", body)
		}
		proof["totp"] = totpAt(t, secret, step+1)
		c := e.browser()
		st, body = e.postJSON(c, "/api/auth/email/verify", proof)
		wantStatus(t, "code and totp", st, http.StatusOK, body)
		me := e.me(c)
		if me["acr"] != store.ACRLoA2 || strings.Join(stringList(me["amr"]), " ") != "email otp" {
			t.Fatalf("acr=%v amr=%v", me["acr"], me["amr"])
		}
	})

	t.Run("a sign-in started by an app returns to it", func(t *testing.T) {
		e := newOIDCEnv(t)
		c := e.browser()
		params := e.webParams("openid")
		params.Set("response_type", "code")
		loc := location(t, e.get(c, "/authorize?"+params.Encode()), http.StatusFound)
		authReqID := loc.Query().Get("auth_req_id")

		e.postJSON(c, "/api/auth/email/start", map[string]any{"email": "alice@example.com", "authReqId": authReqID})
		_, _, frag := e.lastMail()
		if frag.Get("auth_req_id") != authReqID {
			t.Fatalf("link carries auth_req_id %q, want %q", frag.Get("auth_req_id"), authReqID)
		}
		st, body := e.postJSON(c, "/api/auth/email/verify", map[string]any{
			"token": frag.Get("token"), "authReqId": frag.Get("auth_req_id")})
		wantStatus(t, "verify", st, http.StatusOK, body)
		next, _ := body["redirectTo"].(string)
		cb := location(t, e.get(c, next), http.StatusFound)
		if cb.Query().Get("code") == "" || cb.Query().Get("state") != "st-1" {
			t.Fatalf("callback %s", cb)
		}
	})

	t.Run("unavailable without SMTP", func(t *testing.T) {
		e := newOIDCEnv(t)
		e.mailer.mu.Lock()
		e.mailer.enabled = false
		e.mailer.mu.Unlock()
		st, body := e.postJSON(e.browser(), "/api/auth/email/start", map[string]any{"email": "alice@example.com"})
		wantError(t, "start", st, http.StatusNotFound, body, "email_unavailable")
		resp, err := http.Get(e.issuer + "/api/setup")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var state map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&state)
		if state["emailLogin"] != false {
			t.Fatalf("setup state %v", state)
		}
	})
}

func TestAccountEndpointsRejectCrossSite(t *testing.T) {
	e := newOIDCEnv(t)
	c := e.browser()
	e.passwordSignIn(c, "alice")
	req, _ := http.NewRequest(http.MethodPost, e.issuer+"/api/account/totp/enrol",
		strings.NewReader(`{"password":"`+testPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site enrol: status %d", resp.StatusCode)
	}
}

func TestClientIP(t *testing.T) {
	for _, tc := range []struct {
		name  string
		trust bool
		xff   string
		want  string
	}{
		{"untrusted header is ignored", false, "203.0.113.9", "192.0.2.1"},
		{"trusted proxy's entry", true, "203.0.113.9", "203.0.113.9"},
		{"client-supplied prefix is ignored", true, "198.51.100.7, 203.0.113.9", "203.0.113.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{deps: Deps{TrustProxyHeaders: tc.trust, Log: slog.New(slog.DiscardHandler)}}
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "192.0.2.1:5000"
			r.Header.Set("X-Forwarded-For", tc.xff)
			if got := s.clientIP(r); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}
