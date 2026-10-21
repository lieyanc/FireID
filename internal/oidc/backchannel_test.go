package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/lieyanc/FireID/internal/secretbox"
	"github.com/lieyanc/FireID/internal/store"
)

// bcFixture is a store with a signing key, one user, one app and a worker,
// on an adjustable clock.
type bcFixture struct {
	t       *testing.T
	st      *store.Store
	storage *Storage
	now     time.Time
	user    *store.User
	app     *store.App
	w       *Backchannel
}

const testIssuer = "https://id.example"

func newBCFixture(t *testing.T) *bcFixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := &bcFixture{t: t, st: st, now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	st.SetClock(func() time.Time { return f.now })

	box, err := secretbox.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.storage = NewStorage(st, box, Settings{SigningAlgorithm: "ES256"})
	if err := f.storage.EnsureSigningKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.user, err = st.CreateUser(store.NewUser{Username: "alice", Email: "alice@example.com", Status: store.UserActive})
	if err != nil {
		t.Fatal(err)
	}
	f.app, _, err = st.CreateApp(store.NewApp{Slug: "rp", Name: "RP", OwnerUserID: f.user.ID,
		RedirectURIs: []string{"https://rp.example/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	f.w = NewBackchannel(st, box, testIssuer+"/", slog.New(slog.NewTextHandler(io.Discard, nil)))
	return f
}

func (f *bcFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func (f *bcFixture) setURI(uri string) {
	f.t.Helper()
	if err := f.st.UpdateApp(f.app.ID, store.AppUpdate{BackchannelLogoutURI: &uri}); err != nil {
		f.t.Fatal(err)
	}
}

// endSession signs in to the app and signs out again, which queues one
// notification.
func (f *bcFixture) endSession() *store.Session {
	f.t.Helper()
	_, sess, err := f.st.CreateSession(f.user.ID, time.Hour, "", "", "pwd", store.ACRLoA1)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.st.RecordSessionApp(sess.ID, f.app.ID); err != nil {
		f.t.Fatal(err)
	}
	if err := f.st.RevokeSession(sess.ID); err != nil {
		f.t.Fatal(err)
	}
	return sess
}

func (f *bcFixture) pending() int {
	f.t.Helper()
	n, err := f.st.PendingBackchannel(f.app.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *bcFixture) due() []*store.BackchannelJob {
	f.t.Helper()
	jobs, err := f.st.DueBackchannel(10)
	if err != nil {
		f.t.Fatal(err)
	}
	return jobs
}

// relyingParty records the logout tokens it is sent and answers with status.
type relyingParty struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status int
	tokens []string
	// other counts requests to any path but /backchannel, which a followed
	// redirect would produce.
	other int
}

func newRelyingParty(t *testing.T) *relyingParty {
	t.Helper()
	rp := &relyingParty{status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/backchannel", func(w http.ResponseWriter, r *http.Request) {
		rp.mu.Lock()
		defer rp.mu.Unlock()
		if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			t.Errorf("unexpected request %s %s %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		rp.tokens = append(rp.tokens, r.FormValue("logout_token"))
		if rp.status == http.StatusFound {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(rp.status)
		_, _ = w.Write([]byte("thanks"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rp.mu.Lock()
		rp.other++
		rp.mu.Unlock()
	})
	rp.srv = httptest.NewServer(mux)
	t.Cleanup(rp.srv.Close)
	return rp
}

func (rp *relyingParty) uri() string { return rp.srv.URL + "/backchannel" }

func (rp *relyingParty) setStatus(code int) {
	rp.mu.Lock()
	rp.status = code
	rp.mu.Unlock()
}

func (rp *relyingParty) received() []string {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return append([]string(nil), rp.tokens...)
}

// verifyLogoutToken checks the signature against the published key set and
// the header, and returns the claims.
func (f *bcFixture) verifyLogoutToken(raw string) map[string]any {
	f.t.Helper()
	sig, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		f.t.Fatal(err)
	}
	hdr := sig.Signatures[0].Header
	if typ := hdr.ExtraHeaders[jose.HeaderType]; typ != "logout+jwt" {
		f.t.Fatalf("typ header %v, want logout+jwt", typ)
	}
	keys, err := f.storage.KeySet(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	var payload []byte
	for _, k := range keys {
		if k.ID() == hdr.KeyID {
			if payload, err = sig.Verify(k.Key()); err != nil {
				f.t.Fatalf("signature: %v", err)
			}
		}
	}
	if payload == nil {
		f.t.Fatalf("kid %q is not in the published key set", hdr.KeyID)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		f.t.Fatal(err)
	}
	return claims
}

func TestBackchannelDelivery(t *testing.T) {
	f := newBCFixture(t)
	rp := newRelyingParty(t)
	f.setURI(rp.uri())
	sess := f.endSession()
	if f.pending() != 1 {
		t.Fatalf("pending %d, want 1", f.pending())
	}

	f.w.Flush(context.Background())
	got := rp.received()
	if len(got) != 1 {
		t.Fatalf("relying party received %d tokens, want 1", len(got))
	}
	if f.pending() != 0 {
		t.Fatalf("pending after delivery %d", f.pending())
	}

	claims := f.verifyLogoutToken(got[0])
	if claims["iss"] != testIssuer || claims["sub"] != strconv.FormatInt(f.user.ID, 10) || claims["sid"] != sess.SID {
		t.Fatalf("iss/sub/sid: %v", claims)
	}
	if aud, _ := claims["aud"].([]any); len(aud) != 1 || aud[0] != f.app.ClientID {
		t.Fatalf("aud %v, want [%s]", claims["aud"], f.app.ClientID)
	}
	events, _ := claims["events"].(map[string]any)
	if ev, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok || len(ev.(map[string]any)) != 0 {
		t.Fatalf("events %v", claims["events"])
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Fatalf("no jti: %v", claims)
	}
	if _, ok := claims["nonce"]; ok {
		t.Fatalf("logout token must not carry a nonce: %v", claims)
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if int64(iat) != f.now.Unix() || int64(exp) != f.now.Add(logoutTokenTTL).Unix() {
		t.Fatalf("iat %v exp %v, want %d and %d", iat, exp, f.now.Unix(), f.now.Add(logoutTokenTTL).Unix())
	}

	// Nothing is left to send; a second pass is a no-op.
	f.w.Flush(context.Background())
	if len(rp.received()) != 1 {
		t.Fatal("token sent twice")
	}
}

func TestBackchannelRetry(t *testing.T) {
	f := newBCFixture(t)
	rp := newRelyingParty(t)
	f.setURI(rp.uri())
	rp.setStatus(http.StatusInternalServerError)
	f.endSession()

	// Each failed attempt waits the next backoff step, measured on the
	// store clock; a fresh token is signed every time.
	for i, wait := range backchannelBackoff[:3] {
		f.w.Flush(context.Background())
		if n := len(rp.received()); n != i+1 {
			t.Fatalf("attempt %d: relying party saw %d requests", i+1, n)
		}
		if f.pending() != 1 || len(f.due()) != 0 {
			t.Fatalf("attempt %d: pending %d, due %d", i+1, f.pending(), len(f.due()))
		}
		f.advance(wait - time.Second)
		if len(f.due()) != 0 {
			t.Fatalf("attempt %d: due before %v passed", i+1, wait)
		}
		f.advance(time.Second)
		jobs := f.due()
		if len(jobs) != 1 || jobs[0].Attempts != i+1 {
			t.Fatalf("attempt %d: due %+v", i+1, jobs)
		}
	}
	got := rp.received()
	if got[0] == got[1] {
		t.Fatal("retry resent the same token")
	}

	// The relying party recovers; the next attempt delivers.
	rp.setStatus(http.StatusOK)
	f.w.Flush(context.Background())
	if f.pending() != 0 {
		t.Fatalf("pending after recovery %d", f.pending())
	}
	if entries, _ := f.st.ListAudit(store.AuditQuery{Event: "backchannel."}); len(entries) != 0 {
		t.Fatalf("delivered notification was audited as failed: %+v", entries[0])
	}
}

func TestBackchannelGivesUp(t *testing.T) {
	f := newBCFixture(t)
	rp := newRelyingParty(t)
	f.setURI(rp.uri())
	rp.setStatus(http.StatusBadGateway)
	f.endSession()

	for attempt := 1; attempt <= backchannelMaxAttempts; attempt++ {
		f.w.Flush(context.Background())
		if attempt < backchannelMaxAttempts {
			if f.pending() != 1 {
				t.Fatalf("attempt %d: dropped early", attempt)
			}
			f.advance(backchannelBackoff[min(attempt-1, len(backchannelBackoff)-1)])
		}
	}
	if n := len(rp.received()); n != backchannelMaxAttempts {
		t.Fatalf("relying party saw %d attempts, want %d", n, backchannelMaxAttempts)
	}
	if f.pending() != 0 {
		t.Fatal("notification kept after the last attempt")
	}
	entries, err := f.st.ListAudit(store.AuditQuery{Event: "backchannel.failed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Severity != store.SeverityWarning || e.ActorType != store.ActorSystem ||
		e.AppID != f.app.ID || e.UserID != f.user.ID {
		t.Fatalf("audit entry %+v", e)
	}
	if e.Detail["attempts"] != float64(backchannelMaxAttempts) || e.Detail["error"] != "status 502" {
		t.Fatalf("audit detail %v", e.Detail)
	}
}

func TestBackchannelFailures(t *testing.T) {
	t.Run("redirect is not followed", func(t *testing.T) {
		f := newBCFixture(t)
		rp := newRelyingParty(t)
		f.setURI(rp.uri())
		rp.setStatus(http.StatusFound)
		f.endSession()
		f.w.Flush(context.Background())
		rp.mu.Lock()
		other := rp.other
		rp.mu.Unlock()
		if other != 0 {
			t.Fatal("worker followed the redirect")
		}
		f.advance(backchannelBackoff[0])
		if jobs := f.due(); len(jobs) != 1 || jobs[0].Attempts != 1 {
			t.Fatalf("redirect was not treated as a failure: %+v", jobs)
		}
	})

	t.Run("unreachable relying party is retried", func(t *testing.T) {
		f := newBCFixture(t)
		rp := newRelyingParty(t)
		f.setURI(rp.uri())
		rp.srv.Close()
		f.endSession()
		f.w.Flush(context.Background())
		if f.pending() != 1 {
			t.Fatal("notification dropped after a connection failure")
		}
		f.advance(backchannelBackoff[0])
		if jobs := f.due(); len(jobs) != 1 || jobs[0].Attempts != 1 {
			t.Fatalf("after connection failure: %+v", jobs)
		}
	})

	t.Run("app without a URI sends nothing", func(t *testing.T) {
		f := newBCFixture(t)
		f.endSession()
		if f.pending() != 0 {
			t.Fatal("notification queued for an app without a back-channel URI")
		}
	})
}

func TestBackchannelRun(t *testing.T) {
	f := newBCFixture(t)
	rp := newRelyingParty(t)
	f.setURI(rp.uri())
	f.endSession()
	f.w.Interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.w.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(rp.received()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("worker did not deliver")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
}
