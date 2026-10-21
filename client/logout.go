package client

import (
	"context"
	"mime"
	"net/http"
	"sync"
	"time"
)

// logoutEvent is the member the events claim of a logout token must have
// (OpenID Connect Back-Channel Logout 1.0 section 2.4).
const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

const (
	// maxLogoutBody bounds the body of a back-channel logout request. A
	// logout token is under two kilobytes.
	maxLogoutBody = 64 << 10
	// jtiCacheMax bounds the replay cache. Entries only come from tokens
	// that verified, so only the provider can fill it.
	jtiCacheMax = 10000
	// jtiMaxRemember caps how long a jti is kept, for a provider whose exp
	// is far away.
	jtiMaxRemember = 24 * time.Hour
)

// LogoutToken is a verified back-channel logout token. At least one of
// Subject and SID is set: end the local sessions that match either.
type LogoutToken struct {
	Issuer  string
	Subject string
	// SID is the provider session that ended, the sid claim of the ID tokens
	// it issued.
	SID      string
	JTI      string
	IssuedAt time.Time
	Expiry   time.Time
	Raw      map[string]any
}

// VerifyLogoutToken verifies a raw logout token as OpenID Connect
// Back-Channel Logout 1.0 section 2.6 asks: signature by a published key,
// iss, aud and azp as for an ID token, iat present and not in the future,
// exp present and in the future, the backchannel-logout event with an object
// value, no nonce, a jti that has not been seen before, and at least one of
// sub and sid. A typ header, when present, must be logout+jwt (or JWT, for
// providers that do not set it).
func (c *Client) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutToken, error) {
	v, err := c.verifySignature(ctx, raw)
	if err != nil {
		return nil, err
	}
	if typ := normalizeTyp(v.jws.header.Typ); typ != "" && typ != "logout+jwt" && typ != "jwt" {
		return nil, invalid("typ %q is not a logout token", v.jws.header.Typ)
	}
	cl := &v.claims
	if err := c.checkIssuerAudience(cl); err != nil {
		return nil, err
	}
	if err := c.checkTimes(cl); err != nil {
		return nil, err
	}
	events, ok := v.raw["events"].(map[string]any)
	if !ok {
		return nil, invalid("no events claim")
	}
	if _, ok := events[logoutEvent].(map[string]any); !ok {
		return nil, invalid("events lacks the backchannel-logout member")
	}
	if _, ok := v.raw["nonce"]; ok {
		return nil, invalid("a logout token must not carry a nonce")
	}
	if cl.Sub == "" && cl.SID == "" {
		return nil, invalid("neither sub nor sid")
	}
	if cl.JTI == "" {
		return nil, invalid("no jti")
	}
	// The token is accepted for ClockSkew past exp, so the jti is kept
	// that long too; otherwise a replay in that window would get through.
	if !c.jtis.remember(cl.JTI, cl.Exp.time().Add(c.cfg.ClockSkew), c.now()) {
		return nil, invalid("jti %q was already used", cl.JTI)
	}
	return &LogoutToken{
		Issuer:   cl.Iss,
		Subject:  cl.Sub,
		SID:      cl.SID,
		JTI:      cl.JTI,
		IssuedAt: cl.Iat.time(),
		Expiry:   cl.Exp.time(),
		Raw:      v.raw,
	}, nil
}

// BackchannelLogoutHandler serves the application's back-channel logout URI
// (OpenID Connect Back-Channel Logout 1.0 section 2.5). It accepts a form
// POST with a logout_token field, verifies the token and calls onLogout,
// which should end every local session with that SID, or every session of
// that subject when there is no SID. A token that does not verify is
// answered 400; an onLogout error 500, after which the provider retries
// and the token's jti may be used again; success 200. Every answer carries
// Cache-Control: no-store.
func (c *Client) BackchannelLogoutHandler(onLogout func(ctx context.Context, lt *LogoutToken) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/x-www-form-urlencoded" {
			jsonError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBody)
		if err := r.ParseForm(); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		raw := r.PostForm.Get("logout_token")
		if raw == "" {
			jsonError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		lt, err := c.VerifyLogoutToken(r.Context(), raw)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if err := onLogout(r.Context(), lt); err != nil {
			c.jtis.forget(lt.JTI)
			jsonError(w, http.StatusInternalServerError, "server_error")
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// jsonError writes {"error": code} with the given status.
func jsonError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(`{"error":"` + code + `"}`))
}

// jtiCache remembers the jti of every logout token accepted for as long as
// the token would still verify, so a captured token cannot be replayed to
// sign someone out again.
type jtiCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newJTICache() *jtiCache {
	return &jtiCache{seen: make(map[string]time.Time)}
}

// remember records jti until the given time and reports whether it was new.
// Expired entries are dropped on the way; when the cache is still full the
// entry that expires soonest is evicted, which is the one least worth
// keeping.
func (j *jtiCache) remember(jti string, exp, now time.Time) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if until, ok := j.seen[jti]; ok && until.After(now) {
		return false
	}
	for k, until := range j.seen {
		if !until.After(now) {
			delete(j.seen, k)
		}
	}
	if len(j.seen) >= jtiCacheMax {
		var soonest string
		var soonestAt time.Time
		for k, until := range j.seen {
			if soonest == "" || until.Before(soonestAt) {
				soonest, soonestAt = k, until
			}
		}
		delete(j.seen, soonest)
	}
	if limit := now.Add(jtiMaxRemember); exp.After(limit) {
		exp = limit
	}
	j.seen[jti] = exp
	return true
}

// forget drops jti so the same token can be processed again, used when the
// application failed to act on it and the provider will retry.
func (j *jtiCache) forget(jti string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.seen, jti)
}
