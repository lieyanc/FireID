package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/config"
	"github.com/lieyanc/FireID/internal/secretbox"
	"github.com/lieyanc/FireID/internal/store"
)

// cryptoKeyLabel separates the opaque-token key from every other use of the
// master key.
const cryptoKeyLabel = "fireid/op/access-token-crypto/v1"

// Provider wraps zitadel/oidc/v3 pkg/op and wires it to Fire ID's storage and
// session layers.
type Provider struct {
	op      *op.Provider
	storage *Storage
	auth    *auth.Service
	issuer  string
	log     *slog.Logger
}

// paths are the provider's endpoints relative to the issuer. The device
// authorization endpoint is deliberately absent: the flow is not offered.
var paths = map[string]bool{
	oidc.DiscoveryEndpoint: true,
	"/authorize":           true,
	"/authorize/callback":  true,
	"/oauth/token":         true,
	"/oauth/introspect":    true,
	"/userinfo":            true,
	"/revoke":              true,
	"/end_session":         true,
	"/keys":                true,
}

// Handles reports whether path is one of the provider's endpoints.
func Handles(path string) bool { return paths[path] }

// NewProvider creates the OIDC provider. It makes sure a signing key exists
// before the first request.
func NewProvider(st *store.Store, box *secretbox.Box, authSvc *auth.Service, cfg *config.Store, log *slog.Logger) (*Provider, error) {
	issuer := cfg.Issuer()
	c := cfg.Get().OIDC
	storage := NewStorage(st, box, Settings{
		CodeTTL:          time.Duration(c.CodeTTL) * time.Second,
		AccessTokenTTL:   time.Duration(c.AccessTokenTTL) * time.Second,
		RefreshTokenTTL:  time.Duration(c.RefreshTokenTTL) * time.Second,
		IDTokenTTL:       time.Duration(c.IDTokenTTL) * time.Second,
		SigningAlgorithm: c.SigningAlgorithm,
	})
	if err := storage.EnsureSigningKey(context.Background()); err != nil {
		return nil, fmt.Errorf("prepare signing key: %w", err)
	}

	master, err := cfg.MasterKey()
	if err != nil {
		return nil, fmt.Errorf("load master key: %w", err)
	}
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(cryptoKeyLabel))
	var cryptoKey [32]byte
	copy(cryptoKey[:], mac.Sum(nil))

	providerCfg := &op.Config{
		// Opaque access tokens and authorization codes are sealed with this
		// key. It must be secret: anyone holding it could mint access tokens.
		CryptoKey:                cryptoKey,
		DefaultLogoutRedirectURI: issuer + "/",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		GrantTypeRefreshToken:    true,
		SupportedClaims: []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "sid",
			"name", "preferred_username", "updated_at", "email", "email_verified"},
		SupportedScopes: []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess},
		// Logout tokens are sent by Backchannel; every ID token carries sid.
		BackChannelLogoutSupported:        true,
		BackChannelLogoutSessionSupported: true,
	}

	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("parse issuer: %w", err)
	}
	var opts []op.Option
	if u.Scheme == "http" {
		// The library refuses an http issuer unless told otherwise. Plain
		// HTTP is only sensible on a development machine, and the
		// configuration already insists on an explicit scheme.
		opts = append(opts, op.WithAllowInsecure())
	}
	opProvider, err := op.NewProvider(providerCfg, storage, op.StaticIssuer(issuer), opts...)
	if err != nil {
		return nil, fmt.Errorf("create OIDC provider: %w", err)
	}

	p := &Provider{op: opProvider, storage: storage, auth: authSvc, issuer: issuer, log: log}
	storage.log = log
	storage.endBrowserSession = p.endBrowserSession
	return p, nil
}

// ServeHTTP serves the provider's endpoints. Three of them are adjusted on the
// way through: discovery advertises only what is implemented, authorization
// responses carry the issuer (RFC 9207), and end_session can sign the browser
// out.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case oidc.DiscoveryEndpoint:
		p.discovery(w, r)
		return
	case "/authorize", "/authorize/callback":
		w = &issWriter{ResponseWriter: w, issuer: p.issuer}
	case "/end_session":
		r = r.WithContext(context.WithValue(r.Context(), exchangeKey{}, &exchange{w: w, r: r}))
	}
	p.op.ServeHTTP(w, r)
}

// discovery serves the metadata document. The library's version lists the
// implicit flow and id_token response types whether or not a client can use
// them, so the document is corrected before it is sent.
func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := op.ContextWithIssuer(r.Context(), p.issuer)
	raw, err := json.Marshal(op.CreateDiscoveryConfig(ctx, p.op, p.storage))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	doc["response_types_supported"] = []string{string(oidc.ResponseTypeCode)}
	doc["response_modes_supported"] = []string{string(oidc.ResponseModeQuery)}
	doc["grant_types_supported"] = []string{string(oidc.GrantTypeCode), string(oidc.GrantTypeRefreshToken)}
	doc["subject_types_supported"] = []string{"public"}
	doc["authorization_response_iss_parameter_supported"] = true
	doc["request_parameter_supported"] = false
	doc["request_uri_parameter_supported"] = false
	delete(doc, "device_authorization_endpoint")
	delete(doc, "check_session_iframe")
	delete(doc, "request_object_signing_alg_values_supported")

	body, err := json.Marshal(doc)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}

// issWriter adds the iss parameter to authorization responses that redirect
// to a client (RFC 9207), which lets a client that talks to several providers
// tell whose response it is holding. Redirects to Fire ID's own pages are left
// alone.
type issWriter struct {
	http.ResponseWriter
	issuer string
	wrote  bool
}

func (w *issWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		if code == http.StatusFound || code == http.StatusSeeOther {
			if loc := w.Header().Get("Location"); loc != "" {
				w.Header().Set("Location", addIssuer(loc, w.issuer))
			}
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *issWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// addIssuer appends iss to an absolute redirect to a client.
func addIssuer(loc, issuer string) string {
	u, err := url.Parse(loc)
	if err != nil || !u.IsAbs() || loc == issuer || strings.HasPrefix(loc, issuer+"/") {
		return loc
	}
	q := u.Query()
	if q.Has("iss") {
		return loc
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

// exchange lets storage callbacks reach the HTTP request that caused them.
// Only end_session uses it, to clear the browser session.
type exchange struct {
	w http.ResponseWriter
	r *http.Request
}

type exchangeKey struct{}

// endBrowserSession signs the browser out after a logout request whose
// id_token_hint named the user who is signed in. A hint for someone else —
// a stale token from an earlier account — leaves the current session alone.
func (p *Provider) endBrowserSession(ctx context.Context, subject, clientID string) {
	ex, ok := ctx.Value(exchangeKey{}).(*exchange)
	if !ok || p.auth == nil {
		return
	}
	sess, user, err := p.auth.SessionUser(ex.r)
	if err != nil || subjectOf(user.ID) != subject {
		return
	}
	if err := p.auth.SignOutByRequest(ex.r); err != nil {
		p.log.Warn("could not end the browser session on logout", "userId", user.ID, "err", err)
		return
	}
	p.auth.ClearSessionCookie(ex.w)
	p.log.Info("signed out by relying party", "userId", user.ID, "clientId", clientID)

	// The app is only named in the entry; the sign-out stands without it.
	var appID int64
	if app, err := p.storage.store.AppByClientID(clientID); err == nil {
		appID = app.ID
	}
	if err := p.storage.store.Audit(store.AuditEvent{
		Event: "auth.sign_out", ActorType: store.ActorUser, ActorUserID: user.ID, UserID: user.ID,
		AppID: appID, IP: sess.IP, UserAgent: ex.r.UserAgent(),
		Detail: map[string]any{"via": "rp_logout"},
	}); err != nil {
		p.log.Warn("could not record audit event", "event", "auth.sign_out", "err", err)
	}
}
