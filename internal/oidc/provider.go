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

// ServeHTTP serves the provider's endpoints. Several are adjusted on the way
// through: discovery advertises only what is implemented, authorization
// responses carry the issuer (RFC 9207), the callback releases a code only to
// the browser that approved it, credentials are refused in the URL, and
// end_session can sign the browser out.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if msg := credentialsInURL(r); msg != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(oidc.ErrInvalidRequest().WithDescription("%s", msg))
		return
	}
	switch r.URL.Path {
	case "/oauth/token", "/oauth/introspect", "/userinfo", "/revoke":
		// Responses carry tokens or claims about one person; no cache may
		// keep them (RFC 6749 section 5.1, OIDC Core section 3.1.3.3). The
		// library sets neither header.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if r.URL.Path == "/userinfo" {
			w = &bearerWriter{ResponseWriter: w, realm: p.issuer, presented: bearerPresented(r)}
			break
		}
		if r.URL.Path == "/revoke" && r.Method == http.MethodPost && !tokenPresented(r) {
			// The library would look the empty token up and answer 200.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(oidc.ErrInvalidRequest().WithDescription("the token parameter is required"))
			return
		}
		if _, _, ok := r.BasicAuth(); ok {
			w = &basicWriter{ResponseWriter: w, realm: p.issuer}
		}
	case oidc.DiscoveryEndpoint:
		p.discovery(w, r)
		return
	case "/authorize/callback":
		if !p.callbackAllowed(r) {
			http.Error(w, "This sign-in was approved in another browser. Go back to the application and try again.",
				http.StatusBadRequest)
			return
		}
		w = &issWriter{ResponseWriter: w, issuer: p.issuer}
	case "/authorize":
		r = refuseRequestObjects(r)
		w = &issWriter{ResponseWriter: w, issuer: p.issuer}
	case "/end_session":
		r = r.WithContext(context.WithValue(r.Context(), exchangeKey{}, &exchange{w: w, r: r}))
	}
	p.op.ServeHTTP(w, r)
}

// credentialsInURL refuses requests that put a credential in the query
// string, where it would reach access logs, browser history and Referer. The
// library reads r.Form, which merges the query with the body, so it would
// otherwise accept them. The token, introspection and revocation endpoints
// take POST bodies only (RFC 6749 section 3.2, RFC 7009, RFC 7662); userinfo
// takes the token in the Authorization header or a POST body (RFC 6750
// sections 2.1 and 2.2). CORS preflights carry no credentials and pass.
func credentialsInURL(r *http.Request) string {
	switch r.URL.Path {
	case "/oauth/token", "/oauth/introspect", "/revoke":
		if r.Method != http.MethodPost && r.Method != http.MethodOptions {
			return "this endpoint accepts POST only"
		}
		if r.URL.RawQuery != "" {
			return "send the parameters in the request body, not the URL"
		}
	case "/userinfo":
		if r.URL.Query().Has("access_token") {
			return "send the access token in the Authorization header, not the URL"
		}
	}
	return ""
}

// tokenPresented reports whether a revocation request names a token. The
// form is parsed here, which the library then reuses.
func tokenPresented(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		// Left to the library, which reports the malformed body itself.
		return true
	}
	return r.PostForm.Get("token") != ""
}

// bearerPresented reports whether a userinfo request carries an access token
// in either of the places the library looks.
func bearerPresented(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); len(h) > len(oidc.PrefixBearer) &&
		strings.EqualFold(h[:len(oidc.PrefixBearer)], oidc.PrefixBearer) {
		return true
	}
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		return false
	}
	return r.PostForm.Get("access_token") != ""
}

// bearerWriter turns the library's userinfo refusals into RFC 6750 section 3
// challenges. The library answers 401 in plain text for a missing or
// unreadable token and 403 when storage rejects it (revoked, expired, owner
// blocked or no longer allowed the app); to the client each of these means
// "get a new token", which is 401 invalid_token. A request with no token at
// all gets a challenge without an error code, as section 3.1 asks.
type bearerWriter struct {
	http.ResponseWriter
	realm     string
	presented bool
	replaced  bool
}

func (w *bearerWriter) WriteHeader(code int) {
	if w.replaced {
		return
	}
	if code != http.StatusUnauthorized && code != http.StatusForbidden {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.replaced = true
	e := oidc.ErrInvalidRequest().WithDescription("an access token is required")
	challenge := fmt.Sprintf("Bearer realm=%q", w.realm)
	if w.presented {
		e = &oidc.Error{ErrorType: "invalid_token", Description: "the access token is invalid, expired or revoked"}
		challenge += `, error="invalid_token"`
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Type", "application/json")
	h.Set("WWW-Authenticate", challenge)
	w.ResponseWriter.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w.ResponseWriter).Encode(e)
}

func (w *bearerWriter) Write(b []byte) (int, error) {
	if w.replaced {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// basicWriter adds the challenge RFC 6749 section 5.2 requires when a client
// that authenticated with the Authorization header is refused. The library
// answers 401 invalid_client without it.
type basicWriter struct {
	http.ResponseWriter
	realm string
}

func (w *basicWriter) WriteHeader(code int) {
	if code == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") == "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", w.realm))
	}
	w.ResponseWriter.WriteHeader(code)
}

// refusedParamKey carries the error for a request object the authorization
// request asked for. The library decides when to report it: CreateAuthRequest
// returns it once the redirect URI has been checked, so it is redirected to
// the client with the state like any other request error.
type refusedParamKey struct{}

// refuseRequestObjects handles request and request_uri (OIDC Core 6), neither
// of which Fire ID supports. The library ignores request_uri, which would run
// the flow with parameters the client did not mean, and refuses request
// without saying why. Both are taken off the form and replaced by the error.
func refuseRequestObjects(r *http.Request) *http.Request {
	if err := r.ParseForm(); err != nil {
		return r
	}
	var refused *oidc.Error
	switch {
	case r.Form.Has("request_uri"):
		refused = &oidc.Error{ErrorType: "request_uri_not_supported", Description: "request_uri is not supported"}
	case r.Form.Has("request"):
		refused = oidc.ErrRequestNotSupported().WithDescription("request objects are not supported")
	default:
		return r
	}
	r.Form.Del("request_uri")
	r.Form.Del("request")
	return r.WithContext(context.WithValue(r.Context(), refusedParamKey{}, refused))
}

// callbackAllowed binds the code to the browser that approved the request.
// The request ID is not a secret — whoever started the flow saw it in the
// redirect to /login — so without this check someone could start a flow, get
// a signed-in victim to open the login link, and collect the victim's code
// from the callback themselves. An approved request is released only to a
// request carrying the session that approved it; anything else is left to the
// library, which reports unknown and unapproved requests itself.
func (p *Provider) callbackAllowed(r *http.Request) bool {
	// The library reads the ID from the form, body included, so this does too.
	if err := r.ParseForm(); err != nil {
		return false
	}
	ar, err := p.storage.store.AuthRequestByID(r.Form.Get("id"))
	if err != nil || !ar.UserID.Valid {
		return true
	}
	if p.auth == nil || ar.SID == "" {
		return false
	}
	sess, _, err := p.auth.SessionUser(r)
	return err == nil && sess.SID == ar.SID
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

// addIssuer adds iss to an absolute redirect to a client, beside the other
// response parameters: in the fragment when they travel there (response_type
// id_token), otherwise in the query. Registered redirect URIs carry no
// fragment, so one on the way out holds the response.
//
// It also corrects one error code. At the authorization endpoint the library
// reports a response type the client is not registered for as
// unauthorized_client, but Fire ID supports code only, so any other type is
// unsupported_response_type (RFC 6749 section 4.1.2.1).
func addIssuer(loc, issuer string) string {
	u, err := url.Parse(loc)
	if err != nil || !u.IsAbs() || loc == issuer || strings.HasPrefix(loc, issuer+"/") {
		return loc
	}
	if u.Fragment != "" {
		params, err := url.ParseQuery(u.Fragment)
		if err != nil {
			return loc
		}
		fixAuthzParams(params, issuer)
		u.Fragment, u.RawFragment = "", ""
		return u.String() + "#" + params.Encode()
	}
	q := u.Query()
	fixAuthzParams(q, issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

func fixAuthzParams(params url.Values, issuer string) {
	if params.Get("error") == string(oidc.UnauthorizedClient) {
		params.Set("error", "unsupported_response_type")
		params.Set("error_description", "only response_type=code is supported")
	}
	if !params.Has("iss") {
		params.Set("iss", issuer)
	}
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
