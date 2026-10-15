// Package api is the HTTP surface: the JSON API behind the embedded UI, the
// session endpoints, and the OIDC endpoints. Handlers here are thin — they
// translate HTTP to calls on the auth, store and oidc packages and never
// re-implement a security decision.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/store"
	"github.com/lieyanc/FireID/internal/version"
)

// maxBodyBytes caps request bodies. Every JSON endpoint is small; anything
// larger is a mistake or an attack.
const maxBodyBytes = 1 << 20 // 1 MiB

// Deps is what the API server needs from the rest of the program.
type Deps struct {
	Store *store.Store
	Auth  *auth.Service
	Log   *slog.Logger
	Web   fs.FS
	// PublicBase is the externally reachable base URL (the OIDC issuer).
	PublicBase string
	// TrustProxyHeaders allows X-Forwarded-For and X-Forwarded-Proto to be
	// honoured. Only enable it when a reverse proxy on loopback is the sole
	// way to reach this listener.
	TrustProxyHeaders bool
	Started           time.Time
	SetLogLevel       func(string)
}

// Server holds the assembled handlers.
type Server struct {
	deps   Deps
	mux    *http.ServeMux
	http   *http.Server
	listen net.Listener
}

// New builds the server and its routes.
func New(deps Deps) (*Server, error) {
	if deps.Store == nil || deps.Auth == nil {
		return nil, errors.New("api: store and auth are required")
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	s := &Server{deps: deps, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// Handler returns the fully wrapped handler chain. The cross-site check runs on
// every state-changing request, before routing, so a handler that forgets to
// call crossSite itself cannot open a hole.
func (s *Server) Handler() http.Handler {
	return s.withRecover(s.withSecurityHeaders(s.withLogging(s.withCrossSite(s.mux))))
}

// withCrossSite rejects unsafe methods that did not originate from this site.
// Server-to-server callers (the token endpoint, the forward-auth subrequest)
// send no Origin and no Sec-Fetch-Site, and pass through.
func (s *Server) withCrossSite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.crossSite(r) {
			s.deps.Log.Warn("rejected cross-site request", "method", r.Method, "path", r.URL.Path,
				"origin", r.Header.Get("Origin"), "secFetchSite", r.Header.Get("Sec-Fetch-Site"),
				"ip", s.clientIP(r))
			fail(w, http.StatusForbidden, "cross_site", "cross-site requests are not accepted")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Start begins serving on addr.
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listen = ln
	s.http = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.deps.Log.Handler(), slog.LevelWarn),
	}
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.deps.Log.Error("http server stopped", "err", err)
		}
	}()
	s.deps.Log.Info("listening", "addr", ln.Addr().String(), "publicBase", s.deps.PublicBase)
	return nil
}

// Close stops the listener.
func (s *Server) Close() error {
	if s.http == nil {
		return nil
	}
	return s.http.Close()
}

// Addr is the bound address, which differs from the configured one when
// port 0 was requested.
func (s *Server) Addr() string {
	if s.listen == nil {
		return ""
	}
	return s.listen.Addr().String()
}

// routes registers every handler. OIDC endpoints are added by the oidc package
// once the provider is wired in.
func (s *Server) routes() {
	h := func(pattern string, fn http.HandlerFunc) { s.mux.HandleFunc(pattern, fn) }

	h("GET /health", s.health)
	h("GET /api/version", s.version)
	h("GET /api/setup", s.setupState)
	h("POST /api/setup", s.setup)
	h("POST /api/auth/login", s.login)
	h("POST /api/auth/logout", s.logout)
	h("GET /api/auth/me", s.me)

	// The UI catches everything else. Unknown /api/ paths must return JSON, not
	// the HTML shell, so a typo in the frontend fails loudly.
	s.mux.Handle("/", http.HandlerFunc(s.static))
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// withRecover turns a panic into a 500 instead of killing the process.
func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				s.deps.Log.Error("panic in handler", "path", r.URL.Path, "panic", fmt.Sprint(p))
				fail(w, http.StatusInternalServerError, "internal_error", "something went wrong")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withSecurityHeaders sets the headers the workspace uses everywhere.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		// The UI is a self-contained SPA: no inline scripts, no external
		// origins. Passkeys need no additional permissions.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// withLogging records one line per request, with the fields that matter for
// auditing. Tokens and codes are never queried into the log.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		level := slog.LevelDebug
		if rec.status >= 500 {
			level = slog.LevelError
		} else if rec.status >= 400 {
			level = slog.LevelInfo
		}
		s.deps.Log.Log(r.Context(), level, "http",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"ip", s.clientIP(r), "duration", time.Since(start).Round(time.Millisecond).String())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.written {
		r.status = code
		r.written = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.written = true
	return r.ResponseWriter.Write(b)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"uptime": time.Since(s.deps.Started).Round(time.Second).String(),
	})
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, version.Info())
}

// setupState tells the UI whether the first-run wizard or the sign-in form
// should be shown.
func (s *Server) setupState(w http.ResponseWriter, r *http.Request) {
	users, err := s.deps.Store.CountUsers()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal_error", "could not read the account table")
		return
	}
	hasAdmin, err := s.deps.Store.HasSuperAdmin()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal_error", "could not read the account table")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"setupRequired": users == 0 || !hasAdmin,
		"registration":  s.deps.Auth.RegistrationMode(),
	})
}

type setupRequest struct {
	Token       string `json:"token"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
}

// setup creates the first super admin using the token printed at startup.
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.deps.Auth.CheckSetupToken(req.Token); err != nil {
		switch {
		case errors.Is(err, auth.ErrSetupUnavailable):
			fail(w, http.StatusConflict, "setup_unavailable", "setup has already been completed")
		default:
			fail(w, http.StatusUnauthorized, "invalid_token", "that setup token is not valid")
		}
		return
	}
	if err := s.deps.Auth.CheckPassword(req.Password); err != nil {
		fail(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal_error", "could not hash the password")
		return
	}
	user, err := s.deps.Store.CreateUser(store.NewUser{
		Username:     req.Username,
		Email:        req.Email,
		DisplayName:  req.DisplayName,
		PasswordHash: hash,
		Status:       store.UserActive,
		IsSuperAdmin: true,
	})
	if err != nil {
		s.failFromStore(w, err, "could not create the administrator account")
		return
	}
	s.deps.Auth.ConsumeSetupToken()
	s.deps.Log.Warn("super administrator created", "userId", user.ID, "username", user.Username)

	token, sess, err := s.deps.Store.CreateSession(user.ID, 7*24*time.Hour,
		s.clientIP(r), r.UserAgent(), "pwd", store.ACRLoA1)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal_error", "account created, but signing in failed")
		return
	}
	s.deps.Auth.SetSessionCookie(w, token, sess.ExpiresAt)
	writeJSON(w, http.StatusCreated, map[string]any{"user": publicUser(user)})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"`
	// UserID is returned by a challenge response and sent back with the code.
	UserID int64 `json:"userId"`
}

// login performs a password sign-in, or completes one with a TOTP code.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := s.clientIP(r)

	res, err := s.deps.Auth.AuthenticatePassword(req.Username, req.Password, ip)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrSecondFactorRequired), errors.Is(err, auth.ErrSecondFactorNotConfigured):
			// The password was correct; ask for the second factor.
			user, lookupErr := s.deps.Store.UserByUsername(req.Username)
			if lookupErr != nil {
				fail(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"challenge": "totp",
				"userId":    user.ID,
			})
			return
		case errors.Is(err, auth.ErrInvalidCredentials):
			s.deps.Log.Info("failed sign-in", "username", store.NormaliseUsername(req.Username), "ip", ip)
			fail(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
			return
		default:
			s.failFromAuth(w, err)
			return
		}
	}

	s.finishLogin(w, r, res)
}

// loginTOTP completes a sign-in that requires a second factor. It is separated
// from login because the password must be proven again: the client sends both.
func (s *Server) loginTOTP(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := s.clientIP(r)

	// Re-check the password: the challenge response is not a substitute for it.
	if _, err := s.deps.Auth.AuthenticatePassword(req.Username, req.Password, ip); err == nil ||
		!errors.Is(err, auth.ErrSecondFactorRequired) {
		if err == nil {
			// TOTP was disabled between requests; the password alone is fine.
			fail(w, http.StatusConflict, "second_factor_not_required", "this account no longer requires a second factor")
			return
		}
		fail(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}

	user, err := s.deps.Store.UserByUsername(req.Username)
	if err != nil {
		fail(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	res, err := s.deps.Auth.AuthenticateTOTP(user.ID, req.Code, ip, true)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			fail(w, http.StatusUnauthorized, "invalid_code", "that code is not valid")
		default:
			s.failFromAuth(w, err)
		}
		return
	}
	s.finishLogin(w, r, res)
}

// finishLogin issues the session cookie and returns the account.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, res *auth.LoginResult) {
	token, sess, err := s.deps.Auth.StartSession(res, s.clientIP(r), r.UserAgent())
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal_error", "could not start a session")
		return
	}
	s.deps.Auth.SetSessionCookie(w, token, sess.ExpiresAt)
	s.deps.Log.Info("sign-in", "userId", res.User.ID, "username", res.User.Username,
		"amr", res.AMR, "ip", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(res.User)})
}

// logout revokes the session. It is a state-changing POST, so it carries the
// same cross-site check as every other one: a page elsewhere must not be able
// to sign a visitor out.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.crossSite(r) {
		fail(w, http.StatusForbidden, "cross_site", "cross-site requests are not accepted")
		return
	}
	if err := s.deps.Auth.SignOutByRequest(r); err != nil {
		s.deps.Log.Error("sign-out failed", "err", err)
	}
	s.deps.Auth.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// me returns the signed-in account, or 401.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	sess, user, err := s.deps.Auth.SessionUser(r)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.deps.Log.Error("session lookup failed", "err", err)
		}
		fail(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":        publicUser(user),
		"amr":         strings.Fields(sess.AMR),
		"acr":         sess.ACR,
		"sessionId":   sess.ID,
		"expiresAt":   sess.ExpiresAt,
		"issuer":      s.deps.PublicBase,
		"permissions": s.permissions(user),
	})
}

// permissions summarises what the account may do, so the UI does not have to
// infer it from roles.
func (s *Server) permissions(user *store.User) map[string]bool {
	apps, err := s.deps.Store.AppsOwnedBy(user.ID)
	if err != nil {
		s.deps.Log.Error("could not list owned apps", "userId", user.ID, "err", err)
	}
	return map[string]bool{
		"superAdmin":  user.IsSuperAdmin,
		"manageUsers": user.IsSuperAdmin,
		"manageApps":  user.IsSuperAdmin || len(apps) > 0,
		"ownedApps":   len(apps) > 0,
	}
}

// static serves the embedded UI, falling back to index.html so client-side
// routes survive a reload.
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/oauth/") ||
		strings.HasPrefix(r.URL.Path, "/.well-known/") {
		fail(w, http.StatusNotFound, "not_found", "no such endpoint")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is allowed here")
		return
	}
	if s.deps.Web == nil {
		fail(w, http.StatusNotFound, "ui_missing", "the web UI was not built into this binary")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if data, err := fs.ReadFile(s.deps.Web, path); err == nil {
		w.Header().Set("Content-Type", contentTypeFor(path))
		if strings.HasPrefix(path, "assets/") {
			// Hashed asset names, so they can be cached indefinitely.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		_, _ = w.Write(data)
		return
	}

	index, err := fs.ReadFile(s.deps.Web, "index.html")
	if err != nil {
		fail(w, http.StatusNotFound, "ui_missing", "the web UI was not built into this binary")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(index)
}

func contentTypeFor(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".json"):
		return "application/json"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(path, ".png"):
		return "image/png"
	case strings.HasSuffix(path, ".webp"):
		return "image/webp"
	case strings.HasSuffix(path, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(path, ".ico"):
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

// decodeJSON reads a JSON body with a size cap and rejects unknown fields, so a
// typo in a client is caught rather than silently ignored.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		fail(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "send application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		fail(w, http.StatusBadRequest, "invalid_body", "the request body could not be read")
		return false
	}
	return true
}

// clientIP returns the source address. Forwarded headers are honoured only when
// the operator has declared that a proxy is in front.
func (s *Server) clientIP(r *http.Request) string {
	if s.deps.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// The left-most entry is the client; the rest are proxies.
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isSecureRequest reports whether the browser reached us over TLS, including
// through a proxy that terminated it.
func (s *Server) isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if s.deps.TrustProxyHeaders {
		return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
	return false
}

// crossSite rejects state-changing requests that did not originate from this
// site, which is the workspace's replacement for per-form CSRF tokens. Two
// independent signals are checked: the browser's own Sec-Fetch-Site and the
// Origin header.
func (s *Server) crossSite(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		if site != "same-origin" && site != "same-site" && site != "none" {
			return true
		}
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return true
	}
	expected, err := url.Parse(s.deps.PublicBase)
	if err != nil {
		return true
	}
	if !strings.EqualFold(u.Host, expected.Host) {
		return true
	}
	if u.Scheme != expected.Scheme && !(s.deps.TrustProxyHeaders && s.isSecureRequest(r)) {
		return true
	}
	return false
}

// guard wraps a state-changing handler with the cross-site check and the
// session requirement.
func (s *Server) guard(needSuperAdmin bool, fn func(http.ResponseWriter, *http.Request, *store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.crossSite(r) {
			fail(w, http.StatusForbidden, "cross_site", "cross-site requests are not accepted")
			return
		}
		_, user, err := s.deps.Auth.SessionUser(r)
		if err != nil {
			fail(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
			return
		}
		if needSuperAdmin && !user.IsSuperAdmin {
			fail(w, http.StatusForbidden, "forbidden", "this action needs an administrator")
			return
		}
		fn(w, r, user)
	}
}

// publicUser is the account as the UI sees it. Secrets and hashes never appear
// here; keeping one constructor for it is how that stays true.
func publicUser(u *store.User) map[string]any {
	return map[string]any{
		"id":            u.ID,
		"username":      u.Username,
		"email":         u.Email,
		"displayName":   u.DisplayName,
		"status":        u.Status,
		"superAdmin":    u.IsSuperAdmin,
		"totpEnabled":   u.TOTPConfirmed,
		"hasPassword":   u.PasswordHash != "",
		"createdAt":     timeText(u.CreatedAt),
		"lastLoginAt":   timeText(u.LastLoginAt),
		"emailVerified": u.Status == store.UserActive,
	}
}

// timeText renders a timestamp for JSON, using an empty string for "never"
// rather than the zero time, which would read as year 1 in the UI.
func timeText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// fail writes the workspace's error envelope.
func fail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: code, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		// The status line is already sent; nothing useful is left to do but
		// leave a trace.
		slog.Error("encode response", "err", err)
	}
}

// failFromStore maps store errors onto status codes.
func (s *Server) failFromStore(w http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, store.ErrInvalid):
		fail(w, http.StatusBadRequest, "invalid", err.Error())
	case errors.Is(err, store.ErrConflict):
		fail(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such record")
	default:
		s.deps.Log.Error("store error", "err", err, "message", fallback)
		fail(w, http.StatusInternalServerError, "internal_error", fallback)
	}
}

// failFromAuth maps auth errors onto status codes.
func (s *Server) failFromAuth(w http.ResponseWriter, err error) {
	var limited *auth.RateLimitError
	switch {
	case errors.As(err, &limited):
		w.Header().Set("Retry-After", strconv.Itoa(int(limited.RetryAfter.Seconds())+1))
		fail(w, http.StatusTooManyRequests, "rate_limited", limited.Error())
	case errors.Is(err, auth.ErrInvalidPassword):
		fail(w, http.StatusBadRequest, "weak_password", err.Error())
	case errors.Is(err, auth.ErrForbidden):
		fail(w, http.StatusForbidden, "forbidden", err.Error())
	default:
		s.failFromStore(w, err, "authentication failed")
	}
}
