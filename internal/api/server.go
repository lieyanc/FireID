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
	"sync"
	"time"

	"github.com/lieyanc/FireID/internal/auth"
	"github.com/lieyanc/FireID/internal/config"
	"github.com/lieyanc/FireID/internal/forwardauth"
	"github.com/lieyanc/FireID/internal/oidc"
	"github.com/lieyanc/FireID/internal/secretbox"
	"github.com/lieyanc/FireID/internal/store"
	"github.com/lieyanc/FireID/internal/version"
)

// maxBodyBytes caps request bodies. Every JSON endpoint is small; anything
// larger is a mistake or an attack.
const maxBodyBytes = 1 << 20 // 1 MiB

// Deps is what the API server needs from the rest of the program.
type Deps struct {
	Store     *store.Store
	Auth      *auth.Service
	Config    *config.Store
	SecretBox *secretbox.Box
	Log       *slog.Logger
	Web       fs.FS
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
	deps         Deps
	mux          *http.ServeMux
	http         *http.Server
	listen       net.Listener
	oidcProvider *oidc.Provider
	// proxyWarning fires once when forwarded headers arrive but are not
	// trusted, which usually means server.trustProxyHeaders is missing.
	proxyWarning sync.Once
}

// New builds the server and its routes.
func New(deps Deps) (*Server, error) {
	if deps.Store == nil || deps.Auth == nil || deps.Config == nil || deps.SecretBox == nil {
		return nil, errors.New("api: store, auth, config and secretbox are required")
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	s := &Server{deps: deps, mux: http.NewServeMux()}

	oidcProv, err := oidc.NewProvider(deps.Store, deps.SecretBox, deps.Auth, deps.Config, deps.Log)
	if err != nil {
		return nil, fmt.Errorf("create OIDC provider: %w", err)
	}
	s.oidcProvider = oidcProv

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
//
// The OIDC provider's endpoints are exempt: they are meant to be reached from
// other sites (a form-posted logout, a browser-based client calling the token
// endpoint), and none of them acts on the session cookie alone — the token
// endpoints authenticate the client, and logout signs the browser out only for
// a valid id_token_hint naming the signed-in user.
func (s *Server) withCrossSite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !oidc.Handles(r.URL.Path) && s.crossSite(r) {
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
	h("POST /api/auth/login/totp", s.loginTOTP)
	h("POST /api/auth/login/totp/enrol", s.loginTOTPEnrol)
	h("POST /api/auth/email/start", s.emailStart)
	h("POST /api/auth/email/verify", s.emailVerify)
	h("POST /api/account/totp/enrol", s.guard(false, s.accountTOTPEnrol))
	h("POST /api/account/totp/confirm", s.guard(false, s.accountTOTPConfirm))
	h("POST /api/account/totp/disable", s.guard(false, s.accountTOTPDisable))
	h("POST /api/account/recovery-codes", s.guard(false, s.accountRecoveryCodes))
	h("POST /api/auth/login/passkey/begin", s.passkeyLoginBegin)
	h("POST /api/auth/login/passkey/finish", s.passkeyLoginFinish)
	h("POST /api/account/passkeys/begin", s.guardSession(s.accountPasskeysBegin))
	h("POST /api/account/passkeys/finish", s.guardSession(s.accountPasskeysFinish))
	h("GET /api/account/passkeys", s.guard(false, s.accountPasskeys))
	h("POST /api/account/passkeys/{id}/rename", s.guard(false, s.accountPasskeyRename))
	h("DELETE /api/account/passkeys/{id}", s.guard(false, s.accountPasskeyDelete))
	h("GET /api/account/sessions", s.guardSession(s.accountSessions))
	h("DELETE /api/account/sessions/{id}", s.guardSession(s.accountSessionRevoke))
	h("PATCH /api/account/profile", s.guard(false, s.accountProfile))
	h("POST /api/account/password", s.guardSession(s.accountPassword))

	// Administration. Per-app routes check store.CanManageApp in the handler
	// (via managedApp); group writes and app creation are super-admin only.
	h("GET /api/admin/apps", s.guard(false, s.adminApps))
	h("POST /api/admin/apps", s.guard(true, s.adminAppCreate))
	h("GET /api/admin/apps/{slug}", s.guard(false, s.adminApp))
	h("PATCH /api/admin/apps/{slug}", s.guard(false, s.adminAppUpdate))
	h("DELETE /api/admin/apps/{slug}", s.guard(false, s.adminAppDelete))
	h("POST /api/admin/apps/{slug}/secret/rotate", s.guard(false, s.adminAppRotateSecret))
	h("POST /api/admin/apps/{slug}/status", s.guard(false, s.adminAppStatus))
	h("POST /api/admin/apps/{slug}/groups", s.guard(false, s.adminAppGroups))
	h("GET /api/admin/apps/{slug}/members", s.guard(false, s.adminAppMembers))
	h("POST /api/admin/apps/{slug}/members", s.guard(false, s.adminAppMemberSet))
	h("DELETE /api/admin/apps/{slug}/members/{userId}", s.guard(false, s.adminAppMemberRemove))
	h("GET /api/admin/apps/{slug}/access-requests", s.guard(false, s.adminAppAccessRequests))
	h("POST /api/admin/apps/{slug}/access-requests/{id}/decide", s.guard(false, s.adminAccessRequestDecide))
	h("GET /api/admin/groups", s.guard(false, s.adminGroups))
	h("POST /api/admin/groups", s.guard(true, s.adminGroupCreate))
	h("PATCH /api/admin/groups/{id}", s.guard(true, s.adminGroupUpdate))
	h("DELETE /api/admin/groups/{id}", s.guard(true, s.adminGroupDelete))
	h("GET /api/admin/groups/{id}/members", s.guard(true, s.adminGroupMembers))
	h("POST /api/admin/groups/{id}/members", s.guard(true, s.adminGroupSetMembers))
	h("GET /api/admin/users/search", s.guard(false, s.adminUsersSearch))
	h("GET /api/admin/apps/{slug}/forward-auth", s.guard(false, s.adminAppForwardAuth))

	// Forward auth for apps without a login (nginx auth_request).
	fa := &forwardauth.Handler{Store: s.deps.Store, Session: s.deps.Auth.SessionUser,
		Issuer: s.deps.PublicBase, Log: s.deps.Log}
	fa.Register(s.mux)

	// The provider sends the browser here with a pending authorization
	// request; the form endpoint is the no-JavaScript sign-in for it.
	h("GET /login", s.oidcLogin)
	h("POST /oidc/login", s.oidcLoginPOST)

	// The provider's endpoints live at the root (they are relative to the
	// issuer); the UI catches everything else. Unknown /api/ paths must
	// return JSON, not the HTML shell, so a typo in the frontend fails loudly.
	s.mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if oidc.Handles(r.URL.Path) {
			s.oidcProvider.ServeHTTP(w, r)
			return
		}
		s.static(w, r)
	}))
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
		"emailLogin":    s.deps.Auth.EmailEnabled(),
	})
}

type setupRequest struct {
	Token       string `json:"setupToken"`
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
	username := req.Username
	if username == "" {
		// Default username to email local-part for setup flow
		if at := strings.Index(req.Email, "@"); at > 0 {
			username = req.Email[:at]
		}
	}
	user, err := s.deps.Store.CreateUser(store.NewUser{
		Username:     username,
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

	token, sess, err := s.deps.Auth.StartSession(&auth.LoginResult{User: user, AMR: "pwd", ACR: store.ACRLoA1},
		s.clientIP(r), r.UserAgent())
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
	// AuthReqID is set when the sign-in belongs to an authorization request.
	AuthReqID string `json:"authReqId"`
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
		var sf *auth.SecondFactorError
		switch {
		case errors.As(err, &sf):
			// The password was correct; ask for the second factor.
			writeChallenge(w, sf)
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

	s.finishLogin(w, r, res, req.AuthReqID)
}

// loginTOTP completes a sign-in that requires a second factor. The password
// is sent again and checked again: the challenge response is not a substitute
// for it, and no state is kept between the two requests.
func (s *Server) loginTOTP(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ip := s.clientIP(r)
	user, ok := s.passwordForSecondStep(w, req.Username, req.Password, ip)
	if !ok {
		return
	}
	res, err := s.deps.Auth.AuthenticateTOTP(user, req.Code, ip, "pwd")
	if err != nil {
		s.failSecondFactor(w, err)
		return
	}
	s.finishLogin(w, r, res, req.AuthReqID)
}

// loginTOTPEnrol starts the TOTP enrolment that policy demands before an
// account may finish signing in. The first code from the authenticator then
// goes to loginTOTP, which turns TOTP on and signs in.
func (s *Server) loginTOTPEnrol(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user, ok := s.passwordForSecondStep(w, req.Username, req.Password, s.clientIP(r))
	if !ok {
		return
	}
	if user.TOTPConfirmed {
		fail(w, http.StatusConflict, "totp_enabled", "two-step verification is already on; sign in with a code")
		return
	}
	secret, uri, err := s.deps.Auth.BeginEnrolment(user)
	if err != nil {
		s.failSecondFactor(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "uri": uri})
}

// passwordForSecondStep re-checks a password whose account needs a second
// step, and returns that account. Anything else is answered here.
func (s *Server) passwordForSecondStep(w http.ResponseWriter, username, password, ip string) (*store.User, bool) {
	_, err := s.deps.Auth.AuthenticatePassword(username, password, ip)
	var sf *auth.SecondFactorError
	switch {
	case errors.As(err, &sf):
		return sf.User, true
	case err == nil:
		// The second factor was turned off between the two requests.
		fail(w, http.StatusConflict, "second_factor_not_required", "this account no longer requires a second factor")
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.deps.Log.Info("failed sign-in", "username", store.NormaliseUsername(username), "ip", ip)
		fail(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
	default:
		s.failFromAuth(w, err)
	}
	return nil, false
}

// writeChallenge tells the UI which second step comes next.
func writeChallenge(w http.ResponseWriter, sf *auth.SecondFactorError) {
	challenge := "totp"
	if sf.Enrol {
		challenge = "totp_enrol"
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": challenge})
}

// failSecondFactor maps a failed second step onto a response.
func (s *Server) failSecondFactor(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		fail(w, http.StatusUnauthorized, "invalid_code", "that code is not valid")
	case errors.Is(err, auth.ErrTOTPEnabled):
		fail(w, http.StatusConflict, "totp_enabled", err.Error())
	case errors.Is(err, auth.ErrTOTPNotPending):
		fail(w, http.StatusConflict, "totp_not_pending", err.Error())
	case errors.Is(err, auth.ErrTOTPNotEnabled):
		fail(w, http.StatusConflict, "totp_not_enabled", err.Error())
	default:
		s.failFromAuth(w, err)
	}
}

// finishLogin issues the session cookie and returns the account. When the
// sign-in belongs to an authorization request, the response also says where the
// browser goes next.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, res *auth.LoginResult, authReqID string) {
	token, sess, err := s.deps.Auth.StartSession(res, s.clientIP(r), r.UserAgent())
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal_error", "could not start a session")
		return
	}
	s.deps.Auth.SetSessionCookie(w, token, sess.ExpiresAt)
	s.deps.Log.Info("sign-in", "userId", res.User.ID, "username", res.User.Username,
		"amr", res.AMR, "ip", s.clientIP(r))

	resp := map[string]any{"user": publicUser(res.User)}
	if len(res.RecoveryCodes) > 0 {
		resp["recoveryCodes"] = res.RecoveryCodes
	}
	if authReqID != "" {
		d, err := s.oidcProvider.Continue(authReqID, sess, res.User, true)
		switch {
		case errors.Is(err, oidc.ErrUnknownRequest):
			resp["authRequestError"] = "expired"
		case err != nil:
			s.deps.Log.Error("could not continue the authorization request", "err", err)
			resp["authRequestError"] = "internal_error"
		case d.NeedLogin:
			// Signed in, but not strongly enough for what the app asked.
			resp["authRequestError"] = "stronger_authentication_required"
		default:
			resp["redirectTo"] = d.Redirect
			if d.Denied != "" {
				resp["denied"] = d.Denied
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
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
	recovery := 0
	if user.TOTPConfirmed {
		if recovery, err = s.deps.Store.RecoveryCodesLeft(user.ID); err != nil {
			s.deps.Log.Error("could not count recovery codes", "userId", user.ID, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":              publicUser(user),
		"recoveryCodesLeft": recovery,
		"amr":               strings.Fields(sess.AMR),
		"acr":               sess.ACR,
		"sessionId":         sess.ID,
		"expiresAt":         sess.ExpiresAt,
		"issuer":            s.deps.PublicBase,
		"permissions":       s.permissions(user),
	})
}

// permissions summarises what the account may do, so the UI does not have to
// infer it from roles.
func (s *Server) permissions(user *store.User) map[string]bool {
	owned, err := s.deps.Store.AppsOwnedBy(user.ID)
	if err != nil {
		s.deps.Log.Error("could not list owned apps", "userId", user.ID, "err", err)
	}
	manages, err := s.managesAnyApp(user)
	if err != nil {
		s.deps.Log.Error("could not list managed apps", "userId", user.ID, "err", err)
	}
	return map[string]bool{
		"superAdmin":  user.IsSuperAdmin,
		"manageUsers": user.IsSuperAdmin,
		"manageApps":  manages,
		"ownedApps":   len(owned) > 0,
		"createApps":  user.IsSuperAdmin,
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
			// The right-most entry is the one the trusted proxy added. Entries
			// to its left came from the client and can say anything.
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if !s.deps.TrustProxyHeaders && r.Header.Get("X-Forwarded-For") != "" {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			s.proxyWarning.Do(func() {
				s.deps.Log.Warn("a reverse proxy is forwarding client addresses but server.trustProxyHeaders is off: " +
					"every client shares the proxy's address for sign-in throttling; set it to true if the proxy is the only way in")
			})
		}
	}
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

// guardSession is guard for handlers that act on the browser session itself
// (binding a passkey ceremony to it, listing or keeping it), so they also
// receive the session.
func (s *Server) guardSession(fn func(http.ResponseWriter, *http.Request, *store.Session, *store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.crossSite(r) {
			fail(w, http.StatusForbidden, "cross_site", "cross-site requests are not accepted")
			return
		}
		sess, user, err := s.deps.Auth.SessionUser(r)
		if err != nil {
			fail(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
			return
		}
		fn(w, r, sess, user)
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

// oidcLogin handles GET /login?auth_req_id=<id>, where the provider sends the
// browser with a pending authorization request. A signed-in browser whose
// session satisfies the request goes straight on; otherwise the UI shows the
// sign-in form and posts back with the same request ID.
func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_req_id")
	if authReqID == "" {
		http.Error(w, "missing auth_req_id", http.StatusBadRequest)
		return
	}
	sess, user, err := s.deps.Auth.SessionUser(r)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.deps.Log.Error("session lookup failed", "err", err)
		}
		sess, user = nil, nil
	}
	d, err := s.oidcProvider.Continue(authReqID, sess, user, false)
	if errors.Is(err, oidc.ErrUnknownRequest) {
		http.Error(w, "This sign-in request has expired. Go back to the application and try again.", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.deps.Log.Error("could not continue the authorization request", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if d.NeedLogin {
		target := "/sign-in?auth_req_id=" + url.QueryEscape(authReqID)
		if sess != nil {
			// Signed in, but not recently or strongly enough for this app.
			// The sign-in page must show the form rather than send the
			// browser straight back here.
			target += "&reauth=1"
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	http.Redirect(w, r, d.Redirect, http.StatusFound)
}

// oidcLoginPOST is the form-encoded sign-in for an authorization request:
// username, password, an optional TOTP code, and auth_req_id. It exists so a
// browser without JavaScript can still complete the flow.
func (s *Server) oidcLoginPOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "cannot parse form", http.StatusBadRequest)
		return
	}
	authReqID := r.PostFormValue("auth_req_id")
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	code := r.PostFormValue("code")
	if authReqID == "" || username == "" || password == "" {
		http.Error(w, "auth_req_id, username and password are required", http.StatusBadRequest)
		return
	}
	ip := s.clientIP(r)

	res, err := s.deps.Auth.AuthenticatePassword(username, password, ip)
	var sf *auth.SecondFactorError
	if errors.As(err, &sf) && !sf.Enrol {
		if code == "" {
			http.Error(w, "a second-factor code is required", http.StatusUnauthorized)
			return
		}
		res, err = s.deps.Auth.AuthenticateTOTP(sf.User, code, ip, "pwd")
	}
	if err != nil {
		var limited *auth.RateLimitError
		switch {
		case errors.As(err, &limited):
			w.Header().Set("Retry-After", strconv.Itoa(int(limited.RetryAfter.Seconds())+1))
			http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		case errors.Is(err, auth.ErrSecondFactorNotConfigured):
			http.Error(w, "this account must set up two-step verification in the Fire ID web interface first", http.StatusForbidden)
		case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, store.ErrNotFound):
			s.deps.Log.Info("failed sign-in", "username", store.NormaliseUsername(username), "ip", ip)
			http.Error(w, "invalid username, password or code", http.StatusUnauthorized)
		default:
			s.deps.Log.Error("sign-in failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	token, sess, err := s.deps.Auth.StartSession(res, ip, r.UserAgent())
	if err != nil {
		s.deps.Log.Error("could not start a session", "userId", res.User.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.deps.Auth.SetSessionCookie(w, token, sess.ExpiresAt)
	s.deps.Log.Info("sign-in", "userId", res.User.ID, "username", res.User.Username, "amr", res.AMR, "ip", ip)

	d, err := s.oidcProvider.Continue(authReqID, sess, res.User, true)
	switch {
	case errors.Is(err, oidc.ErrUnknownRequest):
		http.Error(w, "You are signed in, but this sign-in request has expired. Go back to the application and try again.", http.StatusBadRequest)
	case err != nil:
		s.deps.Log.Error("could not continue the authorization request", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	case d.NeedLogin:
		http.Error(w, "This application requires a stronger sign-in, such as a second factor.", http.StatusForbidden)
	default:
		http.Redirect(w, r, d.Redirect, http.StatusSeeOther)
	}
}
