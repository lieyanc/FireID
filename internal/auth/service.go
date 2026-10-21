package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lieyanc/FireID/internal/secretbox"
	"github.com/lieyanc/FireID/internal/store"
)

// SessionCookie is the name of the browser session cookie. The __Host- prefix
// is used when the cookie is host-only, which forbids a Domain attribute and
// prevents a subdomain from overwriting it.
const SessionCookie = "fireid_session"

// HostSessionCookie is the variant used when auth.cookieDomain is empty and the
// deployment is on HTTPS.
const HostSessionCookie = "__Host-fireid_session"

// Service wires the credential checks to the store.
type Service struct {
	store *store.Store
	box   *secretbox.Box
	cfg   Config
	log   *slog.Logger
	login *Throttle
	// mailAddr and mailIP limit how many sign-in emails go to one address
	// and are requested from one source.
	mailAddr *Throttle
	mailIP   *Throttle
	mailer   Mailer
	// setup is the one-time setup token; setupMu guards it and is held for
	// the whole of a setup attempt, so one token cannot create two accounts.
	setupMu sync.Mutex
	setup   string
	issuer  string
	// mailWG tracks deliveries in flight, so tests can wait for them.
	mailWG sync.WaitGroup
	// ceremonies holds the pending WebAuthn exchanges.
	ceremonies *ceremonies

	now func() time.Time
}

// Config is the slice of the application configuration that authentication
// needs. Passing a struct rather than the whole config keeps this package free
// of a dependency on the configuration package.
type Config struct {
	SessionTTL                   time.Duration
	CookieDomain                 string
	PasswordMinLength            int
	RequireSecondFactorForAdmins bool
	// SecureCookies forces the Secure attribute; set it when the public URL is
	// HTTPS, even if the listener itself is plaintext behind the proxy.
	SecureCookies bool
	// Registration is "closed" or "open".
	Registration string
}

// New builds the authentication service. It generates a one-time setup token
// when no account exists yet, or when recovery is enabled.
func New(st *store.Store, box *secretbox.Box, cfg Config, log *slog.Logger) (*Service, error) {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 7 * 24 * time.Hour
	}
	if cfg.PasswordMinLength < 8 {
		cfg.PasswordMinLength = 8
	}
	s := &Service{
		store: st,
		box:   box,
		cfg:   cfg,
		log:   log,
		login: NewThrottle(ThrottleOptions{}),
		// Each email counts as it is sent, and the one that crosses the free
		// allowance still goes out: three per address, ten per source, then
		// a lockout that doubles.
		mailAddr: NewThrottle(ThrottleOptions{Free: 2}),
		mailIP:   NewThrottle(ThrottleOptions{Free: 9}),
		now:      func() time.Time { return time.Now().UTC() },
	}
	s.ceremonies = newCeremonies(s.now)
	if err := s.refreshSetupToken(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetIssuer records the public base URL, used to build links in emails.
func (s *Service) SetIssuer(issuer string) { s.issuer = strings.TrimSuffix(issuer, "/") }

// SetupToken returns the current setup token, or "" when setup is not
// available. The token is held in memory only: it is never written to disk and
// never logged anywhere except the one startup line.
func (s *Service) SetupToken() string {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.setup
}

// refreshSetupToken (re)generates the token when the deployment still needs it.
func (s *Service) refreshSetupToken() error {
	users, err := s.store.CountUsers()
	if err != nil {
		return err
	}
	hasAdmin, err := s.store.HasSuperAdmin()
	if err != nil {
		return err
	}
	if users > 0 && hasAdmin {
		s.setup = ""
		return nil
	}
	tok, err := randomToken(16)
	if err != nil {
		return err
	}
	s.setup = tok
	return nil
}

// EnableRecovery clears the setup token so the next start mints a fresh one.
// It is used by -reset-auth.
func (s *Service) EnableRecovery() error {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	s.setup = ""
	return s.refreshSetupToken()
}

// ErrSetupUnavailable is returned when the setup token is not active.
var ErrSetupUnavailable = errors.New("setup is not available")

// ErrSecondFactorRequired is returned when the account must present a second
// factor but the request did not.
var ErrSecondFactorRequired = errors.New("second factor required")

// ErrSecondFactorNotConfigured is returned when a policy demands a second
// factor the account has not enrolled.
var ErrSecondFactorNotConfigured = errors.New("second factor is required but not enrolled")

// SecondFactorError reports a correct first factor that is not enough on its
// own. It matches ErrSecondFactorRequired, and also ErrSecondFactorNotConfigured
// when the account still has to enrol.
type SecondFactorError struct {
	User  *store.User
	Enrol bool
}

func (e *SecondFactorError) Error() string {
	if e.Enrol {
		return ErrSecondFactorNotConfigured.Error()
	}
	return ErrSecondFactorRequired.Error()
}

func (e *SecondFactorError) Is(target error) bool {
	return target == ErrSecondFactorRequired || (e.Enrol && target == ErrSecondFactorNotConfigured)
}

// LoginResult is what a credential check produces before a session exists.
type LoginResult struct {
	User *store.User
	// AMR lists the methods used, e.g. "pwd" or "pwd otp".
	AMR string
	ACR string
	// RecoveryCodes is set when the sign-in also completed a TOTP enrolment.
	// They are shown to the person once and never stored in plain form.
	RecoveryCodes []string
}

// AuthenticatePassword checks a username and password. It never reveals whether
// the account exists: an unknown username still costs a full verification.
func (s *Service) AuthenticatePassword(username, password, ip string) (*LoginResult, error) {
	username = store.NormaliseUsername(username)

	if wait := s.login.RetryAfter("login:" + ip); wait > 0 {
		return nil, &RateLimitError{RetryAfter: wait}
	}
	if wait := s.login.RetryAfter("acct:" + username); wait > 0 {
		return nil, &RateLimitError{RetryAfter: wait}
	}

	user, err := s.store.UserByUsername(username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			VerifyDummy(password)
			s.recordFailure(nil, username, ip)
			return nil, signInFailure(nil, "unknown_account")
		}
		return nil, err
	}

	if user.PasswordHash == "" || user.Status != store.UserActive {
		VerifyDummy(password)
		s.recordFailure(user, username, ip)
		reason := "no_password"
		if user.Status != store.UserActive {
			reason = "account_" + user.Status
		}
		return nil, signInFailure(user, reason)
	}

	if err := VerifyPassword(password, user.PasswordHash); err != nil {
		s.recordFailure(user, username, ip)
		return nil, signInFailure(user, "wrong_password")
	}

	// A hash created with weaker parameters is upgraded in place.
	if NeedsRehash(user.PasswordHash) {
		if hash, err := HashPassword(password); err == nil {
			if err := s.store.SetPassword(user.ID, hash); err != nil {
				s.log.Warn("could not upgrade password hash", "userId", user.ID, "err", err)
			}
		}
	}

	s.login.Reset("login:" + ip)
	s.login.Reset("acct:" + username)

	if s.needsSecondFactor(user) {
		return nil, &SecondFactorError{User: user, Enrol: !user.TOTPConfirmed}
	}

	return &LoginResult{User: user, AMR: "pwd", ACR: store.ACRLoA1}, nil
}

// StartSession turns a successful login into a session and returns the cookie
// value to set.
func (s *Service) StartSession(res *LoginResult, ip, userAgent string) (string, *store.Session, error) {
	token, sess, err := s.store.CreateSession(res.User.ID, s.cfg.SessionTTL, ip, userAgent, res.AMR, res.ACR)
	if err != nil {
		return "", nil, err
	}
	if err := s.store.TouchLogin(res.User.ID); err != nil {
		s.log.Warn("could not record last login", "userId", res.User.ID, "err", err)
	}
	return token, sess, nil
}

// SessionUser resolves a request's session cookie to a session and account.
func (s *Service) SessionUser(r *http.Request) (*store.Session, *store.User, error) {
	token := s.SessionTokenFromRequest(r)
	if token == "" {
		return nil, nil, store.ErrNotFound
	}
	return s.store.SessionUser(token)
}

// SessionTokenFromRequest reads the session cookie. Only the configured name
// is accepted: honouring the plain name as well would let a sibling subdomain
// plant a cookie and defeat the __Host- prefix.
func (s *Service) SessionTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		return c.Value
	}
	return ""
}

// cookieName is the session cookie's name. A host-only cookie on HTTPS gets
// the __Host- prefix, which browsers only accept without a Domain, with
// Secure and with Path=/ — so no other host can set or shadow it.
func (s *Service) cookieName() string {
	if s.cfg.CookieDomain == "" && s.cfg.SecureCookies {
		return HostSessionCookie
	}
	return SessionCookie
}

// SetSessionCookie writes the session cookie. SameSite=Lax is enough because
// the OAuth endpoints are reached by top-level navigation, and the UI's own
// state-changing calls are same-site.
func (s *Service) SetSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    token,
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie removes the cookie. A host-only HTTPS deployment also
// clears the plain name, which builds before the __Host- prefix used and
// which is no longer read.
func (s *Service) ClearSessionCookie(w http.ResponseWriter) {
	names := []string{s.cookieName()}
	if names[0] != SessionCookie {
		names = append(names, SessionCookie)
	}
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Domain:   s.cfg.CookieDomain,
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   s.cfg.SecureCookies,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

// SignOutByRequest revokes the session the request carries.
func (s *Service) SignOutByRequest(r *http.Request) error {
	token := s.SessionTokenFromRequest(r)
	if token == "" {
		return nil
	}
	return s.store.RevokeSessionByToken(token)
}

// BeginSetup compares a submitted setup token in constant time and, when it
// matches, holds the setup until done is called: done(true) spends the token,
// done(false) leaves it for another attempt. Concurrent attempts wait, so the
// second one finds the token spent rather than creating a second account.
func (s *Service) BeginSetup(submitted string) (done func(used bool), err error) {
	s.setupMu.Lock()
	if s.setup == "" {
		s.setupMu.Unlock()
		return nil, ErrSetupUnavailable
	}
	if subtle.ConstantTimeCompare([]byte(s.setup), []byte(submitted)) != 1 {
		s.setupMu.Unlock()
		return nil, ErrInvalidCredentials
	}
	var once sync.Once
	return func(used bool) {
		once.Do(func() {
			if used {
				s.setup = ""
			}
			s.setupMu.Unlock()
		})
	}, nil
}

// RegisterResult is what a self-registration produces.
type RegisterResult struct {
	User *store.User
	// Token is the email-verification token, returned so the caller can put it
	// in a link. It is never logged.
	Token string
}

// Register creates a self-registered account. Every new account starts pending
// until its address is verified, unless email is not configured at all, in
// which case the operator has accepted that addresses are unverified.
func (s *Service) Register(username, email, displayName, password, ip string) (*RegisterResult, error) {
	if s.cfg.Registration != "open" {
		return nil, fmt.Errorf("%w: self-registration is disabled", ErrForbidden)
	}
	if err := s.checkPassword(password); err != nil {
		return nil, err
	}
	if wait := s.login.RetryAfter("register:" + ip); wait > 0 {
		return nil, &RateLimitError{RetryAfter: wait}
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	user, err := s.store.CreateUser(store.NewUser{
		Username:     username,
		Email:        email,
		DisplayName:  displayName,
		PasswordHash: hash,
		Status:       store.UserPending,
	})
	if err != nil {
		s.login.Fail("register:" + ip)
		return nil, err
	}
	return &RegisterResult{User: user}, nil
}

// checkPassword enforces the configured minimum length and a small amount of
// obvious-strength sanity.
func (s *Service) checkPassword(password string) error {
	if len([]rune(password)) < s.cfg.PasswordMinLength {
		return fmt.Errorf("%w: password must be at least %d characters", ErrInvalidPassword, s.cfg.PasswordMinLength)
	}
	if len(password) > 1024 {
		return fmt.Errorf("%w: password must be at most 1024 characters", ErrInvalidPassword)
	}
	return nil
}

// CheckPassword exposes the password policy to the API layer.
func (s *Service) CheckPassword(password string) error { return s.checkPassword(password) }

// recordFailure counts a failed sign-in against both the source address and the
// account, so neither a single noisy address nor a distributed attack on one
// account goes unthrottled. user is the account the username named, or nil.
func (s *Service) recordFailure(user *store.User, username, ip string) {
	if lock := s.login.Fail("login:" + ip); lock > 0 {
		s.log.Warn("login throttled by source", "ip", ip, "lockout", lock.String())
		s.lockedOut(user, "password", "source", ip, lock)
	}
	if lock := s.login.Fail("acct:" + username); lock > 0 {
		// The attempted name is not logged: it may be a password typed into
		// the wrong field. An unknown name is reported as such.
		account := any("unknown")
		if user != nil {
			account = user.ID
		}
		s.log.Warn("login throttled by account", "userId", account, "lockout", lock.String())
		s.lockedOut(user, "password", "account", ip, lock)
	}
}

// lockedOut records a throttle lock-out in the audit log. user is the account
// the failed attempt named, or nil; an attempted username that names no
// account is never recorded, since it may be a mistyped password.
func (s *Service) lockedOut(user *store.User, method, scope, ip string, lock time.Duration) {
	var userID int64
	if user != nil {
		userID = user.ID
	}
	s.audit(store.AuditEvent{
		Event: "auth.locked", Severity: store.SeverityWarning, ActorType: store.ActorSystem,
		UserID: userID, IP: ip,
		Detail: map[string]any{"method": method, "scope": scope, "lockoutSeconds": int(lock.Seconds())},
	})
}

// audit records an event. It is best effort: a failure is logged, never
// returned.
func (s *Service) audit(e store.AuditEvent) {
	if err := s.store.Audit(e); err != nil {
		s.log.Warn("could not record audit event", "event", e.Event, "err", err)
	}
}

// randomToken returns a URL-safe random token of n random bytes.
func randomToken(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// RateLimitError carries the wait a caller must observe.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("too many attempts; retry in %d seconds", int(e.RetryAfter.Seconds())+1)
}

// RegistrationMode reports the deployment-wide self-registration policy, so the
// UI can hide the sign-up form when it is closed.
func (s *Service) RegistrationMode() string {
	if s.cfg.Registration == "" {
		return "closed"
	}
	return s.cfg.Registration
}

// SessionTTL is the configured session lifetime.
func (s *Service) SessionTTL() time.Duration { return s.cfg.SessionTTL }
