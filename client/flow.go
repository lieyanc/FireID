package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	// loginTTL bounds how long a login may take between the redirect to the
	// provider and the callback.
	loginTTL = 10 * time.Minute
	// maxReturnPath bounds the return path kept in the login cookie, which
	// has to fit in a cookie alongside state, nonce and verifier.
	maxReturnPath = 2048
	// maxLoginCookie bounds the login cookie read back.
	maxLoginCookie = 4096
)

// LoginResult is what the callback handler hands to OnLogin.
type LoginResult struct {
	// Claims are the verified ID token claims; Claims.SID is what a
	// back-channel logout token will name.
	Claims *IDTokenClaims
	// Tokens hold the access token (for UserInfoFor), the refresh token when
	// offline_access was granted, and the raw ID token for EndSessionURL.
	Tokens *Tokens
	// ReturnTo is the local path the login started from, already checked
	// to be one: it starts with a single slash and has no scheme or host.
	ReturnTo string
}

// FlowConfig configures LoginHandler and CallbackHandler. The same value
// should be passed to both.
type FlowConfig struct {
	// OnLogin is called after a successful callback. It must create the
	// application's own session and write the response, typically a
	// redirect to res.ReturnTo. An error, returned before anything was
	// written, makes the handler answer 500 through ErrorHandler.
	OnLogin func(w http.ResponseWriter, r *http.Request, res *LoginResult) error
	// ErrorHandler renders a failed callback. The default writes a short
	// text/plain page with the status ErrorStatus gives and logs nothing;
	// supply one to log, or to render the application's own page.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
	// CookieName is the login cookie's name. The default is
	// __Host-fireid_rp_<8 hex digits> when the RedirectURL is https and the
	// same without the prefix when it is http (browsers refuse __Host-
	// without Secure); the digits come from a hash of Issuer and ClientID.
	// A name of your own must likewise be distinct for every Client an
	// application has: with a shared name, a login started at one
	// provider could be finished at another's callback, which the callback
	// refuses only because the cookie also records which Client wrote it.
	CookieName string
	// AuthOptions are added to every authorization request.
	AuthOptions []AuthOption
}

// loginState is the login cookie's content: what the callback needs to
// finish the login the browser started, and which Client started it.
type loginState struct {
	Issuer   string `json:"iss"`
	ClientID string `json:"client_id"`
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Return   string `json:"return"`
	Created  int64  `json:"created"`
}

// LoginHandler starts a login: GET /login?return=/some/path. It generates
// state, nonce and PKCE verifier, keeps them with the return path in a
// short-lived HttpOnly cookie, and redirects the browser to the provider.
//
// The cookie is not signed. A signature would not stop login CSRF — an
// attacker can start their own login and obtain a validly signed cookie —
// so integrity rests on the __Host- prefix, which no other host or
// subdomain can set, together with the state comparison in the callback.
// On a plain-http RedirectURL (development on loopback) the prefix is not
// available and a sibling host could plant the cookie; do not deploy that.
// The verifier sits in the person's own browser, as RFC 7636 intends.
//
// The cookie also records the issuer and client ID, and the callback
// finishes only a login its own Client started. An application with two
// Clients — two providers, or two registrations — would otherwise let a
// login begun at one provider end at the other's callback, where an
// attacker who controls the first provider knows the state and nonce the
// second one will see.
//
// Starting a second login in another tab replaces the cookie: the newest
// login wins and an older tab's callback fails with ErrStateMismatch.
//
// return is accepted only as a local absolute path — a single leading
// slash, no scheme or host; anything else becomes "/".
func (c *Client) LoginHandler(fc FlowConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		st := loginState{
			Issuer:   c.cfg.Issuer,
			ClientID: c.cfg.ClientID,
			State:    RandomString(),
			Nonce:    RandomString(),
			Verifier: NewPKCEVerifier(),
			Return:   localPath(r.URL.Query().Get("return")),
			Created:  c.now().Unix(),
		}
		value, err := json.Marshal(st)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     c.cookieName(fc),
			Value:    base64.RawURLEncoding.EncodeToString(value),
			Path:     "/",
			MaxAge:   int(loginTTL / time.Second),
			HttpOnly: true,
			Secure:   c.secure,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, c.AuthCodeURL(st.State, st.Nonce, st.Verifier, fc.AuthOptions...), http.StatusFound)
	})
}

// CallbackHandler finishes a login at the RedirectURL's path. It requires a
// GET whose login cookie this Client wrote and whose state equals the
// cookie's (compared in constant time), checks the iss parameter against
// the issuer when present — and requires it when the provider advertises
// RFC 9207 — reports an error response as an *AuthError, exchanges the code
// with the PKCE verifier, verifies the ID token with the nonce, clears the
// cookie and calls fc.OnLogin.
func (c *Client) CallbackHandler(fc FlowConfig) http.Handler {
	fail := fc.ErrorHandler
	if fail == nil {
		fail = defaultErrorHandler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		name := c.cookieName(fc)
		st, err := readLoginCookie(r, name)
		if err != nil {
			fail(w, r, err)
			return
		}
		if st.Issuer != c.cfg.Issuer || st.ClientID != c.cfg.ClientID {
			// Another Client's login under a shared cookie name; its cookie
			// is left for that Client's callback.
			fail(w, r, fmt.Errorf("%w: login cookie belongs to another client", ErrStateMismatch))
			return
		}
		if state := q.Get("state"); state == "" || !constantTimeEqual(state, st.State) {
			fail(w, r, fmt.Errorf("%w: state does not match the login cookie", ErrStateMismatch))
			return
		}
		if age := c.now().Unix() - st.Created; age < 0 || age > int64(loginTTL/time.Second) {
			fail(w, r, fmt.Errorf("%w: login started too long ago", ErrStateMismatch))
			return
		}
		// From here on the callback belongs to this login, whatever its
		// outcome, so the cookie is done.
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteLaxMode,
		})
		if iss, ok := q["iss"]; ok {
			if len(iss) != 1 || iss[0] != c.cfg.Issuer {
				fail(w, r, fmt.Errorf("%w: iss parameter %q", ErrIssuerMismatch, q.Get("iss")))
				return
			}
		} else if c.provider.IssuerParameterSupported {
			fail(w, r, fmt.Errorf("%w: no iss parameter from a provider that sends one", ErrIssuerMismatch))
			return
		}
		if code := q.Get("error"); code != "" {
			fail(w, r, &AuthError{Code: code, Description: q.Get("error_description")})
			return
		}
		code := q.Get("code")
		if code == "" {
			fail(w, r, fmt.Errorf("%w: neither code nor error", ErrBadCallback))
			return
		}
		tokens, err := c.Exchange(r.Context(), code, st.Verifier, WithNonce(st.Nonce))
		if err != nil {
			fail(w, r, err)
			return
		}
		res := &LoginResult{Claims: tokens.Claims, Tokens: tokens, ReturnTo: st.Return}
		if err := fc.OnLogin(w, r, res); err != nil {
			fail(w, r, fmt.Errorf("client: OnLogin: %w", err))
		}
	})
}

// cookieName is fc.CookieName or this Client's default.
func (c *Client) cookieName(fc FlowConfig) string {
	if fc.CookieName != "" {
		return fc.CookieName
	}
	return c.cookie
}

// defaultCookieName names the login cookie for one Client: a hash of the
// issuer and client ID makes the suffix, so two Clients on one host never
// read each other's cookie, and the __Host- prefix goes on when the
// RedirectURL is https.
func defaultCookieName(issuer, clientID string, secure bool) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + clientID))
	name := "fireid_rp_" + hex.EncodeToString(sum[:4])
	if secure {
		return "__Host-" + name
	}
	return name
}

// readLoginCookie decodes the login cookie. Any problem is ErrStateMismatch:
// without a usable cookie no login this browser started can be finished.
func readLoginCookie(r *http.Request, name string) (*loginState, error) {
	ck, err := r.Cookie(name)
	if err != nil {
		return nil, fmt.Errorf("%w: no login cookie", ErrStateMismatch)
	}
	if len(ck.Value) > maxLoginCookie {
		return nil, fmt.Errorf("%w: login cookie too large", ErrStateMismatch)
	}
	raw, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed login cookie", ErrStateMismatch)
	}
	var st loginState
	if err := json.Unmarshal(raw, &st); err != nil || st.State == "" || st.Nonce == "" || st.Verifier == "" {
		return nil, fmt.Errorf("%w: malformed login cookie", ErrStateMismatch)
	}
	st.Return = localPath(st.Return)
	return &st, nil
}

// localPath returns p when it is a local absolute path and "/" otherwise.
// Local means a single leading slash: "//host" and "/\host" are what
// browsers read as scheme-relative URLs, so both are refused, as is
// anything with a control character or beyond maxReturnPath bytes.
func localPath(p string) string {
	if p == "" || p[0] != '/' || len(p) > maxReturnPath {
		return "/"
	}
	if len(p) > 1 && (p[1] == '/' || p[1] == '\\') {
		return "/"
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return "/"
		}
	}
	return p
}

// ErrorStatus is the HTTP status for a callback failure, as the default
// ErrorHandler uses it: 400 for a request that does not match a login this
// browser started or is otherwise malformed (ErrStateMismatch,
// ErrIssuerMismatch, ErrBadCallback), 403 when the provider answered
// access_denied, 502 when the provider failed or sent a token that does not
// verify (ErrProvider, *TokenError, ErrInvalidToken, a provider-side
// *AuthError), and 500 for anything else, such as an OnLogin error.
func ErrorStatus(err error) int {
	var ae *AuthError
	if errors.As(err, &ae) {
		switch ae.Code {
		case "access_denied":
			return http.StatusForbidden
		case "server_error", "temporarily_unavailable":
			return http.StatusBadGateway
		default:
			return http.StatusBadRequest
		}
	}
	var te *TokenError
	switch {
	case errors.As(err, &te), errors.Is(err, ErrProvider), errors.Is(err, ErrInvalidToken):
		return http.StatusBadGateway
	case errors.Is(err, ErrStateMismatch), errors.Is(err, ErrIssuerMismatch), errors.Is(err, ErrBadCallback):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// defaultErrorHandler writes a short plain-text page. It repeats nothing
// from the request: an error_description is the provider's — or a forged
// callback's — text and does not belong on the application's page.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	status := ErrorStatus(err)
	var msg string
	switch status {
	case http.StatusBadRequest:
		msg = "Sign-in failed: this request does not match a sign-in started in this browser. Go back and try again."
	case http.StatusForbidden:
		msg = "Sign-in was refused."
	case http.StatusBadGateway:
		msg = "The sign-in service did not answer correctly. Try again in a moment."
	default:
		msg = "Something went wrong during sign-in. Try again."
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	fmt.Fprintln(w, msg)
}
