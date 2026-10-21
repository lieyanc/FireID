// Package forwardauth protects applications that have no login of their own,
// through nginx auth_request (DESIGN §7).
//
// The IdP session cookie never leaves the IdP's host. Each protected app gets
// its own session cookie, set on the app's host through a short hop:
//
//  1. nginx asks GET /api/authz/forward on every request. Without a valid app
//     cookie the answer is 401 with Location pointing at /__fireid/start on the
//     app's host.
//  2. /__fireid/start (proxied to /api/authz/app/start) sets a state cookie on
//     the app's host and sends the browser to the IdP's /api/authz/authorize.
//  3. The IdP checks its own session and store.CanUseApp, then sends the
//     browser back to /__fireid/callback with a one-time code bound to the
//     app, the app's origin and the state cookie.
//  4. The callback redeems the code and sets the app's session cookie, which
//     lives only as long as the IdP session it came from.
//
// The app's host must have <origin>/__fireid/callback among the app's
// redirect URIs, so an owner can only point forward auth at hosts they
// registered.
package forwardauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lieyanc/FireID/internal/store"
)

// Paths on the protected app's host. nginx proxies PathPrefix to
// /api/authz/app/ and keeps AuthzPath internal.
const (
	PathPrefix   = "/__fireid/"
	AuthzPath    = "/__fireid/authz"
	StartPath    = "/__fireid/start"
	CallbackPath = "/__fireid/callback"
	LogoutPath   = "/__fireid/logout"
)

// Headers nginx sets on the subrequest and the proxied /__fireid/ paths.
const (
	headerApp         = "X-FireID-App"
	headerOriginalURL = "X-Original-URL"
)

// stateTTL bounds how long a sign-in may take between start and callback.
const stateTTL = 10 * time.Minute

// Handler serves the forward-auth endpoints.
type Handler struct {
	Store *store.Store
	// Session resolves the IdP session cookie of a request on the IdP's host.
	Session func(*http.Request) (*store.Session, *store.User, error)
	// Issuer is the IdP's public base URL.
	Issuer string
	Log    *slog.Logger
}

// Register adds the endpoints to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/authz/forward", h.Forward)
	mux.HandleFunc("GET /api/authz/authorize", h.Authorize)
	mux.HandleFunc("GET /api/authz/app/start", h.Start)
	mux.HandleFunc("GET /api/authz/app/callback", h.Callback)
	// GET only: a POST from the app's host would be refused as cross-site.
	mux.HandleFunc("GET /api/authz/app/logout", h.Logout)
}

// appContext is what nginx tells FireID about a request on the app's host.
type appContext struct {
	app    *store.App
	orig   *url.URL // the URL the browser asked for
	origin string   // scheme://host of the app
	secure bool
}

// fromProxy reads the app and the original URL nginx sets. Both are
// overwritten by the include on every request, so a client cannot choose them.
func (h *Handler) fromProxy(r *http.Request) (*appContext, error) {
	slug := r.Header.Get(headerApp)
	if slug == "" {
		return nil, errors.New("no " + headerApp + " header: is the nginx include in place?")
	}
	app, err := h.Store.AppBySlug(slug)
	if err != nil {
		return nil, fmt.Errorf("app %q: %w", slug, err)
	}
	orig, err := absoluteURL(r.Header.Get(headerOriginalURL))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", headerOriginalURL, err)
	}
	return &appContext{app: app, orig: orig, origin: originOf(orig), secure: orig.Scheme == "https"}, nil
}

// Forward answers nginx's auth_request subrequest: 204 with identity headers,
// 401 with Location to start a sign-in, or 403.
func (h *Handler) Forward(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ac, err := h.fromProxy(r)
	if err != nil {
		h.Log.Error("forward auth misconfigured", "err", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var token string
	if c, err := r.Cookie(sessionCookie(ac.secure)); err == nil {
		token = c.Value
	}
	_, user, err := h.Store.ForwardSessionUser(token, ac.app.ID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			h.Log.Error("forward session lookup failed", "app", ac.app.Slug, "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Location", ac.origin+StartPath+"?rd="+url.QueryEscape(ac.orig.String()))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	access, err := h.Store.CanUseApp(ac.app, user)
	if err != nil {
		h.Log.Error("access check failed", "app", ac.app.Slug, "userId", user.ID, "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !access.Allowed {
		w.Header().Set("X-FireID-Denied", access.Reason)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	groups, err := h.Store.UserGroupNames(user.ID)
	if err != nil {
		h.Log.Error("group lookup failed", "userId", user.ID, "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	hd := w.Header()
	hd.Set("X-FireID-User", user.Username)
	hd.Set("X-FireID-Email", user.Email)
	hd.Set("X-FireID-Name", user.DisplayName)
	hd.Set("X-FireID-Groups", strings.Join(groups, ","))
	hd.Set("X-FireID-Sub", strconv.FormatInt(user.ID, 10))
	w.WriteHeader(http.StatusNoContent)
}

// Start runs on the app's host: it sets the state cookie and sends the
// browser to the IdP.
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	ac, err := h.fromProxy(r)
	if err != nil {
		h.Log.Error("forward auth misconfigured", "err", err)
		page(w, http.StatusBadRequest, "This site's sign-in is not set up correctly.")
		return
	}
	if !h.hostRegistered(ac) {
		page(w, http.StatusBadRequest, "This site is not registered for sign-in with this application.")
		return
	}
	state, err := randomToken()
	if err != nil {
		h.Log.Error("state generation failed", "err", err)
		page(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie(ac.secure), Value: state, Path: "/", MaxAge: int(stateTTL / time.Second),
		HttpOnly: true, Secure: ac.secure, SameSite: http.SameSiteLaxMode,
	})
	q := url.Values{
		"app":   {ac.app.Slug},
		"state": {state},
		"rd":    {sameOriginOr(r.URL.Query().Get("rd"), ac.origin)},
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, h.Issuer+"/api/authz/authorize?"+q.Encode(), http.StatusFound)
}

// Authorize runs on the IdP's host: it checks the IdP session and the app's
// access rules and hands the browser a one-time code for the app's host.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	sess, user, err := h.Session(r)
	if err != nil {
		http.Redirect(w, r, "/sign-in?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	app, err := h.Store.AppBySlug(q.Get("app"))
	if err != nil {
		page(w, http.StatusBadRequest, "Unknown application.")
		return
	}
	state := q.Get("state")
	if state == "" || len(state) > 128 {
		page(w, http.StatusBadRequest, "The sign-in request is incomplete. Go back to the site and try again.")
		return
	}
	rd, err := absoluteURL(q.Get("rd"))
	if err != nil {
		page(w, http.StatusBadRequest, "The sign-in request is incomplete. Go back to the site and try again.")
		return
	}
	ac := &appContext{app: app, orig: rd, origin: originOf(rd)}
	if !h.hostRegistered(ac) {
		page(w, http.StatusBadRequest, "This site is not registered for sign-in with this application.")
		return
	}
	access, err := h.Store.CanUseApp(app, user)
	if err != nil {
		h.Log.Error("access check failed", "app", app.Slug, "userId", user.ID, "err", err)
		page(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	if !access.Allowed {
		h.Log.Info("forward auth refused", "app", app.Slug, "userId", user.ID, "reason", access.Reason)
		http.Redirect(w, r, "/denied?"+url.Values{"app": {app.Name}, "reason": {access.Reason}}.Encode(),
			http.StatusFound)
		return
	}
	code, err := randomToken()
	if err == nil {
		err = h.Store.CreateForwardCode(code, app.ID, sess.ID, store.HashToken(state), ac.origin, rd.String())
	}
	if err != nil {
		h.Log.Error("forward code failed", "app", app.Slug, "err", err)
		page(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	http.Redirect(w, r, ac.origin+CallbackPath+"?code="+url.QueryEscape(code), http.StatusFound)
}

// Callback runs on the app's host: it redeems the code and sets the app's
// session cookie.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ac, err := h.fromProxy(r)
	if err != nil {
		h.Log.Error("forward auth misconfigured", "err", err)
		page(w, http.StatusBadRequest, "This site's sign-in is not set up correctly.")
		return
	}
	expired := func() {
		page(w, http.StatusBadRequest, "This sign-in link has expired or was already used. Reload the page you wanted to open.")
	}
	fc, err := h.Store.ConsumeForwardCode(r.URL.Query().Get("code"), ac.app.ID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			h.Log.Error("forward code lookup failed", "err", err)
		}
		expired()
		return
	}
	// The code is redeemable only on the host it was issued for, and only by
	// the browser that started the sign-in.
	state, _ := r.Cookie(stateCookie(ac.secure))
	if !strings.EqualFold(fc.Origin, ac.origin) || state == nil ||
		subtle.ConstantTimeCompare([]byte(store.HashToken(state.Value)), []byte(fc.StateHash)) != 1 {
		h.Log.Warn("forward code refused: origin or state mismatch", "app", ac.app.Slug)
		expired()
		return
	}
	token, err := randomToken()
	if err != nil {
		page(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	fs, err := h.Store.CreateForwardSession(token, ac.app.ID, fc.SessionID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			h.Log.Error("forward session failed", "err", err)
		}
		expired()
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie(ac.secure), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: ac.secure, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie(ac.secure), Value: token, Path: "/", Expires: fs.ExpiresAt,
		HttpOnly: true, Secure: ac.secure, SameSite: http.SameSiteLaxMode,
	})
	h.Log.Info("forward session started", "app", ac.app.Slug, "userId", fs.UserID)
	http.Redirect(w, r, sameOriginOr(fc.ReturnURL, ac.origin), http.StatusFound)
}

// Logout ends the app's session on its host. The IdP session is untouched;
// signing out everywhere happens at the IdP.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ac, err := h.fromProxy(r)
	if err != nil {
		h.Log.Error("forward auth misconfigured", "err", err)
		page(w, http.StatusBadRequest, "This site's sign-in is not set up correctly.")
		return
	}
	if c, err := r.Cookie(sessionCookie(ac.secure)); err == nil && c.Value != "" {
		if err := h.Store.DeleteForwardSession(c.Value); err != nil {
			h.Log.Error("forward sign-out failed", "err", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie(ac.secure), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: ac.secure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, sameOriginOr(r.URL.Query().Get("rd"), ac.origin), http.StatusFound)
}

// hostRegistered reports whether the app registered <origin>/__fireid/callback
// as a redirect URI, which is what entitles a host to forward auth.
func (h *Handler) hostRegistered(ac *appContext) bool {
	ok := store.MatchesRedirectURI(ac.app.RedirectURIs, ac.origin+CallbackPath)
	if !ok {
		h.Log.Warn("forward auth host not registered", "app", ac.app.Slug, "origin", ac.origin)
	}
	return ok
}

// sessionCookie and stateCookie are the cookie names on the app's host. On
// HTTPS the __Host- prefix stops a sibling subdomain from planting either.
func sessionCookie(secure bool) string {
	if secure {
		return "__Host-fireid_app"
	}
	return "fireid_app"
}

func stateCookie(secure bool) string {
	if secure {
		return "__Host-fireid_state"
	}
	return "fireid_state"
}

// absoluteURL parses an absolute http(s) URL without user information.
func absoluteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%q is not an absolute http(s) URL", raw)
	}
	return u, nil
}

func originOf(u *url.URL) string { return strings.ToLower(u.Scheme + "://" + u.Host) }

// sameOriginOr returns raw when it is an absolute URL on origin, and the
// origin's root otherwise, so no redirect leaves the app's host.
func sameOriginOr(raw, origin string) string {
	u, err := absoluteURL(raw)
	if err != nil || originOf(u) != origin {
		return origin + "/"
	}
	return u.String()
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// page writes a short plain-text answer for the browser.
func page(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	fmt.Fprintln(w, msg)
}
