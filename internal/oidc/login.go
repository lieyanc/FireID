package oidc

import (
	"errors"
	"net/url"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/lieyanc/FireID/internal/store"
)

// ErrUnknownRequest is returned when an authorization request does not exist
// or has expired. The login page tells the person to start again from the app.
var ErrUnknownRequest = errors.New("this sign-in request is unknown or has expired")

// Decision is what the login page does next with a pending request.
type Decision struct {
	// NeedLogin means the person must sign in (again) before the request can
	// proceed: there is no session, it is older than max_age or prompt=login
	// allows, or its authentication level is below acr_values.
	NeedLogin bool
	// Redirect is where the browser goes next: the provider's callback when
	// the request was approved, or the client with an error.
	Redirect string
	// Denied is the store.Reason* value when access was refused.
	Denied string
}

// Continue decides a pending authorization request for the browser's session.
// sess and user are nil when nobody is signed in. justSignedIn is true when the
// session was created by the request being handled — the person typed their
// credentials for this flow — which satisfies prompt=login and max_age. On
// approval it records the session's authentication time and methods on the
// request, which is what the ID token will report.
func (p *Provider) Continue(authReqID string, sess *store.Session, user *store.User, justSignedIn bool) (*Decision, error) {
	st := p.storage.store
	ar, err := st.AuthRequestByID(authReqID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnknownRequest
	}
	if err != nil {
		return nil, err
	}
	app, err := st.AppByID(ar.AppID)
	if err != nil {
		return nil, err
	}
	promptNone := hasScope(ar.Prompt, oidc.PromptNone)

	if sess == nil || user == nil || !sessionSatisfies(ar, sess, justSignedIn, st.Now()) {
		if promptNone {
			return &Decision{Redirect: p.errorRedirect(ar, "login_required", "the user must sign in")}, nil
		}
		return &Decision{NeedLogin: true}, nil
	}

	access, err := st.CanUseApp(app, user)
	if err != nil {
		return nil, err
	}
	if !access.Allowed {
		p.log.Info("sign-in to app refused", "userId", user.ID, "app", app.Slug, "reason", access.Reason)
		return &Decision{
			Redirect: p.errorRedirect(ar, "access_denied", "the user may not use this application"),
			Denied:   access.Reason,
		}, nil
	}

	if err := st.ApproveAuthRequest(ar.ID, user.ID, sess.CreatedAt, sess.AMR, sess.ACR, ""); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrUnknownRequest
		}
		return nil, err
	}
	return &Decision{Redirect: p.issuer + "/authorize/callback?id=" + url.QueryEscape(ar.ID)}, nil
}

// sessionSatisfies applies prompt=login, max_age and acr_values to the session.
func sessionSatisfies(ar *store.AuthRequest, sess *store.Session, justSignedIn bool, now time.Time) bool {
	if !justSignedIn {
		if hasScope(ar.Prompt, oidc.PromptLogin) {
			return false
		}
		if ar.MaxAge >= 0 && now.Sub(sess.CreatedAt) > time.Duration(ar.MaxAge)*time.Second {
			return false
		}
	}
	return acrSatisfied(ar.ACRValues, sess.ACR)
}

// acrSatisfied reports whether the session meets one of the requested levels.
// Values Fire ID does not define are ignored, as OIDC Core section 3.1.2.1
// treats acr_values as voluntary unless the client asks for the claim as
// essential.
func acrSatisfied(requested, have string) bool {
	known := false
	for _, v := range parseSpaceList(requested) {
		if v != store.ACRLoA1 && v != store.ACRLoA2 {
			continue
		}
		known = true
		if store.Satisfies(v, have) {
			return true
		}
	}
	return !known
}

// errorRedirect builds the error response to the client. The redirect URI was
// checked against the registration when the request was created.
func (p *Provider) errorRedirect(ar *store.AuthRequest, code string, description string) string {
	u, err := url.Parse(ar.RedirectURI)
	if err != nil {
		return p.issuer + "/"
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if ar.State != "" {
		q.Set("state", ar.State)
	}
	q.Set("iss", p.issuer)
	u.RawQuery = q.Encode()
	// The request is finished either way; it must not be approvable later.
	_ = p.storage.store.DeleteAuthRequest(ar.ID)
	return u.String()
}
