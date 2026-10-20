package oidc

import (
	"time"

	oidclib "github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lieyanc/FireID/internal/store"
)

// authRequest adapts store.AuthRequest to op.AuthRequest.
type authRequest struct {
	req      *store.AuthRequest
	clientID string
}

var _ op.AuthRequest = (*authRequest)(nil)

func (a *authRequest) GetID() string          { return a.req.ID }
func (a *authRequest) GetACR() string         { return a.req.ACR }
func (a *authRequest) GetAMR() []string       { return parseSpaceList(a.req.AMR) }
func (a *authRequest) GetAudience() []string  { return []string{a.clientID} }
func (a *authRequest) GetAuthTime() time.Time { return a.req.AuthTime }
func (a *authRequest) GetClientID() string    { return a.clientID }
func (a *authRequest) GetCodeChallenge() *oidclib.CodeChallenge {
	if a.req.CodeChallenge == "" {
		return nil
	}
	return &oidclib.CodeChallenge{
		Challenge: a.req.CodeChallenge,
		Method:    oidclib.CodeChallengeMethod(a.req.CodeChallengeMethod),
	}
}
func (a *authRequest) GetNonce() string       { return a.req.Nonce }
func (a *authRequest) GetRedirectURI() string { return a.req.RedirectURI }

// GetResponseType is always code: FireID only supports the authorization code
// flow (RFC 9700 deprecates implicit and hybrid).
func (a *authRequest) GetResponseType() oidclib.ResponseType { return oidclib.ResponseTypeCode }

// GetResponseMode is query, the only mode advertised in discovery.
func (a *authRequest) GetResponseMode() oidclib.ResponseMode { return oidclib.ResponseModeQuery }
func (a *authRequest) GetScopes() []string                   { return parseSpaceList(a.req.Scope) }
func (a *authRequest) GetState() string                      { return a.req.State }

func (a *authRequest) GetSubject() string {
	if !a.req.UserID.Valid {
		return ""
	}
	return subjectOf(a.req.UserID.Int64)
}

// Done reports whether the login page approved the request. Approval sets the
// user and the authentication time together.
func (a *authRequest) Done() bool {
	return a.req.UserID.Valid && a.req.UserID.Int64 != 0 && !a.req.AuthTime.IsZero()
}
