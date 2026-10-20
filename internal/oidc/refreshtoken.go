package oidc

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lieyanc/FireID/internal/store"
)

// refreshTokenRequest adapts a stored refresh token to op.RefreshTokenRequest.
// It carries the original authentication context so a refreshed ID token still
// reports when and how the user signed in.
type refreshTokenRequest struct {
	rt       *store.RefreshToken
	clientID string
	scopes   []string
}

var _ op.RefreshTokenRequest = (*refreshTokenRequest)(nil)

func (r *refreshTokenRequest) GetAMR() []string       { return parseSpaceList(r.rt.AMR) }
func (r *refreshTokenRequest) GetAudience() []string  { return []string{r.clientID} }
func (r *refreshTokenRequest) GetAuthTime() time.Time { return r.rt.AuthTime }
func (r *refreshTokenRequest) GetClientID() string    { return r.clientID }
func (r *refreshTokenRequest) GetScopes() []string    { return r.scopes }
func (r *refreshTokenRequest) GetSubject() string     { return subjectOf(r.rt.UserID) }

// SetCurrentScopes narrows the scopes of the tokens minted by this exchange.
// The refresh token itself keeps its original scope (RFC 6749 section 6).
func (r *refreshTokenRequest) SetCurrentScopes(scopes []string) { r.scopes = scopes }
