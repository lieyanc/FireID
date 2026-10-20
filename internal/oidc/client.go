package oidc

import (
	"net/url"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/lieyanc/FireID/internal/store"
)

// Client wraps a store.App to implement op.Client.
type Client struct {
	app        *store.App
	idTokenTTL time.Duration
}

var _ op.Client = (*Client)(nil)

// NewClient returns an op.Client backed by the given store.App.
func NewClient(app *store.App, idTokenTTL time.Duration) op.Client {
	return &Client{app: app, idTokenTTL: idTokenTTL}
}

// GetID implements op.Client.
func (c *Client) GetID() string {
	return c.app.ClientID
}

// RedirectURIs implements op.Client.
func (c *Client) RedirectURIs() []string {
	return c.app.RedirectURIs
}

// PostLogoutRedirectURIs implements op.Client.
func (c *Client) PostLogoutRedirectURIs() []string {
	return c.app.PostLogoutRedirectURIs
}

// ApplicationType implements op.Client. Public clients are native apps: the
// library then accepts a loopback redirect on any port (RFC 8252 section 7.3),
// which is how desktop and CLI tools receive the code. Confidential clients are
// web servers and get exact matching.
func (c *Client) ApplicationType() op.ApplicationType {
	if c.app.ClientType == store.ClientPublic {
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}

// AuthMethod implements op.Client.
func (c *Client) AuthMethod() oidc.AuthMethod {
	switch c.app.TEAuthMethod {
	case store.AuthPost:
		return oidc.AuthMethodPost
	case store.AuthNone:
		return oidc.AuthMethodNone
	default:
		return oidc.AuthMethodBasic
	}
}

// ResponseTypes implements op.Client. Only the authorization code flow is
// offered; implicit and hybrid are deprecated by RFC 9700.
func (c *Client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

// GrantTypes implements op.Client.
func (c *Client) GrantTypes() []oidc.GrantType {
	out := make([]oidc.GrantType, 0, len(c.app.GrantTypes))
	for _, gt := range c.app.GrantTypes {
		out = append(out, oidc.GrantType(gt))
	}
	return out
}

// LoginURL implements op.Client. The login handler approves the request and
// sends the browser on to /authorize/callback?id=<id>.
func (c *Client) LoginURL(id string) string {
	return "/login?auth_req_id=" + url.QueryEscape(id)
}

// AccessTokenType implements op.Client. Access tokens are opaque; resource
// servers use introspection or userinfo.
func (c *Client) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeBearer
}

// IDTokenLifetime implements op.Client.
func (c *Client) IDTokenLifetime() time.Duration {
	return c.idTokenTTL
}

// DevMode implements op.Client. It would relax redirect URI checks, so it is
// never on.
func (c *Client) DevMode() bool {
	return false
}

// RestrictAdditionalIdTokenScopes implements op.Client. Scopes were already
// narrowed to the app's registration when the request was stored, so nothing
// more is removed. The library calls the returned function unconditionally.
func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

// RestrictAdditionalAccessTokenScopes implements op.Client. See
// RestrictAdditionalIdTokenScopes.
func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

// IsScopeAllowed implements op.Client.
func (c *Client) IsScopeAllowed(scope string) bool {
	for _, s := range c.app.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// IDTokenUserinfoClaimsAssertion implements op.Client. The profile and email
// claims go into the ID token as well as /userinfo: many relying parties read
// them only from the ID token.
func (c *Client) IDTokenUserinfoClaimsAssertion() bool {
	return true
}

// ClockSkew implements op.Client. The library back-dates iat by this much and
// extends exp by the same, which absorbs a relying party whose clock runs a
// little ahead.
func (c *Client) ClockSkew() time.Duration {
	return 30 * time.Second
}
