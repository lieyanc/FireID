// Package client is an OpenID Connect relying party for Go applications,
// written for Fire ID but usable against any provider that follows the
// specifications for the parts it uses. It depends on nothing outside the
// standard library.
//
// Three things are offered:
//
//   - The authorization code flow with PKCE, with real ID token verification:
//     [New] discovers the provider, [Client.AuthCodeURL], [Client.Exchange]
//     and [Client.Refresh] drive the protocol, [Client.VerifyIDToken] checks
//     a token against the provider's published keys. [Client.LoginHandler]
//     and [Client.CallbackHandler] wrap all of it into two net/http handlers
//     for a browser application.
//   - Back-channel logout (OpenID Connect Back-Channel Logout 1.0):
//     [Client.VerifyLogoutToken] and [Client.BackchannelLogoutHandler].
//   - Trusted identity headers for an application behind Fire ID's forward
//     auth: [TrustedHeaders] reads X-FireID-* headers from the reverse proxy
//     and nothing else.
//
// Token verification uses only crypto from the standard library. RS256,
// PS256, ES256 and EdDSA signatures are accepted; the key is always taken
// from the provider's JWKS by kid, never from the token, and the algorithm
// must fit both the key's type and the alg the JWK states.
package client
