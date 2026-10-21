# Stage 8: the `client/` module

Done 2026-10-21, commit 387f5bd (pushed). Separate Go module
`github.com/lieyanc/FireID/client`, standard library only, MIT; the main
module pulls it with `require github.com/lieyanc/FireID/client v0.0.0` plus
`replace … => ./client`, so `go.sum` stays unchanged. Guide:
`client/README.md`.

What it covers: discovery, cached JWKS with stale-serving and a 30 s refresh
floor, compact JWS verification (RS256, PS256, ES256, EdDSA; key by `kid`
from the published set only; RSA 2048–16384), ID token rules, userinfo with
subject equality, refresh, RP-initiated logout, PKCE login/callback
handlers, back-channel logout verification and receiver, trusted-header
middleware. `internal/api/client_test.go` drives the real server through the
package (code flow, refresh replay, rotation and retirement, back-channel
delivery and replay, forward-auth headers, end session).

Pitfalls worth remembering:

- The login cookie's name and contents are hashed/bound to
  `issuer + client_id`, and the callback rejects a state cookie written by
  another `Client`. Without that, two Clients on one host exchange logins
  across issuers. A custom `FlowConfig.CookieName` must still be distinct
  per Client.
- A failing JWKS refresh must not drop the cached set; otherwise an
  unreachable provider kills verification of tokens whose keys are already
  cached. The refresh runs outside the mutex with one in-flight fetch.
- The logout `jti` has to be remembered until `exp + ClockSkew`, not until
  `exp`, or a captured token replays inside the skew window.
- `json.Unmarshal("null", &[]string)` succeeds and yields nil: every
  `RawMessage`-driven decode has to reject a literal `null` explicitly,
  including `aud`.
- Repeated `X-FireID-*` headers make a request anonymous; the proxy must
  replace them (`proxy_set_header` does). A Unix-socket listener needs
  `TrustUnixSocket`.
