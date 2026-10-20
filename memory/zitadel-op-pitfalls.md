---
name: zitadel-op-pitfalls
description: zitadel/oidc pkg/op behaviours that are not obvious from the interfaces and that Stage 2 had to work around
metadata:
  type: project
---

Found while building Stage 2 (2026-10-19) against v3.51.14. Each one was a real bug or a near miss.

- `op.Key.Key()` is what `/keys` publishes. Returning the signing key's private half there leaks it. `internal/oidc/keys.go` keeps `signingKey` and `publicKey` as separate types for that reason.
- `RestrictAdditionalIdTokenScopes` / `RestrictAdditionalAccessTokenScopes` are called unconditionally; returning nil panics at token time. Return an identity function.
- `GetRefreshTokenInfo` must return `op.ErrInvalidRefreshToken` for unknown tokens, or `/revoke` answers 500 instead of trying the value as an access token.
- `ValidateAuthReqScopes` lets every standard scope through regardless of `IsScopeAllowed`; scopes are narrowed again in `Storage.CreateAuthRequest`.
- For native (public) clients the redirect check accepts any loopback URI with the same path, ignoring host, scheme and registered port. `CreateAuthRequest` re-checks with `store.MatchesRedirectURI`, returning `ErrInvalidRequestRedirectURI` (the only error type the library will not redirect).
- PKCE is enforced by the library only for `AuthMethodNone`; `require_pkce` and S256-only are ours.
- The discovery document hardcodes implicit / `id_token` response types; `Provider.ServeHTTP` serves a corrected one.
- `AuthRequestByCode` runs before PKCE and client checks, so consuming the code there is what makes a failed exchange non-retryable. It must return the real request ID: the library deletes the request by that ID after a successful exchange.
- The library passes the id_token_hint subject as `userID` to `CreateAuthRequest`; it is a client's claim, not a login, and is ignored.

**Why:** the interfaces look like plain storage hooks, but several carry security semantics that only the handler source reveals.

**How to apply:** before relying on a `pkg/op` hook, read the handler that calls it in the module cache. Changes here need the e2e tests in `internal/api/oidc_test.go` to stay green.
