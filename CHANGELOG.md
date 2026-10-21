# Changelog

All notable changes to Fire ID are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor
version may change the configuration or the UI API; such changes are listed
under **Changed** with what to do.

## [Unreleased]

## [0.1.0] - Unreleased

The first release.

### Added

- **OpenID Connect provider.** Discovery, authorization code flow with PKCE (S256
  only; required for public clients), refresh tokens that rotate on every use with
  family revocation on reuse, `userinfo`, JWKS, token introspection (RFC 7662),
  revocation (RFC 7009), RP-initiated logout and `iss` in authorization responses
  (RFC 9207). ID tokens are signed with ES256 or RS256. Redirect URIs match exactly.
- **First-run setup.** The first start logs a one-time setup token that creates the
  super administrator; `-reset-auth` re-enters that mode for account recovery.
- **Sign-in methods.** Passwords (argon2id) with an optional TOTP second factor and
  recovery codes, passkeys (WebAuthn, username-less, with user verification), and
  email sign-in by code or magic link when SMTP is configured. Sign-in attempts
  are throttled per address and per account.
- **Web UI** in English and Chinese, compiled into the binary.
- **Account self-service.** Profile, password change, TOTP and passkey management,
  and a list of active sessions that can be signed out individually.
- **Applications and delegated administration.** Applications with owners who
  manage only their own app: redirect URIs, client-secret rotation, members,
  group grants, registration policy and access requests. Groups are shared across
  applications.
- **Forward auth** for sites without a login of their own, through nginx
  `auth_request`, with a per-app snippet generated in the UI. See
  [docs/forward-auth.md](docs/forward-auth.md).
- **Audit log** of authentication and administrative events, kept for 180 days.
- **Signing-key rotation** from the admin UI; retired keys stay published until
  they are removed, so issued tokens keep verifying.
- **Back-channel logout**: applications that register a URI receive a signed
  logout token when a session that signed in to them ends.
- **Go client module** [`github.com/lieyanc/FireID/client`](client/README.md):
  OIDC login handlers with ID-token verification, a back-channel logout receiver,
  and middleware for the forward-auth identity headers.
- **Releases**: static binaries for Linux and macOS on amd64 and arm64 with a
  `SHA256SUMS` file, and a multi-arch container image at `ghcr.io/lieyanc/fireid`.

### Security

- TOTP secrets and signing keys are encrypted at rest with a master key generated
  into `data/master.key`; passwords and client secrets are stored hashed.
- State-changing requests from another site are refused.
- The authorization callback only releases a code to the browser session that
  approved the request, so an authorization request ID seen in one browser cannot
  be used to collect another person's code.
- Reusing a refresh token revokes the whole family, access tokens included;
  token, introspection, revocation and userinfo requests refuse credentials in
  the URL; form bodies are capped at 1 MiB.
- `fireid.db` and its sidecars are created mode `0600`, and a world-readable
  `config.json` or `master.key` is tightened on start.
- The hardening pass and the walk of the OpenID conformance plans are in
  [docs/conformance.md](docs/conformance.md) and `internal/api/hardening_test.go`.
  The official conformance suite has not been run yet.

[Unreleased]: https://github.com/lieyanc/FireID/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lieyanc/FireID/releases/tag/v0.1.0
