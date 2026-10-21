# FireID — design

Fire ID is a self-hosted OpenID Connect provider for a small fleet of personal and
friend-owned services. One Go binary, SQLite storage, an embedded React admin UI, and
an nginx `auth_request` endpoint for services that have no login of their own.

Status: in development — see [§9 Build order](#9-build-order). The UI's JSON API is in
[api.md](api.md).

## 1. Goals

- **One user pool** shared by every connected application, with **per-application
  membership** so access can be scoped to a project or a set of friends.
- **Standards-compliant OIDC** so unmodified clients work: generic OIDC clients
  (new-api, Sub2API, FireCortex), plus a forward-auth mode for apps that speak no
  protocol at all.
- **Self-service** registration and invitations, with the policy chosen per
  application by that application's owner.
- **Delegated administration**: the operator is the super admin; each application has
  an owner who manages only their own application — redirect URIs, secret rotation,
  who may sign in, and pending access requests.
- **Auditable**: every authentication and administrative event is recorded.
- **Open source, MIT.** Generic product; no deployment-specific values in the repo.

### Non-goals (v1)

- SAML, LDAP server, SCIM, RADIUS, Kerberos.
- Multi-tenant isolation with separate per-tenant user pools. One deployment serves
  one community; applications scope access, they do not partition identity.
- Third-party social login (GitHub/Google). Designed for, not built.
- Enterprise features: device trust, conditional access policies, PAM.

## 2. Terminology

| Term | Meaning |
|---|---|
| **User** | A person. Global within the deployment. |
| **App** | An OAuth client. Has an owner, redirect URIs, and an access policy. |
| **Owner** | A user who administers one app. Not a super admin. |
| **Group** | A named set of users. Apps grant access to groups. |
| **Membership** | A row linking a user to an app with a role. |
| **Super admin** | The operator. Sees everything, owns the IdP settings. |

## 3. Architecture

```
browser ──► OpenResty (443) ──┬─► id.example.com     → FireID  (UI + OIDC endpoints)
                              ├─► app-a.example.com   → FireID forward-auth ──► app-a backend
                              └─► app-b.example.com   ────────────────────────► app-b backend
                                                     (nginx auth_request consulted first)
```

- FireID listens on loopback only. Everything reaches it through the reverse proxy.
- Applications that speak OIDC talk to FireID directly and never need proxy help.
- Applications that do not speak OIDC are protected at the proxy: nginx asks
  `/api/authz/forward` on every request and copies the returned identity headers onto
  the upstream request.

### Packages

```
cmd/fireid/          entry point: flags, config, wiring, graceful shutdown
internal/config/     on-disk JSON config + atomic Store
internal/store/      SQLite: schema, queries, invariants
internal/auth/       sessions, password/passkey/TOTP/magic-link credentials, throttling
internal/mail/       SMTP delivery (stdlib net/smtp)
internal/oidc/       OIDC provider: discovery, authorize, token, JWKS, userinfo, logout
internal/forwardauth/ nginx auth_request decision endpoint
internal/api/        HTTP surface for the UI + admin JSON API
internal/updater/    GitHub release OTA (house template)
web/                 React UI, embedded with go:embed
client/              separate Go module: OIDC client + trusted-header middleware
docs/                this file and operational notes
```

`client/` is its own Go module so an application can import it without pulling in the
server's dependencies:

```
github.com/lieyanc/FireID/client
```

## 4. Data model

SQLite, WAL, `foreign_keys(1)`, `busy_timeout(5000)`, `synchronous(NORMAL)`, pool of 4.
Schema lives in an embedded idempotent `migrate.sql`; later columns are appended to
`incrementalColumns` in Go. A `schema_version` row records the last applied version.

### Identity

```sql
users(id, username UNIQUE, email UNIQUE, display_name, status, is_super_admin,
      password_hash, session_gen, totp_secret_enc, totp_confirmed_at,
      created_at, updated_at, last_login_at)
```
- `status`: `pending` (registered, email unverified) | `active` | `disabled`.
- `password_hash`: argon2id, parameters stored in the encoded string.
- `session_gen`: incremented to revoke every session and token issued for the user.
- `totp_secret_enc`: encrypted at rest with the master key, never returned by the API.

```sql
webauthn_credentials(id, user_id FK, credential_id UNIQUE, public_key, sign_count,
                     transports, aaguid, name, created_at, last_used_at,
                     backup_eligible, backup_state)
credential_tokens(id, user_id FK, purpose, token_hash, expires_at, used_at, created_at)
```
- `purpose`: `email_verify` | `magic_link` | `password_reset` | `invite`.
- Only the hash is stored; the plaintext token appears once, in the email or URL.

### Applications

```sql
apps(id, slug UNIQUE, name, description, homepage_url, logo_url,
     client_id UNIQUE, client_secret_hash, secret_rotated_at,
     token_endpoint_auth_method, require_pkce, client_type,
     owner_user_id FK, status, created_at, updated_at)

app_redirect_uris(app_id FK, uri, PRIMARY KEY(app_id, uri))
app_post_logout_redirect_uris(app_id FK, uri, PRIMARY KEY(app_id, uri))
app_scopes(app_id FK, scope, PRIMARY KEY(app_id, scope))
app_grants(app_id FK, grant_type, PRIMARY KEY(app_id, grant_type))
```
- `client_type`: `confidential` | `public`. Public clients have no secret and must use PKCE.
- `token_endpoint_auth_method`: `client_secret_basic` | `client_secret_post` | `none`.
  new-api sends the secret in the body, so `client_secret_post` must work.
- `status`: `active` | `suspended` | `pending_review`.
- Redirect URIs are matched exactly after normalisation. Loopback URIs may use any port
  (RFC 8252 §7.3). No wildcards.

```sql
app_registration_policy(app_id PK, mode, default_access)
```
- `mode`: `closed` | `invite` | `open` | `admin_approval`.
  `open` accepts any active user of this deployment; `admin_approval` holds the user in
  the app's pending list until the owner approves.
- `default_access`: `all_users` | `groups` | `members_only`.

```sql
groups(id, name UNIQUE, description, created_at)
group_members(group_id FK, user_id FK, PRIMARY KEY(group_id, user_id))
app_group_access(app_id FK, group_id FK, PRIMARY KEY(app_id, group_id))
app_memberships(app_id FK, user_id FK, role, status, created_at, approved_by FK,
                PRIMARY KEY(app_id, user_id))
access_requests(id, app_id FK, user_id FK, message, status, created_at, decided_at,
                decided_by FK)
```
- `app_memberships.role`: `owner` | `admin` | `member`. `status`: `active` | `pending` | `blocked`.
- Effective access to an app = owner/admin, or an active membership, or a group granted
  to the app, or (when `default_access = all_users`) any active user.

### Sessions and tokens

```sql
sessions(id, user_id FK, token_hash UNIQUE, created_at, expires_at, last_seen_at,
         ip, user_agent, amr, acr, revoked_at)
auth_codes(code_hash PK, app_id FK, user_id FK, redirect_uri, scope, nonce,
           code_challenge, code_challenge_method, auth_time, amr, acr, sid,
           expires_at, consumed_at)
refresh_tokens(id, token_hash UNIQUE, app_id FK, user_id FK, family_id, scope,
               created_at, expires_at, rotated_at, revoked_at, revoked_reason)
id_token_sessions(sid PK, app_id FK, user_id FK, created_at, expires_at)
```
- Everything server-side is stored as a SHA-256 hash of the opaque value.
- `auth_codes` live 60 seconds and are single-use; replay revokes the whole family.
- Refresh tokens rotate on every use. Reuse of a rotated token revokes the family
  (RFC 9700 §4.14.2) and raises an audit event.
- `amr` records how the session authenticated (`pwd`, `otp`, `webauthn`, `email`),
  `acr` the level: `urn:fireid:loa:1` (single factor) or `...:2` (password + TOTP, or
  passkey user-verified).

### Keys and audit

```sql
signing_keys(id, kid UNIQUE, alg, private_key_enc, public_jwk, created_at, activated_at,
             retired_at, is_current)
audit_log(id, at, actor_user_id, actor_type, event, app_id, user_id, ip, user_agent,
          detail_json, severity)
settings(key PK, value_json, updated_at, updated_by FK)
```

## 5. Authentication

Authentication methods, all usable together:

| Method | Notes |
|---|---|
| Password | argon2id. Optional TOTP second factor. |
| TOTP | RFC 6238, SHA-1, 6 digits, 30 s, ±1 step. A code is accepted once: the highest used step is stored per account. Ten recovery codes (`xxxxx-xxxxx`, 50 bits each, stored hashed) are issued at enrolment; regenerating replaces them all. |
| Passkey | WebAuthn, discoverable credentials (username-less), user verification required for `loa:2`. Multiple per account. |
| Email code / magic link | One email carries a 6-digit code and a link; either redeems it, once. 10-minute validity, five wrong codes spend it, a new email spends the previous one. Three emails per address and ten per source address before an exponential lockout. Requires SMTP. |

Rules:

- First run prints a one-time **setup token** to the log; it creates the super admin.
  `-reset-auth` re-enters that mode. No password is ever logged.
- Login throttling per IP and per account: 5 free attempts, then exponential lockout
  starting at 1 minute up to 15 minutes. Unknown usernames still pay a dummy argon2id
  verification so timing does not reveal existence.
- A user with no password and no passkey can only be reached by magic link.
- A confirmed TOTP is required after every first factor, email included (`amr` `pwd otp`
  or `email otp`, `acr` `loa:2`). An enrolment that was started but not confirmed does
  not count, so it cannot be used to slip past `requireSecondFactorForAdmins`; an
  account under that policy is led through enrolment on its next password sign-in.
- Email sign-in reveals nothing about which addresses have accounts: the answer is the
  same, and the lookup and delivery happen after the response. The link carries its
  token in the URL fragment, so it never reaches a server log, and the page redeems it
  only on a button press, because mail scanners open links. Redeeming it proves the
  address, so it also activates a `pending` account.
- Turning TOTP on asks for the password again; turning it off or regenerating recovery
  codes asks for a current code. Each of the three sends a notice to the account's
  verified address.
- `requireSecondFactorForAdmins` protects an account only once its enrolment is done.
  Until then, whoever holds the password can enrol their own authenticator and receive
  the recovery codes; the notice email is the account holder's only warning. Enrol
  administrators before relying on the policy.
- Deleting a credential never deletes the user; the last credential removal is allowed
  only if a recovery path exists (another credential, or a super admin reset).

### Session cookie

Opaque random 32-byte session id, stored hashed in `sessions`. Cookie attributes:
`HttpOnly`, `SameSite=Lax`, `Secure` when the request arrives over TLS, `Path=/`,
`Domain` configurable for subdomain sharing. The IdP's own session is deliberately
separate from any application session.

CSRF for the UI: `Origin`/`Sec-Fetch-Site` checks on unsafe methods (house convention),
plus `SameSite=Lax`. No per-form tokens.

## 6. OIDC surface

Discovery: `/.well-known/openid-configuration`. Paths are the protocol library's
defaults, relative to the issuer; discovery is the authoritative list.

Endpoints:

| Endpoint | Notes |
|---|---|
| `/authorize` | Authorization code only. PKCE S256 required for public clients and for apps with `require_pkce`; `plain` is refused. Responses carry `iss` (RFC 9207). |
| `/authorize/callback` | Where the login page sends an approved request; issues the code. |
| `/oauth/token` | `authorization_code`, `refresh_token`. Client auth: `client_secret_basic`, `client_secret_post`, or `none` for public clients. |
| `/userinfo` | `sub`; `name`, `preferred_username`, `updated_at` with `profile`; `email`, `email_verified` with `email`. |
| `/keys` | Published signing keys, public halves only. |
| `/oauth/introspect` | RFC 7662. The client must authenticate and may only introspect its own tokens. |
| `/revoke` | RFC 7009. Revoking a refresh token ends the whole grant, including its access tokens. |
| `/end_session` | RP-initiated logout. Signs the browser out only for a valid `id_token_hint` naming the signed-in user. |

Not offered yet, and not advertised: `client_credentials`, the device flow,
`/.well-known/oauth-authorization-server`, the `groups` scope, private_key_jwt.

Supported scopes: `openid` (required), `profile`, `email`, `offline_access`. A request is
narrowed to the scopes the app is registered for; `offline_access` needs the
`refresh_token` grant.

`sub` is the numeric account ID, so a rename does not create a new identity at every
app. Access tokens are opaque (an encrypted token ID under a key derived from the master
key), backed by an `access_tokens` row that carries scope, expiry and revocation;
resource servers use `userinfo` or introspection. ID tokens (`RS256` or `ES256`, chosen
at key generation) carry `iss`, `sub`, `aud`, `azp`, `exp`, `iat`, `auth_time`, `amr`,
`acr`, `nonce` when sent, `at_hash`, `c_hash`, and the profile/email claims of the
granted scopes.

Token rules enforced in `internal/store`:

- An authorization code is redeemed once, at the first step of the exchange; a failed
  exchange burns it, and a second redemption revokes every token issued from it.
- A request yields one code. Pending requests expire after 15 minutes.
- Refresh tokens rotate on every use. Presenting a rotated token revokes the family.
- A password change or a disabled account revokes refresh and access tokens.
- `store.CanUseApp` is asked again on every refresh, userinfo and introspection call.

Client compatibility constraints, from the current fleet:

- **new-api** sends the secret in the token request body (no PKCE) and reads identity
  from `userinfo` — `sub` and `email` must both be non-empty. It does not validate the
  id_token, so `userinfo` correctness is what matters for it.
- **Sub2API** is the strictest: PKCE, `id_token` signature via JWKS, `iss`/`aud`/`nonce`
  checks, and `sub` equality between `userinfo` and `id_token`. FireID must satisfy this.
- Both keep a local admin login as break-glass; FireID must never be the only way in.

Security requirements taken from RFC 9700 and the 2026 incident record of comparable
products:

- Exact redirect URI matching, always. Reject `open redirect` patterns and fragments.
- `state` and `nonce` stored with the authorization request, `state` echoed, `nonce`
  bound into the id_token.
- Authorization codes are single-use, ≤60 s, bound to client, redirect URI, and PKCE verifier.
- Refresh token rotation with family revocation on reuse.
- No implicit flow, no password grant.
- `iss` in the authorisation response (RFC 9207).
- Back-channel logout for apps that register it.

## 7. Forward auth for applications without a login

`GET /api/authz/forward` — called by nginx as an internal subrequest.

- Returns `204` when the session is valid and the user may use the app, with headers:
  `X-FireID-User`, `X-FireID-Email`, `X-FireID-Name`, `X-FireID-Groups`, `X-FireID-Sub`.
- Returns `401` with `Location` set to the login URL when unauthenticated.
- Returns `403` when the user is known but not entitled to this app.
- The app identity is taken from the `X-FireID-App` value nginx sets, never from the client.
- When `X-FireID-Redirect-Param: location` is set, the configured client app receives the
  identity in a `Remote-User` style header after a redirect instead of a subrequest
  status — **not in v1**; the subrequest mode is enough.

nginx side (two locations, one include per protected site):

```nginx
location = /__fireid/authz {
    internal;
    proxy_pass http://127.0.0.1:8099/api/authz/forward;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-FireID-App "app-a";
    proxy_set_header X-Original-URL $scheme://$host$request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Real-IP $remote_addr;
}
```

Critical rules, each of which has been a real CVE in a comparable product in 2026:

1. **Overwrite** `X-Original-URL`, `X-Original-Method`, `X-Forwarded-*`, and every
   `X-FireID-*` header from nginx variables. Never trust a client-supplied copy.
2. The `/__fireid/authz` location is `internal` and forwards no request body.
3. Backends must be unreachable except through the proxy — bind them to loopback.
   A published Docker port bypasses both nginx and any firewall rule.
4. Downstream apps receive identity headers only from the proxy, and must be bound to
   loopback so a direct connection cannot forge them.

## 8. Administration

UI areas:

- **Sign-in**: password, passkey, email code. "Use another account" for passkey-only.
- **Account**: profile, email verification, password, passkeys (add/name/remove),
  TOTP enrolment with recovery codes, active sessions with revoke, connected apps with
  revoke.
- **Apps** (per app, owner or super admin): details, redirect URIs, secret rotation,
  scopes, token auth method, registration policy, access (groups and members),
  pending access requests, audit trail for that app. Built in Stage 5 except
  editable scopes (every app gets `openid profile email`) and the audit trail (Stage 7).
- **Admin** (super admin): users (list, search, create, disable, reset credential,
  force logout, delete), groups, all apps (including create and approve), global
  registration policy, SMTP settings, signing keys (rotate, retire, history), audit log,
  system health, update (OTA). Groups and app creation are built; the rest is not
  yet.
- **Self-service** (later stage): an app catalog, requesting access to an app, and
  invitations. Until then an app's members are added by its managers.

Delegation boundary: an owner sees only their apps and only the users who have a
relationship with those apps (member, requester, or in a granted group) — plus, when the
app's policy is `open`, the fact that any active user may sign in. To add a member, an
owner may look up one account by its exact username or email; only the super admin can
list or search the directory.

## 9. Build order

| Stage | Content | State |
|---|---|---|
| 0 | Research: IdP landscape, client inventory, library verification | done |
| 1 | Repo skeleton, config, SQLite schema, version, Makefile, licence, docs | done |
| 2 | OIDC provider core on the chosen library — discovery, authorize, token, JWKS, userinfo, introspect, revoke, end_session | done; end-to-end tests in `internal/api/oidc_test.go` |
| 3 | Product layer: setup flow, sessions, password/TOTP/magic link, UI shell, i18n | done; API in [api.md](api.md), tests in `internal/api/signin_test.go` |
| 4 | Passkeys, account and session management | done; API in [api.md](api.md), tests in `internal/api/passkey_test.go`, `account_test.go` |
| 5 | Apps, owners, groups, registration policies, access requests | done; API in [api.md](api.md#administration), tests in `internal/api/admin_test.go` |
| 6 | Forward-auth endpoint and the per-site nginx include | |
| 7 | Audit log, signing-key rotation, back-channel logout | |
| 8 | `client/` module: OIDC client with real id_token verification, trusted-header middleware | |
| 9 | OpenID conformance-suite run, hardening pass, release pipeline | |

Stage 8 is worth doing early for any application that already has login code to retire.

## 10. Open questions

- Whether to keep the whole protocol layer on `zitadel/oidc`'s OP package or hand-write
  thin handlers over a JOSE library. Awaiting the library review.
- Whether per-app access tokens should be audience-restricted to `/userinfo` only, or
  usable as bearer tokens by the apps themselves (a "resource server" mode). v1: tokens
  are for `userinfo` and forward-auth; apps that need their own bearer flow keep using
  their existing API keys.
