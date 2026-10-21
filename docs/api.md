# UI API

The JSON API behind the embedded UI. It is not a public API: it changes with the
UI. Applications integrate through OIDC (see [DESIGN.md §6](DESIGN.md#6-oidc-surface))
or, without a login of their own, through [forward auth](#forward-auth).

Conventions:

- Bodies are JSON; unknown fields are rejected (`400 invalid_body`).
- Errors use one envelope: `{"error": "<code>", "message": "<English text>"}`.
  The UI translates by `error`; `message` is a fallback.
- `429 rate_limited` carries `Retry-After` (seconds).
- State-changing requests from another site are refused with `403 cross_site`.
- Secrets that must reach the person (TOTP secret, recovery codes, client
  secrets) appear in exactly one response and nowhere else.
- Every `/api/` response carries `Cache-Control: no-store`, and so do the
  provider's token, introspection, revocation and userinfo responses.
- Request bodies are capped at 1 MiB on every endpoint, the provider's
  included; request headers at 32 KiB.
- The provider refuses credentials in the URL: `/oauth/token`,
  `/oauth/introspect` and `/revoke` take a POST body only, and `/userinfo` the
  `Authorization` header or a POST body (`400 invalid_request` otherwise).
- `/userinfo` refuses with `401` and an RFC 6750 `WWW-Authenticate: Bearer`
  challenge: `error="invalid_token"` for any token it will not honour, none
  when no token was sent. A client refused at `/oauth/token`,
  `/oauth/introspect` or `/revoke` after `client_secret_basic` gets `401` with
  `WWW-Authenticate: Basic`.

## Shapes

`User`:

```json
{
  "id": 1, "username": "alice", "email": "alice@example.com", "displayName": "Alice",
  "status": "active", "superAdmin": false, "totpEnabled": true, "hasPassword": true,
  "emailVerified": true, "createdAt": "2026-10-20T08:00:00Z", "lastLoginAt": ""
}
```

`acr` values are `urn:fireid:loa:1` (one factor) and `urn:fireid:loa:2` (two
factors). `amr` entries are `pwd`, `otp`, `email` and `webauthn`. A passkey
sign-in is `amr: ["webauthn"]` with `loa:2`: the server requires the
authenticator to verify the person (PIN, biometric) and refuses an answer
without it.

`SignedIn` — every endpoint that completes a sign-in returns this with `200`:

```json
{
  "user": { "...": "User" },
  "redirectTo": "https://app.example/callback?code=…",   // only with authReqId
  "denied": "not_permitted",                              // only when access was refused
  "authRequestError": "expired",                          // only with authReqId, see below
  "recoveryCodes": ["abcde-fghij", "…"]                   // only when TOTP was just enrolled
}
```

When `authReqId` was sent, the browser should go to `redirectTo` (also when
`denied` is set — the app receives `access_denied`). `authRequestError` means the
person is signed in but the app's request cannot continue:
`expired` (start again from the app), `stronger_authentication_required`,
`internal_error`. `denied` is a reason from the [access decision](#access-decision).

`Challenge` — the first factor was right, another step is needed, `200`:

```json
{ "challenge": "totp" }        // send the TOTP code (or a recovery code)
{ "challenge": "totp_enrol" }  // policy requires TOTP and the account has none yet
```

`Ceremony` — the start of a passkey prompt, `200`:

```json
{
  "publicKey": { "challenge": "…", "rpId": "id.example.com", "…": "…" },
  "ceremonyId": "…"
}
```

Pass `publicKey` to `navigator.credentials.get()` / `.create()` (binary fields
are base64url), then post the browser's answer back with the same `ceremonyId`.
A ceremony is single-use, lives in server memory for six minutes and does not
survive a restart. Passkeys need a host name issuer: with an IP address issuer
the passkey endpoints answer `404 passkeys_unavailable`.

`Passkey`:

```json
{
  "id": 3, "name": "MacBook", "createdAt": "2026-10-21T08:00:00Z", "lastUsedAt": "",
  "backupEligible": true, "backupState": true
}
```

`name` is `""` until the person names it (at most 64 characters); `lastUsedAt` is
`""` until the first sign-in with it. `backupEligible`/`backupState` say whether
the authenticator may sync the passkey and whether it currently is synced.

`SessionInfo`:

```json
{
  "id": 12, "createdAt": "2026-10-21T08:00:00Z", "lastSeenAt": "2026-10-21T09:30:00Z",
  "expiresAt": "2026-11-20T08:00:00Z", "ip": "203.0.113.7",
  "userAgent": "Mozilla/5.0 …", "amr": ["webauthn"], "current": true
}
```

`current` marks the session making the request.

## Setup and session

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/setup` | | `{setupRequired, registration: "closed"\|"open", emailLogin: bool}` |
| POST | `/api/setup` | `{setupToken, username, email, displayName, password}` | `201 {user}` and a session cookie. `401 invalid_token`, `409 setup_unavailable`, `400 weak_password`, `400 invalid`, `409 conflict` |
| GET | `/api/auth/me` | | `{user, recoveryCodesLeft, amr: [], acr, sessionId, expiresAt, issuer, permissions: {superAdmin, manageUsers, manageApps, ownedApps, createApps}}` or `401 unauthenticated`. See [Permissions](#permissions) |
| POST | `/api/auth/logout` | `{}` | `204` |
| GET | `/api/version` | | `{version, commit, buildTime}` |

## Password sign-in

| Method | Path | Body | Result |
|---|---|---|---|
| POST | `/api/auth/login` | `{username, password, authReqId?}` | `SignedIn` or `Challenge`. `401 invalid_credentials` |
| POST | `/api/auth/login/totp` | `{username, password, code, authReqId?}` | `SignedIn`. `code` is a 6-digit TOTP code or a recovery code. `401 invalid_code`, `401 invalid_credentials`, `409 second_factor_not_required` (TOTP was turned off meanwhile: sign in again) |
| POST | `/api/auth/login/totp/enrol` | `{username, password}` | `{secret, uri}` after a `totp_enrol` challenge. Then call `/api/auth/login/totp` with a code from the app; that response carries `recoveryCodes`. `409 totp_enabled` |

`uri` is an `otpauth://` URI to render as a QR code; `secret` is the same key
for manual entry.

## Passkey sign-in

| Method | Path | Body | Result |
|---|---|---|---|
| POST | `/api/auth/login/passkey/begin` | `{}` | `Ceremony` for `navigator.credentials.get()`. `404 passkeys_unavailable` |
| POST | `/api/auth/login/passkey/finish` | `{ceremonyId, response, authReqId?}` | `SignedIn`. `401 invalid_ceremony` (unknown, used or expired: start again), `401 invalid_credentials` (also for a passkey the server does not know), `429 rate_limited` |

The sign-in is usernameless: no account is named up front, and the browser
offers the passkeys it holds for this site. `response` is the
`PublicKeyCredential` from `navigator.credentials.get()` with every binary field
base64url-encoded. The server requires user verification. A passkey sign-in
completes without a TOTP step. Unknown passkeys count towards a per-address
rate limit. Two assertions racing on the same credential (a replay) cannot both
pass: the loser gets `invalid_credentials`, as does an assertion for a disabled
account.

## Email sign-in

Available only when `/api/setup` reports `emailLogin: true` (SMTP configured).

| Method | Path | Body | Result |
|---|---|---|---|
| POST | `/api/auth/email/start` | `{email, authReqId?, lang?}` | `202 {}` whether or not the address has an account. `lang` (`en`/`zh`) picks the message language, default from `Accept-Language`. `404 email_unavailable` when SMTP is off, `400 invalid` for a malformed address |
| POST | `/api/auth/email/verify` | `{email, code, totp?, authReqId?}` or `{token, totp?, authReqId?}` | `SignedIn`, or `Challenge` `totp` (resend the same body plus `totp`). `401 invalid_code`, `403 totp_enrol_required` (policy requires TOTP and the account has none: sign in with the password, which leads through enrolment) |

The email holds a 6-digit code and a link to
`/email-login#token=<token>&auth_req_id=<id>` (the `auth_req_id` part only when
the sign-in started from an app). The token travels in the fragment so it never
reaches a server log; the page must not redeem it on load — mail scanners open
links — but on a button press. A code allows five wrong guesses, then it is
spent. Both expire after 10 minutes. Sending a new email spends the previous one.
A successful email sign-in also verifies the address.

## Account security (signed in)

| Method | Path | Body | Result |
|---|---|---|---|
| POST | `/api/account/totp/enrol` | `{password?}` | `{secret, uri}`. `password` is required when the account has one. `409 totp_enabled` when already on |
| POST | `/api/account/totp/confirm` | `{code}` | `{recoveryCodes}`. `401 invalid_code`, `409 totp_not_pending` |
| POST | `/api/account/totp/disable` | `{code}` | `204`. `code` is a TOTP or recovery code. `403 forbidden` when policy requires TOTP for this account, `409 totp_not_enabled` |
| POST | `/api/account/recovery-codes` | `{code}` | `{recoveryCodes}` — replaces all previous codes. `409 totp_not_enabled` |

All four answer `401 invalid_code` for a wrong code and `401 invalid_credentials`
for a wrong password.

## Account passkeys (signed in)

| Method | Path | Body | Result |
|---|---|---|---|
| POST | `/api/account/passkeys/begin` | `{password?}` | `Ceremony` for `navigator.credentials.create()`. `password` is required when the account has one; `401 invalid_credentials` when wrong. `404 passkeys_unavailable` |
| POST | `/api/account/passkeys/finish` | `{ceremonyId, name, response}` | `201 {passkey}`. `401 invalid_ceremony`, `401 invalid_credentials` (the browser's answer does not verify), `400 invalid` (name over 64 characters), `409 conflict` (this passkey is already registered) |
| GET | `/api/account/passkeys` | | `{passkeys: [Passkey]}` |
| POST | `/api/account/passkeys/:id/rename` | `{name}` | `204`. `404 not_found`, `400 invalid` |
| DELETE | `/api/account/passkeys/:id` | | `204`. `404 not_found`, `409 last_credential` |

A registration ceremony is bound to the account and the browser session that
started it; finishing it from another session answers `invalid_ceremony`. The
server asks for a discoverable credential (resident key) with user verification,
and excludes passkeys the account already has, so the same authenticator cannot
be registered twice. `response` is the `PublicKeyCredential` from
`navigator.credentials.create()`, binary fields base64url-encoded.

`last_credential` means the passkey is the account's only way to sign in (no
password and no other passkey) and email sign-in is off, so removing it would
lock the account out. Set a password or add another passkey first. With email
sign-in on, the last passkey may go: an emailed link still reaches the account.
A security notice is emailed when a passkey is added or removed and when the
password changes.

`404 not_found` covers a passkey that does not exist and one that belongs to
another account.

## Account management (signed in)

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/account/sessions` | | `{sessions: [SessionInfo]}`, live sessions only, most recently active first |
| DELETE | `/api/account/sessions/:id` | | `204`. `404 not_found`, `409 cannot_revoke_current` (use `/api/auth/logout` instead) |
| POST | `/api/account/sessions/revoke-others` | `{}` | `204`; every other session ends, and so does every token issued to applications |
| PATCH | `/api/account/profile` | `{displayName}` | `204`. `400 invalid` |
| POST | `/api/account/password` | `{currentPassword?, newPassword}` | `204`. `401 invalid_credentials`, `400 weak_password`, `429 rate_limited` |

Revoking a session signs that browser out at its next request. `404 not_found`
covers a session that does not exist, belongs to another account, or has already
ended.

Changing the password keeps the session that made the change signed in. Every
other session of the account is revoked, and so is every refresh token issued to
applications. `currentPassword` is required when the account has a password;
an account without one sets its first password this way. The username and email
address are not editable here.

## Administration

Apps, their members, groups and access requests ([DESIGN.md §8](DESIGN.md#8-administration)).
Every endpoint needs a session and goes through the same cross-site check as the
rest of the API.

### Permissions

`permissions` in `/api/auth/me`:

| Field | Meaning |
|---|---|
| `superAdmin`, `manageUsers` | the account is the super admin |
| `manageApps` | the account manages at least one app (always true for the super admin) |
| `ownedApps` | the account is the owner of at least one app |
| `createApps` | the account may register apps: super admin only |
| `viewAudit`, `manageKeys` | the deployment-wide audit log and the signing keys: super admin only |

An account *manages* an app when it is the super admin, the app's owner, or an
active member with role `owner` or `admin`. Deleting an app is for the super admin
and the app's owner (`ownerUserId`) only. An app the caller cannot manage answers
`404 not_found`, exactly like an unknown slug, so slugs cannot be probed.

Errors across this section: `403 forbidden` (the action needs more than the caller
has), `404 not_found`, `409 conflict` (a duplicate slug or group name, a request
already decided), `400 invalid` with the store's reason in `message`.

### Admin shapes

`App`:

```json
{
  "id": 4, "slug": "wiki", "name": "Wiki", "description": "", "homepageUrl": "https://wiki.example.com",
  "clientId": "3f1c…", "clientType": "confidential", "tokenEndpointAuthMethod": "client_secret_basic",
  "requirePkce": false, "ownerUserId": 1, "status": "active",
  "registrationMode": "closed", "defaultAccess": "members_only",
  "redirectUris": ["https://wiki.example.com/oidc/callback"], "postLogoutRedirectUris": [],
  "scopes": ["openid", "profile", "email"], "grantTypes": ["authorization_code", "refresh_token"],
  "backchannelLogoutUri": "", "backchannelLogoutSessionRequired": false,
  "secretRotatedAt": "", "createdAt": "2026-10-21T08:00:00Z", "updatedAt": "2026-10-21T08:00:00Z"
}
```

`Member` is `{user: User, role, status, createdAt}` with `role` `owner` | `admin` |
`member` and `status` `active` | `pending` | `blocked`. `Group` is
`{id, name, description, memberCount, createdAt}`. `AccessRequest` is
`{id, user: User, message, createdAt}`. Lists are never `null`.

### Apps

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/admin/apps` | | `{apps: [App]}`, the apps the caller manages (super admin: all) |
| POST | `/api/admin/apps` | `{slug, name, description?, homepageUrl?, clientType?, tokenEndpointAuthMethod?, redirectUris, postLogoutRedirectUris?, registrationMode?, defaultAccess?, ownerUserId?}` | `201 {app, clientSecret}`. Super admin only. `400 invalid`, `409 conflict` |
| GET | `/api/admin/apps/:slug` | | `{app, members: [Member], groups: [{id, name}], pendingRequests: [AccessRequest], canDelete, backchannelPending}` |
| PATCH | `/api/admin/apps/:slug` | any of `{name, description, homepageUrl, tokenEndpointAuthMethod, redirectUris, postLogoutRedirectUris, registrationMode, defaultAccess, backchannelLogoutUri, backchannelLogoutSessionRequired}` | `204`. `400 invalid` |
| DELETE | `/api/admin/apps/:slug` | | `204`. Super admin or the app's owner, otherwise `403 forbidden` |
| POST | `/api/admin/apps/:slug/secret/rotate` | `{}` | `{clientSecret}`. `400 invalid` for a public client |
| POST | `/api/admin/apps/:slug/status` | `{status: "active"\|"suspended"}` | `204` |
| POST | `/api/admin/apps/:slug/groups` | `{groupIds: [id]}` | `204`; replaces the granted groups. `400 invalid` for an unknown group |

Creation defaults: `clientType` `confidential`; `tokenEndpointAuthMethod`
`client_secret_basic` (`none` for a public client, which must use PKCE);
`registrationMode` `closed`; `defaultAccess` `members_only`; `ownerUserId` the
caller. Redirect URIs are validated against the client type, and at least one is
required. `clientType` and the slug cannot be changed later.

`clientSecret` appears in the create and rotate responses only (sent with
`Cache-Control: no-store`) and is `""` for a public client. Rotation replaces
the secret at once; tokens already issued keep working until they expire.

In a PATCH an omitted field is left alone; a list replaces the stored one
(`redirectUris` may not be empty). Suspending an app refuses every sign-in and
every token use from then on. Deleting an app also deletes its URIs,
memberships, access requests and every token issued to it.

`backchannelLogoutUri` is where the app is told that a session it signed in
through has ended ([back-channel logout](#back-channel-logout)); `""` turns it
off. It must be `https`, or `http` on a loopback host, without a fragment.
`backchannelPending` counts the notifications still waiting to be delivered.

### Members

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/admin/apps/:slug/members` | | `{members: [Member]}`, oldest first |
| POST | `/api/admin/apps/:slug/members` | `{userId, role, status}` | `201 {member}`; adds or updates the membership. `400 invalid` (unknown user, bad role or status, the owner's row), `403 forbidden` (`role: "owner"` from anyone but the super admin) |
| DELETE | `/api/admin/apps/:slug/members/:userId` | | `204`. `400 invalid` for the owner, `404 not_found` |

The app's owner (`ownerUserId`) always manages the app; their membership row
cannot be changed or removed here.

### Groups

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/admin/groups` | | `{groups: [Group]}`. Anyone with `manageApps` (owners need the names to grant access), otherwise `403 forbidden` |
| POST | `/api/admin/groups` | `{name, description}` | `201 {group}`. `400 invalid`, `409 conflict` |
| PATCH | `/api/admin/groups/:id` | `{name, description}` | `204`. `404 not_found`, `409 conflict` |
| DELETE | `/api/admin/groups/:id` | | `204`; its memberships and app grants go with it. `404 not_found` |
| GET | `/api/admin/groups/:id/members` | | `{users: [User]}`. `404 not_found` |
| POST | `/api/admin/groups/:id/members` | `{userIds: [id]}` | `204`; replaces the member set. `400 invalid` for an unknown user |

Everything except the list is super admin only. A name is 1 to 100 characters, a
description at most 500.

### Access requests

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/admin/apps/:slug/access-requests` | | `{requests: [AccessRequest]}`, pending only, oldest first |
| POST | `/api/admin/apps/:slug/access-requests/:id/decide` | `{approve: bool}` | `204`. `404 not_found` (also for a request that belongs to another app), `409 conflict` (already decided) |

Approval makes the requester an active `member`. The requester is told the
outcome by email when SMTP is configured.

### User search

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/admin/users/search?q=` | | `{users: [User]}`. Anyone with `manageApps`, otherwise `403 forbidden` |

The super admin gets a prefix match on username, email or display name (at most
20). Anyone else gets at most the one account whose username or email equals `q`
exactly: an owner must not be able to browse the directory (the delegation
boundary in [DESIGN.md §8](DESIGN.md#8-administration)). An empty `q` returns no
users.

### Access decision

Whether a person may use an app is decided by `store.CanUseApp`, at sign-in and
again at every token use (refresh, userinfo, introspection) and every forward-auth
request, so a change takes
effect without waiting for tokens to expire. The first rule that matches wins:

| # | Condition | Result (`denied` reason) |
|---|---|---|
| 1 | the app is suspended / the account is not active | refuse (`app_suspended` / `user_not_active`) |
| 2 | the account is the super admin | allow |
| 3 | a `blocked` membership | refuse (`blocked`) |
| 4 | a `pending` membership | refuse (`pending_approval`) |
| 5 | an `active` membership | allow |
| 6 | a member of a group granted to the app | allow |
| 7 | `defaultAccess` is `all_users` | allow |
| | otherwise | refuse (`not_permitted`) |

`defaultAccess` is `all_users`, `groups` or `members_only`. Members and granted
groups are let in whatever it says, so only `all_users` changes the outcome
(rule 7); `groups` and `members_only` currently decide the same way and record
the intent. `registrationMode` — `closed`, `invite`,
`open`, `admin_approval` — says how new people are meant to join the app. It is
stored and editable, but the self-service request and invite flow and the app
catalog are a later stage: today a person gets into an `admin_approval` (or any
other) app only when a manager adds them as a member, puts them in a granted
group, or the app's default access lets them in.

### Audit log

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/admin/audit?event=&app=&user=&before=&limit=` | | `{entries: [AuditEntry], nextBefore}`. Super admin only |
| GET | `/api/admin/apps/:slug/audit?event=&before=&limit=` | | the same, only rows about that app. Managers of the app |

`AuditEntry`:

```json
{
  "id": 812, "at": "2026-10-21T08:00:00Z", "severity": "info", "event": "app.update",
  "actorType": "admin", "actor": {"id": 1, "username": "root", "displayName": ""},
  "app": {"slug": "wiki", "name": "Wiki"}, "user": null,
  "ip": "192.0.2.10", "userAgent": "Mozilla/5.0 …", "detail": {"fields": ["redirectUris"]}
}
```

Rows come newest first. `event` matches exactly, or as a prefix when it ends in
`.` (`auth.`); `app` is a slug (`404 not_found` if unknown); `user` is an account
ID and matches the row's subject or its actor. `limit` defaults to 50 and is
capped at 200. `nextBefore` is the smallest `id` of a full page — pass it as
`before` for the next one — and `null` on the last page. `actor`, `app`, `user`
and `detail` are `null` when absent or since deleted. A non-numeric `user`,
`before` or `limit` is `400 invalid`.

The per-app view shows the same fields as the global one, including the source
address and user agent of that app's sign-in refusals — an app's managers see
them in their own server logs anyway.

Severity is `info`, `warning` or `critical`; `actorType` is `user`, `admin`,
`system` or `client`. Rows are kept for 180 days. Recording is best effort — a
failed write is logged and never fails the action — and `detail` never holds a
secret: no password, code, token or attempted username.

| Event | Severity | When |
|---|---|---|
| `setup.complete` | info | the first super admin was created |
| `auth.sign_in` | info | a sign-in finished; detail `{method, amr}`, `method` is `password`, `passkey` or `email` |
| `auth.sign_in_failed` | warning | credentials were refused; detail `{method, reason}` with `reason` such as `unknown_account`, `wrong_password`, `wrong_code`, `unknown_credential`; `user` set when the attempt named an account. Attempts refused by throttling are covered by `auth.locked`, not logged one by one |
| `auth.locked` | warning | throttling locked out a source or an account; detail `{method, scope, lockoutSeconds}` |
| `auth.sign_out` | info | the person signed out; detail `{via: "rp_logout"}` and the app when an app's `/end_session` did it |
| `account.password_change`, `account.totp_enable`, `account.totp_disable`, `account.recovery_codes`, `account.passkey_add`, `account.passkey_remove`, `account.update`, `account.session_revoke`, `account.sessions_revoke_others` | info | the account holder changed their own account |
| `app.create`, `app.update`, `app.secret_rotate`, `app.status`, `app.groups_set`, `app.member_set`, `app.member_remove`, `app.access_decision` | info | an app was administered; `app.update` lists the changed field names |
| `app.delete` | warning | an app was deleted; the row has no app, detail `{appId, slug, name}` names it |
| `group.create`, `group.update`, `group.delete`, `group.members_set` | info | a group was administered |
| `key.rotate`, `key.retire` | warning | a signing key was rotated or retired; detail `{kid}` |
| `oauth.access_denied` | warning | a sign-in to an app was refused; detail `{reason}` from the [access decision](#access-decision) |
| `oauth.refresh_replay` | critical | a rotated refresh token came back; its whole family was revoked |
| `backchannel.failed` | warning | a back-channel logout notification was given up; detail `{attempts, error}` |

### Signing keys

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/admin/signing-keys` | | `{keys: [{kid, alg, createdAt, activatedAt, retiredAt, current}]}`, newest first, retired ones included; `retiredAt` is `null` until retired |
| POST | `/api/admin/signing-keys/rotate` | `{}` | `201 {kid}` |
| POST | `/api/admin/signing-keys/:kid/retire` | | `204`. `400 invalid` for the current key, `404 not_found` |

Super admin only. Rotation generates a key with the configured algorithm and
makes it current: new ID tokens and logout tokens are signed with it at once.
The previous key stays in `/keys`, so tokens it signed keep verifying. Retiring
removes a non-current key from `/keys`; anything it signed stops verifying, so
wait at least the longest ID-token lifetime after a rotation. Retiring cannot be
undone. Private keys never leave the server.

### Back-channel logout

OpenID Connect Back-Channel Logout 1.0. Discovery advertises
`backchannel_logout_supported` and `backchannel_logout_session_supported`; every
ID token, including refreshed ones, carries `sid`, the browser session's public
identifier (`/userinfo` does not).

When a session ends — sign-out, `/end_session`, revoking a session, signing out
everywhere else, a password change or removal, a disabled account — FireID
POSTs to the `backchannelLogoutUri` of every app that session signed in to:

```
POST <backchannelLogoutUri>
Content-Type: application/x-www-form-urlencoded

logout_token=<JWT>
```

The logout token is signed with the current signing key (`kid` in the header,
`typ` `logout+jwt`) and carries `iss`, `aud` (the client ID), `iat`, `exp` (two
minutes), `jti`, `sub`, `sid` and the `http://schemas.openid.net/event/backchannel-logout`
event, never a `nonce`. The app should verify it against `/keys` (fetching
again on an unknown `kid`), end the local session with that `sid`, and answer
`2xx` within five seconds. Redirects are not followed. A failure is retried
after 30 seconds, 2 minutes, 10 minutes, 30 minutes and 2 hours; after six
attempts the notification is dropped and `backchannel.failed` is recorded.
`sid` is always sent, so `backchannelLogoutSessionRequired` is satisfied either
way.

A session that simply expires sends nothing, and sessions created before the
upgrade to schema v6 did not record which apps they signed in to, so they send
nothing either.

## Forward auth

The endpoints behind nginx `auth_request` ([DESIGN.md §7](DESIGN.md#7-forward-auth-for-applications-without-a-login),
operator guide in [forward-auth.md](forward-auth.md)). The `/api/authz/*` ones are
called by nginx and by browsers following redirects, not by the UI. `/api/authz/app/*`
is reached on the protected site's host as `/__fireid/*`, through the server snippet,
which sets `X-FireID-App` and `X-Original-URL`; FireID never takes either from the
client.

| Method | Path | Called by | Result |
|---|---|---|---|
| GET | `/api/authz/forward` | nginx subrequest | `204` with `X-FireID-User`, `X-FireID-Email`, `X-FireID-Name`, `X-FireID-Groups` (comma-separated group names), `X-FireID-Sub` (account ID). `401` with `Location: <site>/__fireid/start?rd=<url>` without a valid site session. `403` with `X-FireID-Denied: <reason>` when [refused](#access-decision); `403` (logged) when `X-FireID-App` is missing or unknown |
| GET | `/api/authz/app/start?rd=` | browser, as `/__fireid/start` | `302` to `/api/authz/authorize` on the IdP, setting the state cookie (`__Host-fireid_state` on HTTPS, 10 minutes). `400` for an unregistered host |
| GET | `/api/authz/authorize?app=&state=&rd=` | browser, on the IdP host | `302` to `/sign-in?return=…` without an IdP session, to `/denied?app=<name>&reason=<reason>` when refused, otherwise to `<site>/__fireid/callback?code=`. `400` for an unknown app, a missing `state` or an unregistered host |
| GET | `/api/authz/app/callback?code=` | browser, as `/__fireid/callback` | `302` to `rd`, setting the site cookie `__Host-fireid_app` (`fireid_app` on plain HTTP). `400` for an unknown, expired or used code, another origin's code, or a missing or wrong state cookie |
| GET | `/api/authz/app/logout?rd=` | browser, as `/__fireid/logout` | `302` to `rd`; ends the site session only |
| GET | `/api/admin/apps/:slug/forward-auth` | UI | `{callbackPath, hosts, serverSnippet, locationSnippet}`. Managers of the app; `404 not_found` otherwise |

The code is single-use, lives 60 seconds and is bound to the app, the site's
origin and the hash of the state cookie. A site session is valid for its app only,
expires with the IdP session it came from, and ends with it (sign-out, password
change, session revocation, disabled account). `CanUseApp` is asked on every
`/api/authz/forward` call. `rd` is honoured only when it is a URL on the site's
own origin; anything else becomes the site root. The `400` answers are short
plain-text pages.

A host is entitled to an app when `<scheme>://<host>/__fireid/callback` is one of
the app's redirect URIs. `hosts` lists those origins; `serverSnippet` goes in the
site's `server` block and `locationSnippet` in every location that proxies to the
app. The snippets point at FireID's own listener (`server.host`, a wildcard
becoming `127.0.0.1`, and `server.port`).

## Browser routes

Served by the backend, not the UI:

- `GET /login?auth_req_id=…` — where the provider sends the browser. Continues at
  once when the session is good enough, otherwise redirects to the UI route
  `/sign-in?auth_req_id=…`. When a session exists but the app asks for more
  (`prompt=login`, `max_age`, a higher `acr_values`) the redirect adds `&reauth=1`:
  the page must show the form instead of sending a signed-in browser back to
  `/login`, which would loop.
- `POST /oidc/login` — form-encoded sign-in for browsers without JavaScript.

UI routes: `/` (account home), `/sign-in`, `/setup`, `/email-login`, `/denied`,
and for administration `/apps`, `/apps/new`, `/apps/:slug`, `/groups`, `/audit`,
`/signing-keys` (each page
checks `permissions` and sends the person home when they may not be there).

- `/sign-in?return=<path>` — after signing in, the browser goes to `return`. Only
  values starting with `/api/authz/authorize?` are honoured (forward auth sends
  people here); anything else is ignored, so the parameter cannot send anyone to
  another site.
- `/denied?app=<name>&reason=<reason>` — where forward auth sends a signed-in
  person the app refuses. `reason` is one from the [access decision](#access-decision);
  anything else reads as `not_permitted`.
