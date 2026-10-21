# UI API

The JSON API behind the embedded UI. It is not a public API: it changes with the
UI. Applications integrate through OIDC (see [DESIGN.md §6](DESIGN.md#6-oidc-surface)).

Conventions:

- Bodies are JSON; unknown fields are rejected (`400 invalid_body`).
- Errors use one envelope: `{"error": "<code>", "message": "<English text>"}`.
  The UI translates by `error`; `message` is a fallback.
- `429 rate_limited` carries `Retry-After` (seconds).
- State-changing requests from another site are refused with `403 cross_site`.
- Secrets that must reach the person (TOTP secret, recovery codes) appear in
  exactly one response and nowhere else.

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
  "denied": "not_member",                                 // only when access was refused
  "authRequestError": "expired",                          // only with authReqId, see below
  "recoveryCodes": ["abcde-fghij", "…"]                   // only when TOTP was just enrolled
}
```

When `authReqId` was sent, the browser should go to `redirectTo` (also when
`denied` is set — the app receives `access_denied`). `authRequestError` means the
person is signed in but the app's request cannot continue:
`expired` (start again from the app), `stronger_authentication_required`,
`internal_error`.

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
| GET | `/api/auth/me` | | `{user, recoveryCodesLeft, amr: [], acr, sessionId, expiresAt, issuer, permissions: {superAdmin, manageUsers, manageApps, ownedApps}}` or `401 unauthenticated` |
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

## Browser routes

Served by the backend, not the UI:

- `GET /login?auth_req_id=…` — where the provider sends the browser. Continues at
  once when the session is good enough, otherwise redirects to the UI route
  `/sign-in?auth_req_id=…`. When a session exists but the app asks for more
  (`prompt=login`, `max_age`, a higher `acr_values`) the redirect adds `&reauth=1`:
  the page must show the form instead of sending a signed-in browser back to
  `/login`, which would loop.
- `POST /oidc/login` — form-encoded sign-in for browsers without JavaScript.

UI routes: `/` (account home), `/sign-in`, `/setup`, `/email-login`.
