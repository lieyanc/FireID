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
factors). `amr` entries are `pwd`, `otp` and `email`.

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
