---
name: hardening-2026-10-21
description: Stage 9 security hardening pass — what was changed in internal/ and cmd/, and what was deliberately left alone
type: project
---

Done 2026-10-21, not committed by the agent. Tests in `internal/api/hardening_test.go`,
`internal/store/hardening_test.go`, `internal/auth/{setup,password}_test.go`,
`internal/config/config_test.go`.

Changed:

- **`/authorize/callback` is bound to the approving session** (`oidc.Provider.callbackAllowed`).
  The auth request ID is visible to whoever started the flow; before, an attacker could
  get a signed-in victim to open `/login?auth_req_id=<theirs>` and then fetch the
  victim's code from the callback themselves. Approved requests now need a cookie whose
  session `sid` equals the request's `sid`.
- Refresh-family revocation (reuse and `/revoke`) also revokes the family's access
  tokens, through `auth_request_id`, in one transaction.
- `Cache-Control: no-store` on every `/api/` response and on token, introspect, revoke
  and userinfo; Permissions-Policy, HSTS (https issuer only). No COOP: it would sever
  `window.opener` for relying parties that sign in through a popup.
- Credentials in the URL refused: token/introspect/revoke POST body only, userinfo no
  `access_token` query (the library reads `r.Form`, which merges the query).
- Global 1 MiB body cap (the library's own form parsing allowed 10 MB); MaxHeaderBytes 32 KiB.
- Setup token check-and-spend is one critical section (`auth.Service.BeginSetup`); two
  racing POSTs could create two super admins.
- Argon2id runs under a semaphore (GOMAXPROCS, min 2); 64 MiB each, so a burst of
  sign-ins could exhaust memory before the throttle counted anything.
- Failed sign-ins log the account ID, never the attempted username (people type
  passwords there). Test env now captures logs in `oidcEnv.logs`.
- `fireid.db`, `-wal`, `-shm` forced to 0600; an existing group/other-readable
  `config.json` or `master.key` is tightened (best effort, a read-only mount is not
  fatal); `master.key` is created with O_EXCL.

Left, deliberately:

- Back-channel URIs may be `http://` on loopback (api.md rule), so an app owner can make
  FireID POST a logout token to any local port: blind, fixed body, no redirects.
- The token endpoint accepts basic or post whatever the app registered (library behaviour).
- Code exchange does not re-ask `CanUseApp`; the code lives ≤60 s after an access check.
- `auth.cookieDomain` sends the IdP session cookie to every subdomain, forward-auth
  backends included. The config allows it; DESIGN says forward auth does not need it.
- `-reset-auth` sets `auth.recovery` but nothing reads it: with a super admin present no
  setup token is minted, and `/api/setup` only creates accounts. A feature gap, not
  a hole; fixing it means designing the reset path.
- `store.SessionUser` compares the user's `session_gen` with itself (sessions have no
  gen column). Harmless, because every revocation path sets `revoked_at`.

**Why:** Stage 9 asked for a hardening pass before the release pipeline. The callback
binding was the only finding that let one person obtain another's tokens.

**How to apply:** a new provider endpoint that takes a credential must be added to
`credentialsInURL` and the no-store list in `provider.go`. Any new way to approve an
auth request must record the session `sid`, or the callback will refuse it.
