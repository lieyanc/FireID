---
name: stage7-backchannel-audit
description: Stage 7 facts — revocation trigger feeds the back-channel outbox, sid via userinfo claims, logout+jwt signer, audit is best effort
type: project
---

- Every way a session ends sets `sessions.revoked_at`; the SQLite trigger `sessions_backchannel_logout` (migrate.go incrementalIndexes) queues outbox rows in the same transaction. A new revocation path must set `revoked_at`, not only bump `session_gen`, or apps are not told (ClearPassword used to only bump).
- pkg/op's CreateIDToken never sets SessionID; `sid` gets into ID tokens through `userinfo.AppendClaims` in SetUserinfoFromRequest (IDTokenClaims.SetUserInfo merges Claims). Refresh tokens carry `sid` so refreshed ID tokens keep it.
- `op.SignerFromKey` hardcodes typ JWT; logout tokens use our own signer with typ `logout+jwt`. `oidc.NewLogoutTokenClaims` uses time.Now, so the worker builds the claims from the store clock.
- `session_apps` is written at login approval, so sessions from before v6 never notify.
- Audit writes are best effort and never fail the action; detail must not contain secrets or attempted usernames. `auth.SignInFailure` carries the account and a reason to the audit log while still matching ErrInvalidCredentials.
- `/keys` is the JWKS endpoint: UI pages must not use backend paths (vite backendPaths lists them); the keys page is `/signing-keys`.

**Why:** these were the non-obvious decisions of Stage 7 (commit 09cd280).
**How to apply:** check them before touching session revocation, ID-token claims, or adding UI routes.
