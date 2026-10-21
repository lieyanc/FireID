---
name: stage4-pitfalls
description: WebAuthn/passkey and account-management traps hit while building Stage 4
type: project
---

- **IP issuer = no passkeys.** WebAuthn forbids an IP address as RP ID, and the default config's `publicUrl` is `http://127.0.0.1:8099`. Passkey endpoints answer `404 passkeys_unavailable` then. Test and develop passkeys with `http://localhost:<port>`.
- **Replay guard needs the stored counter.** After `ValidatePasskeyLogin` the returned credential already holds the new count; pass the count read from the database (`stored.SignCount`) as `prevCount` to `RecordPasskeyUse`, or the conditional UPDATE never matches.
- **A counter stuck at 0 is normal** for synced passkeys and must keep working; only a counter that went backwards (CloneWarning) fails the sign-in.
- **UV-less assertions are refused**, not downgraded: passkey sign-in is always `amr ["webauthn"]` + loa:2, and no TOTP step follows.
- **Ceremonies live only in process memory** (6-minute TTL, 10 000 cap, single use, registration bound to user and session). Multiple instances behind a load balancer would need sticky sessions or a shared store.
- **Migration test.** `TestMigrateUpgradesV1Database` drops every incremental column, so any new index on such a column must also be dropped in its list.

**Why:** each of these cost a failing test or a design correction during Stage 4 (2026-10-21).

**How to apply:** check this list before touching `internal/auth/passkey.go`, `ceremony.go`, or adding incremental columns with indexes.
