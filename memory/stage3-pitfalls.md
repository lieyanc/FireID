---
name: stage3-pitfalls
description: Non-obvious constraints found while building Stage 3 (sign-in product, TOTP, email, web UI)
metadata:
  type: project
---

Found 2026-10-20 while building Stage 3; each one caused a bug or a review finding.

- **Throttle check-then-fail is not atomic.** `auth.Throttle` and any "read count, compare, then increment" give a burst of parallel guesses extra attempts. Budgets that must hold (email code attempts) reserve the attempt with a conditional UPDATE first (`store.ReserveCodeAttempt`).
- **Confirm the secret you verified.** `store.ConfirmTOTP` takes the ciphertext that was checked; without it a second tab's re-enrolment gets confirmed with a secret no authenticator holds.
- **`needsSecondFactor` is false for non-active users.** Any flow that activates a pending account (email sign-in) must test `TOTPConfirmed || PolicyRequiresTOTP` itself.
- **Forced enrolment under `requireSecondFactorForAdmins` is password-only until done**: whoever has the password enrols their own authenticator. Mitigated only by the notice email; documented in DESIGN §5.
- **`trustProxyHeaders` defaults to false** (was hardcoded true before Stage 3). Behind a proxy without it, every client shares 127.0.0.1 and one person's failures lock everyone out; the server warns once.
- **CSP `script-src 'self'`** forbids inline scripts: the pre-paint theme script lives in `web/public/theme-init.js`. `form-action 'self'` means app hand-off is `window.location.assign`, not a form post.
- **Vite dev proxy must rewrite Origin** to the backend's origin, and `server.publicUrl` must equal `FIREID_BACKEND`, or every POST is `403 cross_site`.
- **`/login` → `/sign-in` loop**: when a session exists but is insufficient, the backend adds `reauth=1`; the UI bounces a signed-in browser to `/login` only without it.

**Why:** these are cross-cutting rules that are easy to break again when adding passkeys (Stage 4) or admin-driven status changes (Stage 5).

**How to apply:** any new factor or sign-in path must go through the same second-factor gate and attempt reservation; any new inline script or cross-origin post will be blocked by the CSP.
