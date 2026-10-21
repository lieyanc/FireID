# Memory Index

One fact per file. Format: `- [Title](file.md) — one-line hook`.

- [Protocol library choice](oidc-library-choice.md) — zitadel/oidc v3 pkg/op ≥3.51.14; never below v3.47 (opaque-token forgery advisory); rotation and reuse detection are ours
- [Redirect URI rules](redirect-uri-rules.md) — exact match only, loopback may omit the port; no wildcards anywhere
- [Where access is decided](access-decision.md) — only store.CanUseApp answers "may this user use this app"
- [pkg/op pitfalls](zitadel-op-pitfalls.md) — JWKS key leak, nil scope funcs panic, ErrInvalidRefreshToken, loose native redirect check, hardcoded discovery
- [Stage 3 pitfalls](stage3-pitfalls.md) — atomic attempt budgets, bind TOTP confirm to the secret, pending users and 2FA, trustProxyHeaders default, CSP, dev proxy Origin, reauth=1 loop
- [Stage 4 pitfalls](stage4-pitfalls.md) — no passkeys on an IP issuer, replay guard uses the stored counter, counter 0 is fine, UV required, in-memory ceremonies, migration test drops indexes
- [App management](app-management.md) — CanManageApp only, 404 for apps you cannot manage, owner_user_id vs owner role, registrationMode not enforced yet
- [Stage 6 forward auth](stage6-forward-auth.md) — per-app cookie via one-time code, host entitled by redirect URI, nginx header inheritance trap, real-nginx check without root
- [Stage 7 back-channel and audit](stage7-backchannel-audit.md) — revoked_at trigger feeds the outbox, sid via userinfo claims, logout+jwt signer, UI must avoid /keys
- [Stage 8 client module](stage8-client-module.md) — separate stdlib-only module; cookie hash-bound to issuer+client_id, JWKS keeps stale keys, jti until exp+skew, literal null is a type error
- [Hardening pass 2026-10-21](hardening-2026-10-21.md) — callback bound to the approving session, family revocation takes access tokens, no-store, no credentials in URLs, setup race, argon2 semaphore, file modes; what was left and why
