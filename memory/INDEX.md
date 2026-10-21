# Memory Index

One fact per file. Format: `- [Title](file.md) — one-line hook`.

- [Protocol library choice](oidc-library-choice.md) — zitadel/oidc v3 pkg/op ≥3.51.14; never below v3.47 (opaque-token forgery advisory); rotation and reuse detection are ours
- [Redirect URI rules](redirect-uri-rules.md) — exact match only, loopback may omit the port; no wildcards anywhere
- [Where access is decided](access-decision.md) — only store.CanUseApp answers "may this user use this app"
- [pkg/op pitfalls](zitadel-op-pitfalls.md) — JWKS key leak, nil scope funcs panic, ErrInvalidRefreshToken, loose native redirect check, hardcoded discovery
- [Stage 3 pitfalls](stage3-pitfalls.md) — atomic attempt budgets, bind TOTP confirm to the secret, pending users and 2FA, trustProxyHeaders default, CSP, dev proxy Origin, reauth=1 loop
