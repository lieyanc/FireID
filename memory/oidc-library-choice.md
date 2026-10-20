---
name: oidc-library-choice
description: FireID builds its OIDC provider on zitadel/oidc v3 pkg/op; the minimum version and the storage responsibilities that stay ours
metadata:
  type: project
---

The provider is built on `github.com/zitadel/oidc/v3` `pkg/op`, pinned **≥ v3.51.14**.

**Why:** it is the only Go OP library with a live release cadence and a published security-response record. GHSA-j8gq-92xf-382c (fixed v3.47.0) let anyone holding an opaque access token flip ciphertext bits to forge a different `sub` — a full authentication bypass for resource servers using introspection. Never pin below v3.47. The alternative, `authelia.com/provider/oauth2`, covers more specs but has no `/userinfo` endpoint, which is the one endpoint new-api depends on.

**How to apply:** the library does not rotate refresh tokens or detect reuse — `internal/store` must do both, revoking the whole family on reuse (RFC 9700 §4.14.2). Redirect URIs are matched exactly by `store.MatchesRedirectURI`; never use `RedirectURIGlobs`. `op.Client.DevMode()` must stay false. Keep `go-jose/go-jose/v4` at ≥ v4.1.6 ourselves (done 2026-10-19), since the library pins an older one. Library behaviour that bit Stage 2 is in [[zitadel-op-pitfalls]]. Full review: `identity-auth-research/details/go-oidc-libraries.md` in the Agent workspace.
