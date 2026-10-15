---
name: redirect-uri-rules
description: Redirect URIs are matched exactly, with only the RFC 8252 loopback-any-port exception; fragments and userinfo are refused
metadata:
  type: project
---

`store.ValidateRedirectURI` and `store.MatchesRedirectURI` are the only place redirect URIs are judged.

**Why:** loose matching is a token-exfiltration vector — the bug class behind Fosite's CVE-2020-15233. Wildcards invite it.

**How to apply:** https required, except http on loopback (127.0.0.1, [::1], localhost). No fragments, no userinfo, no wildcards. A registered loopback URI without an explicit port matches any port at request time; anything else must match exactly. Both registration and comparison normalise through `NormaliseRedirectURI`.
