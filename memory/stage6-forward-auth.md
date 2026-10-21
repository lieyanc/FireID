---
name: stage6-forward-auth
description: How forward auth is built (code hop to a per-app cookie) and the nginx traps found while verifying it
type: project
---

- **The IdP cookie never leaves the IdP host.** Each protected site gets its own `__Host-fireid_app` cookie through a one-time code (60 s, bound to app + site origin + state-cookie hash). No `cookieDomain` sharing is needed or wanted.
- **A host is entitled only if the app lists `<origin>/__fireid/callback` as a redirect URI.** Start and authorize both check it; that is what keeps an owner from pointing forward auth at someone else's host.
- **nginx drops inherited `proxy_set_header` once a location sets its own.** That is why the identity headers are a separate location snippet that must go into every proxying location; without it a client's own `X-FireID-User` reaches the backend. An empty `auth_request_set` value removes the header, which is the wanted overwrite.
- **Verified with real nginx 1.28 without root:** `apt-get download nginx`, `dpkg-deb -x`, run with `-p <dir> -c <conf>` on high ports, python echo backend. Repeat this for any snippet change.
- **POST from the site host is refused as cross-site** by the global check, so `/__fireid/logout` is GET.

**Why:** design choices and traps from Stage 6 (2026-10-21).

**How to apply:** read before touching `internal/forwardauth/` or the generated nginx snippets.
