---
name: registration-modes
description: How registrationMode, defaultAccess groups, the catalog, access requests and invites work, and the traps around them
metadata:
  type: project
---

- `store.CanUseApp` still decides alone. Rule 5 changed: under `defaultAccess = groups` a plain `member` membership grants nothing (owner/admin still do). `Access.Join` (`join` for open, `request` for admin_approval, `""` otherwise and always under groups) is set only for `not_permitted`; the catalog, join/request handlers and the OIDC denial all act on it instead of reading `registrationMode` themselves.
- `validateAppPolicy` rejects `groups` + `open`/`admin_approval`.
- Catalog visibility = `store.CatalogEntry`; anything outside it is 404 (same as unknown slug); visible-but-not-applicable is 409.
- Request = pending membership + access_request in one tx. Deny deletes only a *pending* membership; approve upgrades only a pending one (a block set meanwhile survives).
- Invites live in `app_invites` (schema v7), not `credential_tokens` (that table is per-user, single-use). Token only in the create response; SHA-256 stored; `redactPath` in `api` hides `/api/invites/<token>` and `/invite/<token>` from request logs — any new route carrying a token in its path must be added there. Uses are spent in the UPDATE that checks `uses < max_uses`; mismatch/blocked refusals spend nothing; never downgrades owner/admin.
- There was no `POST /api/register` before this work; it was added here. Register with an invite checks the token but does not spend it. "Verified email" = account status `active` (pending → active only by redeeming an emailed code).
- OIDC refusal with a non-empty Join (and not prompt=none) goes to `/denied?app=<slug>&reason=&auth_req_id=` and does **not** delete the auth request, so `/login?auth_req_id=` can resume after joining. Every other refusal still deletes it and returns `access_denied` to the client.

**Why:** settled 2026-11-09 when registration modes were made real (contract in the team-lead brief).

**How to apply:** new self-service actions go through `CatalogEntry`/`Access.Join`; never branch on `RegistrationMode` at a call site.
