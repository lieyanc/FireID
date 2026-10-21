---
name: app-management
description: Who may manage an app, the 404-not-403 rule, and what registrationMode does not do yet
metadata:
  type: project
---

- `store.CanManageApp` is the only place that decides who may administer an app: super admin, `owner_user_id`, or an active member with role owner/admin. The API reaches it through `managedApp`.
- An app the caller cannot manage answers **404**, exactly like an unknown slug, so slugs cannot be probed.
- Deleting an app and the protected membership row follow `owner_user_id`, not the owner *role*.
- Owners see the user directory only by exact username/email (`UserByLogin`); prefix search is super-admin only (DESIGN §8 delegation boundary).
- As of Stage 6 `registrationMode` is stored but not enforced (no self-service catalog, requests or invites yet), and `defaultAccess` `groups` and `members_only` decide the same way.

**Why:** settled in Stage 5 (2026-10-21, a1eef8a).

**How to apply:** new per-app endpoints go through `managedApp`; implement registration modes inside the store, then make `CanUseApp`/the request flow use them.
