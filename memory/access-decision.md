---
name: access-decision
description: store.CanUseApp is the single place that decides whether a user may use an app; callers must not re-derive it
metadata:
  type: project
---

`store.CanUseApp` returns an `Access` with a reason, and every caller uses it: the authorize endpoint, the forward-auth endpoint, and the admin UI.

**Why:** a second implementation of the rule drifts, and a drifted access rule is a silent authorization bug.

**How to apply:** the order is fixed — suspended app or inactive account refuses everyone; super admin passes; blocked membership refuses; pending membership refuses with a reason the UI can act on; active membership allows; a granted group allows; `default_access = all_users` allows any active user. Add new cases inside `CanUseApp`, not at call sites.
