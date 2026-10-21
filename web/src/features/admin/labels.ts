import type { MessageKey } from "@/i18n"
import type {
  AppClientType,
  AppStatus,
  AuditActorType,
  AuditSeverity,
  DefaultAccess,
  MemberRole,
  MemberStatus,
  RegistrationMode,
  TokenEndpointAuthMethod,
} from "@/lib/types"

// Wording for the enum values of the admin API, in the order the UI offers
// them.

export const APP_STATUS_LABELS: Record<AppStatus, MessageKey> = {
  active: "admin.apps.status.active",
  suspended: "admin.apps.status.suspended",
}

export const CLIENT_TYPE_LABELS: Record<AppClientType, MessageKey> = {
  confidential: "admin.apps.clientType.confidential",
  public: "admin.apps.clientType.public",
}

export const AUTH_METHOD_LABELS: Record<TokenEndpointAuthMethod, MessageKey> = {
  client_secret_basic: "admin.apps.authMethod.basic",
  client_secret_post: "admin.apps.authMethod.post",
  none: "admin.apps.authMethod.none",
}

/** The token endpoint methods that fit each client type (store.validateAppPolicy). */
export const AUTH_METHODS_FOR: Record<
  AppClientType,
  TokenEndpointAuthMethod[]
> = {
  confidential: ["client_secret_basic", "client_secret_post"],
  public: ["none"],
}

export const REGISTRATION_MODE_LABELS: Record<RegistrationMode, MessageKey> = {
  closed: "admin.apps.registrationMode.closed",
  invite: "admin.apps.registrationMode.invite",
  open: "admin.apps.registrationMode.open",
  admin_approval: "admin.apps.registrationMode.adminApproval",
}

export const DEFAULT_ACCESS_LABELS: Record<DefaultAccess, MessageKey> = {
  members_only: "admin.apps.defaultAccess.membersOnly",
  groups: "admin.apps.defaultAccess.groups",
  all_users: "admin.apps.defaultAccess.allUsers",
}

export const ROLE_LABELS: Record<MemberRole, MessageKey> = {
  owner: "admin.members.role.owner",
  admin: "admin.members.role.admin",
  member: "admin.members.role.member",
}

export const MEMBER_STATUS_LABELS: Record<MemberStatus, MessageKey> = {
  active: "admin.members.status.active",
  pending: "admin.members.status.pending",
  blocked: "admin.members.status.blocked",
}

export const AUDIT_SEVERITY_LABELS: Record<AuditSeverity, MessageKey> = {
  info: "admin.audit.severity.info",
  warning: "admin.audit.severity.warning",
  critical: "admin.audit.severity.critical",
}

export const AUDIT_ACTOR_LABELS: Record<AuditActorType, MessageKey> = {
  user: "admin.audit.actorType.user",
  admin: "admin.audit.actorType.admin",
  system: "admin.audit.actorType.system",
  client: "admin.audit.actorType.client",
}

/** The audit event catalogue (docs/DESIGN.md), grouped by the name's prefix. */
export const AUDIT_EVENT_LABELS = {
  "setup.complete": "admin.audit.events.setup.complete",
  "auth.sign_in": "admin.audit.events.auth.sign_in",
  "auth.sign_in_failed": "admin.audit.events.auth.sign_in_failed",
  "auth.locked": "admin.audit.events.auth.locked",
  "auth.sign_out": "admin.audit.events.auth.sign_out",
  "account.password_change": "admin.audit.events.account.password_change",
  "account.totp_enable": "admin.audit.events.account.totp_enable",
  "account.totp_disable": "admin.audit.events.account.totp_disable",
  "account.recovery_codes": "admin.audit.events.account.recovery_codes",
  "account.passkey_add": "admin.audit.events.account.passkey_add",
  "account.passkey_remove": "admin.audit.events.account.passkey_remove",
  "account.update": "admin.audit.events.account.update",
  "account.session_revoke": "admin.audit.events.account.session_revoke",
  "account.sessions_revoke_others":
    "admin.audit.events.account.sessions_revoke_others",
  "app.create": "admin.audit.events.app.create",
  "app.update": "admin.audit.events.app.update",
  "app.delete": "admin.audit.events.app.delete",
  "app.secret_rotate": "admin.audit.events.app.secret_rotate",
  "app.status": "admin.audit.events.app.status",
  "app.groups_set": "admin.audit.events.app.groups_set",
  "app.member_set": "admin.audit.events.app.member_set",
  "app.member_remove": "admin.audit.events.app.member_remove",
  "app.access_decision": "admin.audit.events.app.access_decision",
  "group.create": "admin.audit.events.group.create",
  "group.update": "admin.audit.events.group.update",
  "group.delete": "admin.audit.events.group.delete",
  "group.members_set": "admin.audit.events.group.members_set",
  "key.rotate": "admin.audit.events.key.rotate",
  "key.retire": "admin.audit.events.key.retire",
  "oauth.access_denied": "admin.audit.events.oauth.access_denied",
  "oauth.refresh_replay": "admin.audit.events.oauth.refresh_replay",
  "backchannel.failed": "admin.audit.events.backchannel.failed",
} satisfies Record<string, MessageKey>

export type AuditCategory =
  | "setup"
  | "auth"
  | "account"
  | "app"
  | "group"
  | "key"
  | "oauth"
  | "backchannel"

export const AUDIT_CATEGORY_LABELS: Record<AuditCategory, MessageKey> = {
  setup: "admin.audit.category.setup",
  auth: "admin.audit.category.auth",
  account: "admin.audit.category.account",
  app: "admin.audit.category.app",
  group: "admin.audit.category.group",
  key: "admin.audit.category.key",
  oauth: "admin.audit.category.oauth",
  backchannel: "admin.audit.category.backchannel",
}

/** Wording for an event name; undefined for names outside the catalogue. */
export function auditEventLabel(event: string): MessageKey | undefined {
  return Object.hasOwn(AUDIT_EVENT_LABELS, event)
    ? AUDIT_EVENT_LABELS[event as keyof typeof AUDIT_EVENT_LABELS]
    : undefined
}

/** Catalogue event names that start with `category.`, in catalogue order. */
export function auditEventsIn(category: AuditCategory) {
  return Object.keys(AUDIT_EVENT_LABELS).filter((event) =>
    event.startsWith(`${category}.`)
  )
}

/** Keys of a label record, typed, in declaration order. */
export function optionsOf<K extends string>(labels: Record<K, MessageKey>) {
  return Object.keys(labels) as K[]
}
