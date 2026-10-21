import type { MessageKey } from "@/i18n"
import type {
  AppClientType,
  AppStatus,
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

/** Keys of a label record, typed, in declaration order. */
export function optionsOf<K extends string>(labels: Record<K, MessageKey>) {
  return Object.keys(labels) as K[]
}
