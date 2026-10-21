// Shapes of the UI API (docs/api.md). Keep in step with the Go handlers.

export type ApiErrorBody = {
  error: string
  message: string
}

export type User = {
  id: number
  username: string
  email: string
  displayName: string
  status: string
  superAdmin: boolean
  totpEnabled: boolean
  hasPassword: boolean
  emailVerified: boolean
  createdAt: string
  /** "" when the account has never signed in. */
  lastLoginAt: string
}

export type SetupState = {
  setupRequired: boolean
  registration: "closed" | "open"
  /** True when SMTP is configured and email sign-in is offered. */
  emailLogin?: boolean
}

export type Permissions = {
  superAdmin: boolean
  manageUsers: boolean
  manageApps: boolean
  ownedApps: boolean
  createApps: boolean
}

export type Me = {
  user: User
  /** Unused recovery codes; 0 while two-step verification is off. */
  recoveryCodesLeft: number
  /** Authentication methods of this session: "pwd", "otp", "email", … */
  amr: string[]
  /** "urn:fireid:loa:1" (single factor) or "urn:fireid:loa:2" (two factors). */
  acr: string
  sessionId: string
  expiresAt: string
  issuer: string
  permissions: Permissions
}

export type AuthRequestError =
  "expired" | "stronger_authentication_required" | "internal_error"

/** Returned by every endpoint that completes a sign-in. */
export type SignedIn = {
  user: User
  redirectTo?: string
  denied?: string
  authRequestError?: AuthRequestError | string
  recoveryCodes?: string[]
}

/** The first factor was right; another step is needed. */
export type Challenge = { challenge: "totp" | "totp_enrol" }

export type SignInResult = SignedIn | Challenge

export function isChallenge(result: SignInResult): result is Challenge {
  return "challenge" in result
}

export type TotpEnrolment = {
  secret: string
  /** otpauth:// URI, rendered as a QR code. */
  uri: string
}

export type RecoveryCodes = { recoveryCodes: string[] }

export type VersionInfo = {
  version: string
  commit: string
  buildTime: string
}

/** A registered passkey (GET /api/account/passkeys). */
export type Passkey = {
  id: number
  /** "" when the person never named it; the UI shows a default. */
  name: string
  createdAt: string
  /** "" when it has never been used to sign in. */
  lastUsedAt: string
  /** The authenticator may sync the passkey to other devices. */
  backupEligible: boolean
  /** The passkey is currently synced (backed up). */
  backupState: boolean
}

/** A signed-in browser session (GET /api/account/sessions). */
export type AccountSession = {
  id: number
  createdAt: string
  lastSeenAt: string
  ip: string
  userAgent: string
  /**
   * Authentication methods: "pwd", "otp", "email", "webauthn", … The store
   * keeps them space-separated, so a bare string is accepted too.
   */
  amr: string[] | string
  /** True for the session making the request. */
  current: boolean
}

/** Options for a passkey prompt, plus the id the answer is posted back with. */
export type PasskeyCeremony<Options> = {
  publicKey: Options
  ceremonyId: string
}

export type AppClientType = "confidential" | "public"
export type TokenEndpointAuthMethod =
  "client_secret_basic" | "client_secret_post" | "none"
export type AppStatus = "active" | "suspended"
export type RegistrationMode = "closed" | "invite" | "open" | "admin_approval"
export type DefaultAccess = "all_users" | "groups" | "members_only"

/** A relying party registered with Fire ID (GET /api/admin/apps). */
export type App = {
  id: number
  slug: string
  name: string
  description: string
  homepageUrl: string
  clientId: string
  clientType: AppClientType
  tokenEndpointAuthMethod: TokenEndpointAuthMethod
  requirePkce: boolean
  ownerUserId: number
  status: AppStatus
  registrationMode: RegistrationMode
  defaultAccess: DefaultAccess
  redirectUris: string[]
  postLogoutRedirectUris: string[]
  scopes: string[]
  grantTypes: string[]
  /** "" when the secret has never been rotated. */
  secretRotatedAt: string
  createdAt: string
  updatedAt: string
}

export type MemberRole = "owner" | "admin" | "member"
export type MemberStatus = "active" | "pending" | "blocked"

export type AppMember = {
  user: User
  role: MemberRole
  status: MemberStatus
  createdAt: string
}

export type Group = {
  id: number
  name: string
  description: string
  memberCount: number
  createdAt: string
}

export type GroupRef = Pick<Group, "id" | "name">

/** Someone asking to use an app whose registration needs approval. */
export type AccessRequest = {
  id: number
  user: User
  message: string
  createdAt: string
}

/** GET /api/admin/apps/:slug */
export type AppDetail = {
  app: App
  members: AppMember[]
  /** Groups whose members may use the app. */
  groups: GroupRef[]
  pendingRequests: AccessRequest[]
  canDelete: boolean
}

/** Fields POST /api/admin/apps accepts. */
export type AppCreate = {
  slug: string
  name: string
  description?: string
  homepageUrl?: string
  clientType?: AppClientType
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod
  redirectUris: string[]
  postLogoutRedirectUris?: string[]
  registrationMode?: RegistrationMode
  defaultAccess?: DefaultAccess
  ownerUserId?: number
}

/** Fields PATCH /api/admin/apps/:slug accepts; omitted ones are unchanged. */
export type AppUpdate = Partial<
  Pick<
    App,
    | "name"
    | "description"
    | "homepageUrl"
    | "tokenEndpointAuthMethod"
    | "redirectUris"
    | "postLogoutRedirectUris"
    | "registrationMode"
    | "defaultAccess"
  >
>
