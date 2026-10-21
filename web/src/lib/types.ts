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
