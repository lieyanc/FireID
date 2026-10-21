import type {
  AccessRequest,
  AccountSession,
  ApiErrorBody,
  App,
  AppCreate,
  AppDetail,
  AppMember,
  AppStatus,
  AppUpdate,
  AuditFilter,
  AuditPage,
  ForwardAuthSetup,
  Group,
  Me,
  MemberRole,
  MemberStatus,
  Passkey,
  PasskeyCeremony,
  RecoveryCodes,
  SetupState,
  SignedIn,
  SignInResult,
  SigningKey,
  TotpEnrolment,
  User,
  VersionInfo,
} from "@/lib/types"
import type {
  AssertionResponseJSON,
  CreationOptionsJSON,
  RegistrationResponseJSON,
  RequestOptionsJSON,
} from "@/lib/webauthn"

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  /** Seconds, from the Retry-After header on 429 responses. */
  readonly retryAfter?: number

  constructor(
    status: number,
    code: string,
    message: string,
    retryAfter?: number
  ) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.code = code
    this.retryAfter = retryAfter
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError
}

type UnauthenticatedListener = (path: string) => void
let unauthenticatedListener: UnauthenticatedListener | null = null

/**
 * Registers the handler called whenever a request reports that the session is
 * gone. Only `401 unauthenticated` counts: a wrong code or password is also a
 * 401, but with its own error code.
 */
export function setUnauthenticatedListener(
  listener: UnauthenticatedListener | null
) {
  unauthenticatedListener = listener
}

async function toApiError(res: Response): Promise<ApiError> {
  let body: Partial<ApiErrorBody> = {}
  try {
    body = (await res.json()) as Partial<ApiErrorBody>
  } catch {
    // Non-JSON error (e.g. a proxy page); fall back to the status text.
  }
  const retryHeader = res.headers.get("Retry-After")
  const retryAfter = retryHeader ? Number(retryHeader) : undefined
  return new ApiError(
    res.status,
    body.error ?? (res.status === 401 ? "unauthenticated" : "internal_error"),
    body.message || res.statusText || `HTTP ${res.status}`,
    Number.isFinite(retryAfter) ? retryAfter : undefined
  )
}

export async function request<T>(
  method: string,
  path: string,
  options: { body?: unknown; signal?: AbortSignal } = {}
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" }
  const init: RequestInit = {
    method,
    headers,
    credentials: "same-origin",
    signal: options.signal,
  }
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json"
    init.body = JSON.stringify(options.body)
  }

  let res: Response
  try {
    res = await fetch(path, init)
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error
    }
    throw new ApiError(0, "network", "Network error")
  }
  if (!res.ok) {
    const error = await toApiError(res)
    if (error.code === "unauthenticated") unauthenticatedListener?.(path)
    throw error
  }
  if (res.status === 204) return undefined as T
  const text = await res.text()
  return (text ? JSON.parse(text) : undefined) as T
}

const get = <T>(path: string) => request<T>("GET", path)
const post = <T>(path: string, body?: unknown) =>
  request<T>("POST", path, { body: body ?? {} })

// The backend rejects unknown fields; JSON.stringify drops undefined ones, so
// optional fields are passed as undefined rather than "".

const appPath = (slug: string) => `/api/admin/apps/${encodeURIComponent(slug)}`

/** Query string of an audit log page; empty filters are left out. */
function auditQuery(filter: AuditFilter, before?: number, limit?: number) {
  const params = new URLSearchParams()
  if (filter.event) params.set("event", filter.event)
  if (filter.app) params.set("app", filter.app)
  if (filter.user !== undefined) params.set("user", String(filter.user))
  if (before !== undefined) params.set("before", String(before))
  if (limit !== undefined) params.set("limit", String(limit))
  const query = params.toString()
  return query ? `?${query}` : ""
}

export type PasswordCredentials = {
  username: string
  password: string
  authReqId?: string
}

export type EmailVerifyBody = (
  { email: string; code: string } | { token: string }
) & { totp?: string; authReqId?: string }

export const api = {
  version: () => get<VersionInfo>("/api/version"),
  setup: {
    state: () => get<SetupState>("/api/setup"),
    create: (body: {
      setupToken: string
      username: string
      email: string
      displayName: string
      password: string
    }) => post<{ user: User }>("/api/setup", body),
  },
  auth: {
    me: () => get<Me>("/api/auth/me"),
    logout: () => post<void>("/api/auth/logout"),
    login: (body: PasswordCredentials) =>
      post<SignInResult>("/api/auth/login", body),
    loginTotp: (body: PasswordCredentials & { code: string }) =>
      post<SignedIn>("/api/auth/login/totp", body),
    enrolTotp: (body: { username: string; password: string }) =>
      post<TotpEnrolment>("/api/auth/login/totp/enrol", body),
    emailStart: (body: {
      email: string
      authReqId?: string
      /** Language of the email: the UI's current one. */
      lang?: "en" | "zh"
    }) => post<Record<string, never>>("/api/auth/email/start", body),
    emailVerify: (body: EmailVerifyBody) =>
      post<SignInResult>("/api/auth/email/verify", body),
    passkeyBegin: () =>
      post<PasskeyCeremony<RequestOptionsJSON>>(
        "/api/auth/login/passkey/begin"
      ),
    passkeyFinish: (body: {
      ceremonyId: string
      response: AssertionResponseJSON
      authReqId?: string
    }) => post<SignedIn>("/api/auth/login/passkey/finish", body),
  },
  account: {
    enrolTotp: (password?: string) =>
      post<TotpEnrolment>("/api/account/totp/enrol", { password }),
    confirmTotp: (code: string) =>
      post<RecoveryCodes>("/api/account/totp/confirm", { code }),
    disableTotp: (code: string) =>
      post<void>("/api/account/totp/disable", { code }),
    regenerateRecoveryCodes: (code: string) =>
      post<RecoveryCodes>("/api/account/recovery-codes", { code }),
    passkeys: {
      list: () => get<{ passkeys: Passkey[] }>("/api/account/passkeys"),
      begin: (password?: string) =>
        post<PasskeyCeremony<CreationOptionsJSON>>(
          "/api/account/passkeys/begin",
          { password }
        ),
      finish: (body: {
        ceremonyId: string
        name: string
        response: RegistrationResponseJSON
      }) => post<{ passkey: Passkey }>("/api/account/passkeys/finish", body),
      rename: (id: number, name: string) =>
        post<void>(`/api/account/passkeys/${id}/rename`, { name }),
      delete: (id: number) =>
        request<void>("DELETE", `/api/account/passkeys/${id}`),
    },
    sessions: {
      list: () => get<{ sessions: AccountSession[] }>("/api/account/sessions"),
      revoke: (id: number) =>
        request<void>("DELETE", `/api/account/sessions/${id}`),
      /** Signs out every session but the one making the request. */
      revokeOthers: () => post<void>("/api/account/sessions/revoke-others"),
    },
    updateProfile: (displayName: string) =>
      request<void>("PATCH", "/api/account/profile", {
        body: { displayName },
      }),
    changePassword: (currentPassword: string, newPassword: string) =>
      post<void>("/api/account/password", { currentPassword, newPassword }),
  },
  admin: {
    apps: () => get<{ apps: App[] }>("/api/admin/apps"),
    app: (slug: string) => get<AppDetail>(appPath(slug)),
    /** clientSecret is "" for public clients; it is never returned again. */
    createApp: (body: AppCreate) =>
      post<{ app: App; clientSecret: string }>("/api/admin/apps", body),
    updateApp: (slug: string, body: AppUpdate) =>
      request<void>("PATCH", appPath(slug), { body }),
    deleteApp: (slug: string) => request<void>("DELETE", appPath(slug)),
    rotateAppSecret: (slug: string) =>
      post<{ clientSecret: string }>(`${appPath(slug)}/secret/rotate`, {}),
    setAppStatus: (slug: string, status: AppStatus) =>
      post<void>(`${appPath(slug)}/status`, { status }),
    appMembers: (slug: string) =>
      get<{ members: AppMember[] }>(`${appPath(slug)}/members`),
    /** Adds the person, or changes the role and status of an existing member. */
    addAppMember: (
      slug: string,
      body: { userId: number; role: MemberRole; status: MemberStatus }
    ) => post<{ member: AppMember }>(`${appPath(slug)}/members`, body),
    removeAppMember: (slug: string, userId: number) =>
      request<void>("DELETE", `${appPath(slug)}/members/${userId}`),
    /** Replaces the groups whose members may use the app. */
    setAppGroups: (slug: string, groupIds: number[]) =>
      post<void>(`${appPath(slug)}/groups`, { groupIds }),
    accessRequests: (slug: string) =>
      get<{ requests: AccessRequest[] }>(`${appPath(slug)}/access-requests`),
    decideAccessRequest: (slug: string, id: number, approve: boolean) =>
      post<void>(`${appPath(slug)}/access-requests/${id}/decide`, { approve }),
    forwardAuth: (slug: string) =>
      get<ForwardAuthSetup>(`${appPath(slug)}/forward-auth`),
    /** The events of one app, newest first. */
    appAudit: (
      slug: string,
      filter: Pick<AuditFilter, "event">,
      before?: number,
      limit?: number
    ) =>
      get<AuditPage>(
        `${appPath(slug)}/audit${auditQuery(filter, before, limit)}`
      ),
    /** Every event, newest first (super admin). */
    audit: (filter: AuditFilter, before?: number) =>
      get<AuditPage>(`/api/admin/audit${auditQuery(filter, before)}`),
    signingKeys: () => get<{ keys: SigningKey[] }>("/api/admin/signing-keys"),
    /** Makes a new key current; the old one stays published. */
    rotateSigningKey: () =>
      post<{ kid: string }>("/api/admin/signing-keys/rotate"),
    /** Stops publishing a key that is no longer current. */
    retireSigningKey: (kid: string) =>
      post<void>(`/api/admin/signing-keys/${encodeURIComponent(kid)}/retire`),
    groups: () => get<{ groups: Group[] }>("/api/admin/groups"),
    createGroup: (body: { name: string; description: string }) =>
      post<{ group: Group }>("/api/admin/groups", body),
    updateGroup: (id: number, body: { name: string; description: string }) =>
      request<void>("PATCH", `/api/admin/groups/${id}`, { body }),
    deleteGroup: (id: number) =>
      request<void>("DELETE", `/api/admin/groups/${id}`),
    groupMembers: (id: number) =>
      get<{ users: User[] }>(`/api/admin/groups/${id}/members`),
    /** Replaces the group's members. */
    setGroupMembers: (id: number, userIds: number[]) =>
      post<void>(`/api/admin/groups/${id}/members`, { userIds }),
    /**
     * Super admins get a prefix search; anyone else at most the one account
     * whose username or email matches exactly.
     */
    searchUsers: (q: string, signal?: AbortSignal) =>
      request<{ users: User[] }>(
        "GET",
        `/api/admin/users/search?${new URLSearchParams({ q })}`,
        { signal }
      ),
  },
}
