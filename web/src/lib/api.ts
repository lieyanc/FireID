import type {
  ApiErrorBody,
  Me,
  RecoveryCodes,
  SetupState,
  SignedIn,
  SignInResult,
  TotpEnrolment,
  User,
  VersionInfo,
} from "@/lib/types"

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
  },
}
