import { toast } from "sonner"

import type { Translate } from "@/i18n"
import { isApiError } from "@/lib/api"
import { webauthnErrorMessage } from "@/lib/webauthn"

// API error codes the UI has its own wording for; anything else falls back to
// the server's English message.
const KNOWN_CODES = [
  "invalid_credentials",
  "invalid_code",
  "cross_site",
  "email_unavailable",
  "invalid_body",
  "internal_error",
  "unauthenticated",
  "invalid_token",
  "setup_unavailable",
  "weak_password",
  "conflict",
  "totp_enabled",
  "totp_not_enabled",
  "totp_not_pending",
  "forbidden",
  "second_factor_not_required",
  "totp_enrol_required",
  "invalid_ceremony",
  "cannot_revoke_current",
  "last_credential",
  "not_found",
  "passkeys_unavailable",
] as const

type KnownCode = (typeof KNOWN_CODES)[number]

function isKnownCode(code: string): code is KnownCode {
  return (KNOWN_CODES as readonly string[]).includes(code)
}

/** Human-readable message for any thrown value. */
export function errorMessage(error: unknown, t: Translate) {
  if (isApiError(error)) {
    if (error.code === "network") return t("common.errors.network")
    if (error.code === "rate_limited") {
      return error.retryAfter
        ? t("common.errors.rate_limited", { seconds: error.retryAfter })
        : t("common.errors.rateLimitedNoWait")
    }
    if (isKnownCode(error.code)) return t(`common.errors.${error.code}`)
    return error.message
  }
  const webauthn = webauthnErrorMessage(error, t)
  if (webauthn) return webauthn
  if (error instanceof Error) return error.message
  return t("common.errors.title")
}

export function toastError(error: unknown, t: Translate, title?: string) {
  const message = errorMessage(error, t)
  if (title) toast.error(title, { description: message })
  else toast.error(message)
}

/** True for API errors with one of the given codes. */
export function hasCode(error: unknown, ...codes: string[]) {
  return isApiError(error) && codes.includes(error.code)
}
