import type { MessageKey } from "@/i18n"

function isLoopback(hostname: string) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase()
  return host === "localhost" || host === "::1" || /^127\./.test(host)
}

/** Why a redirect URI would be refused (store.ValidateRedirectURI), or null. */
export function redirectUriProblem(raw: string): MessageKey | null {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return "admin.apps.uris.notAbsolute"
  }
  if (!url.host) return "admin.apps.uris.notAbsolute"
  if (raw.includes("#")) return "admin.apps.uris.fragment"
  if (url.username || url.password) return "admin.apps.uris.userinfo"
  if (url.protocol === "https:") return null
  if (url.protocol === "http:") {
    return isLoopback(url.hostname) ? null : "admin.apps.uris.httpNotLoopback"
  }
  return "admin.apps.uris.scheme"
}
