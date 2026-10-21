import { toast } from "sonner"

import { setUnauthenticatedListener } from "@/lib/api"
import { meQuery, qk, queryClient } from "@/lib/queries"

/** Re-reads the session after a sign-in so the account page sees it. */
export function refreshSession() {
  return queryClient.fetchQuery({ ...meQuery, staleTime: 0 })
}

/** Forgets everything cached for the signed-out session. */
export function signedOut() {
  queryClient.setQueryData(qk.me, null)
  queryClient.removeQueries({
    predicate: (query) =>
      query.queryKey[0] !== qk.me[0] && query.queryKey[0] !== qk.setup[0],
  })
}

let checking = false

/**
 * A 401 unauthenticated from any account call means the session may be gone:
 * re-check it and, if it really ended, drop cached data so the session gate
 * sends the person to /sign-in.
 */
export function installUnauthenticatedHandler(
  sessionExpiredMessage: () => string
) {
  setUnauthenticatedListener((path) => {
    if (path.startsWith("/api/auth/") || checking) return
    if (!queryClient.getQueryData(qk.me)) return
    checking = true
    void refreshSession()
      .then((me) => {
        if (!me) {
          toast.warning(sessionExpiredMessage())
          signedOut()
        }
      })
      .catch(() => {})
      .finally(() => {
        checking = false
      })
  })
}
