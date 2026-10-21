import { Suspense, useEffect, useRef } from "react"
import { Navigate, Outlet, useLocation } from "react-router"

import {
  FullPageSpinner,
  PageSpinner,
  QueryError,
} from "@/components/common/query-state"
import { AppLayout } from "@/components/layout/app-layout"
import { useI18n } from "@/i18n"
import { useMe, useSetupState } from "@/lib/queries"
import { installUnauthenticatedHandler } from "@/lib/session"

function FullPageError({
  error,
  onRetry,
}: {
  error: unknown
  onRetry: () => void
}) {
  return (
    <div className="flex min-h-svh items-center justify-center p-4">
      <div className="w-full max-w-md">
        <QueryError error={error} onRetry={onRetry} />
      </div>
    </div>
  )
}

// Routes that send the browser to /setup while no administrator exists.
const NEEDS_SETUP = ["/", "/sign-in"]

/**
 * Root route: /setup is reachable only before the first administrator
 * exists, and the account and sign-in pages are not reachable until then.
 */
export function SetupGate() {
  const setup = useSetupState()
  const { pathname } = useLocation()

  if (setup.isPending) return <FullPageSpinner />
  if (setup.isError) {
    return (
      <FullPageError error={setup.error} onRetry={() => void setup.refetch()} />
    )
  }

  const required = setup.data.setupRequired
  if (required && NEEDS_SETUP.includes(pathname)) {
    return <Navigate to="/setup" replace />
  }
  // Past setup, "/" decides: the account page, or /sign-in without a session.
  if (!required && pathname === "/setup") {
    return <Navigate to="/" replace />
  }
  return (
    <Suspense fallback={<FullPageSpinner />}>
      <Outlet />
    </Suspense>
  )
}

/** Signed-in area: anyone without a session goes to /sign-in. */
export function SessionGate() {
  const { t } = useI18n()
  const me = useMe()

  const tRef = useRef(t)
  useEffect(() => {
    tRef.current = t
  }, [t])
  useEffect(() => {
    installUnauthenticatedHandler(() => tRef.current("shell.sessionExpired"))
  }, [])

  if (me.isPending) return <FullPageSpinner />
  if (me.isError) {
    return <FullPageError error={me.error} onRetry={() => void me.refetch()} />
  }
  if (!me.data) return <Navigate to="/sign-in" replace />
  return (
    <AppLayout user={me.data.user}>
      <Suspense fallback={<PageSpinner />}>
        <Outlet />
      </Suspense>
    </AppLayout>
  )
}
