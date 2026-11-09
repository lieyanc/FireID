import * as React from "react"
import { Link, useNavigate, useSearchParams } from "react-router"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowRightIcon, LogOutIcon } from "lucide-react"

import { AuthShell } from "@/components/layout/auth-shell"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Spinner } from "@/components/ui/spinner"
import { JoinButton, RequestAccessButton } from "@/features/apps/join-actions"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { hasCode, toastError } from "@/lib/errors"
import { qk, useMe } from "@/lib/queries"
import { signedOut } from "@/lib/session"

/**
 * Refusal reasons from store.CanUseApp. Anything else reads as not_permitted.
 */
const REASONS: Record<string, MessageKey> = {
  pending_approval: "auth.denied.reason.pending_approval",
  blocked: "auth.denied.reason.blocked",
  app_suspended: "auth.denied.reason.app_suspended",
  user_not_active: "auth.denied.reason.user_not_active",
  not_permitted: "auth.denied.reason.not_permitted",
}

const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/**
 * Where forward auth and the OIDC sign-in send a signed-in person who may not
 * use the app. Every query parameter is untrusted: `app` (the slug) is only
 * passed to GET /api/apps/:slug, and joining or asking goes through
 * the API, which decides again. `auth_req_id` only resumes a sign-in through
 * the backend's /login, which checks it as well.
 */
export default function DeniedPage() {
  const { t } = useI18n()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [busy, setBusy] = React.useState(false)

  const slug = params.get("app") ?? ""
  const authReqId = params.get("auth_req_id") || undefined
  const reason = REASONS[params.get("reason") ?? ""] ?? REASONS.not_permitted
  const me = useMe()
  const lookup = useQuery({
    queryKey: qk.catalogApp(slug),
    queryFn: async () => (await api.catalog.app(slug)).app,
    enabled: !!me.data && SLUG_PATTERN.test(slug),
  })
  const entry = lookup.data
  // Only a name the API confirmed is shown; the slug in the link is not.
  const app = entry?.name ?? ""
  // After joining, an OIDC sign-in carries on where it stopped.
  const resume = authReqId
    ? `/login?${new URLSearchParams({ auth_req_id: authReqId })}`
    : undefined

  const switchAccount = async () => {
    setBusy(true)
    try {
      await api.auth.logout()
    } catch (error) {
      // Already signed out is as good as signing out now.
      if (!hasCode(error, "unauthenticated")) {
        setBusy(false)
        toastError(error, t)
        return
      }
    }
    await queryClient.cancelQueries()
    signedOut()
    navigate("/sign-in", { replace: true })
  }

  return (
    <AuthShell>
      <Card>
        <CardHeader>
          <CardTitle className="break-words">
            {entry?.state === "allowed"
              ? t("apps.denied.allowedTitle", { app })
              : app
                ? t("auth.denied.title", { app })
                : t("auth.denied.titleUnknown")}
          </CardTitle>
          <CardDescription>
            {entry?.state === "allowed"
              ? t("apps.denied.allowed")
              : entry?.state === "pending"
                ? t("auth.denied.reason.pending_approval")
                : entry?.join === "join"
                  ? t("apps.denied.canJoin")
                  : entry?.join === "request"
                    ? t("apps.denied.canRequest")
                    : t(reason)}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {entry?.state === "allowed" && resume && (
            <Button asChild>
              <a href={resume}>
                {t("apps.denied.continue", { app })}
                <ArrowRightIcon data-icon="inline-end" />
              </a>
            </Button>
          )}
          {entry?.state === "available" && entry.join === "join" && (
            <JoinButton slug={entry.slug} name={entry.name} />
          )}
          {entry?.state === "available" && entry.join === "request" && (
            <RequestAccessButton slug={entry.slug} name={entry.name} />
          )}
          <Button asChild>
            <Link to="/">{t("auth.denied.home")}</Link>
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={busy}
            onClick={() => void switchAccount()}
          >
            {busy ? (
              <Spinner data-icon="inline-start" />
            ) : (
              <LogOutIcon data-icon="inline-start" />
            )}
            {busy ? t("auth.denied.switching") : t("auth.denied.switchAccount")}
          </Button>
        </CardContent>
      </Card>
    </AuthShell>
  )
}
