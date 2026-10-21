import * as React from "react"
import { Link, useNavigate, useSearchParams } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { LogOutIcon } from "lucide-react"

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
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { hasCode, toastError } from "@/lib/errors"
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

/** Same cap as an app's name; anyone can put any text in the link. */
const MAX_APP_NAME = 100

function appName(value: string | null) {
  const chars = Array.from(value?.trim() ?? "")
  if (chars.length <= MAX_APP_NAME) return chars.join("")
  return chars.slice(0, MAX_APP_NAME).join("") + "…"
}

/**
 * Where forward auth sends a signed-in person who may not use the site's
 * app. Both query parameters are untrusted: they only pick a message.
 */
export default function DeniedPage() {
  const { t } = useI18n()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [busy, setBusy] = React.useState(false)

  const app = appName(params.get("app"))
  const reason = REASONS[params.get("reason") ?? ""] ?? REASONS.not_permitted

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
            {app
              ? t("auth.denied.title", { app })
              : t("auth.denied.titleUnknown")}
          </CardTitle>
          <CardDescription>{t(reason)}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
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
