import * as React from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Link, useNavigate, useParams } from "react-router"
import {
  CircleAlertIcon,
  ExternalLinkIcon,
  LogInIcon,
  LogOutIcon,
  UserPlusIcon,
} from "lucide-react"

import { FullPageSpinner, QueryError } from "@/components/common/query-state"
import { AuthShell } from "@/components/layout/auth-shell"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Spinner } from "@/components/ui/spinner"
import { AppLogo } from "@/features/apps/app-logo"
import { inviteSignInPath } from "@/features/sign-in/flow"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode, toastError } from "@/lib/errors"
import { qk, useMe } from "@/lib/queries"
import { signedOut } from "@/lib/session"
import type { InvitePreview } from "@/lib/types"
import { displayName } from "@/lib/user"
import { httpUrl } from "@/lib/utils"

/** Invite tokens are 32 random bytes in base64url; anything else is junk. */
const TOKEN = /^[A-Za-z0-9_-]{16,200}$/

type Accepted = { slug: string; name: string; homepageUrl: string }

/**
 * Where an invitation link lands. The token comes from the URL, so it is only
 * ever passed to the API, which decides whether it is any good.
 */
export default function InvitePage() {
  const { token = "" } = useParams()
  const valid = TOKEN.test(token)
  const me = useMe()
  const preview = useQuery({
    queryKey: qk.invitePreview(token),
    queryFn: () => api.invites.preview(token),
    enabled: valid,
    staleTime: 60_000,
  })

  if (valid && (preview.isPending || me.isPending)) return <FullPageSpinner />

  let content: React.ReactNode
  if (!valid || hasCode(preview.error, "not_found")) {
    content = <InvalidCard />
  } else if (preview.isError) {
    content = (
      <QueryError
        error={preview.error}
        onRetry={() => void preview.refetch()}
      />
    )
  } else if (preview.data) {
    content = (
      <InviteCard
        token={token}
        preview={preview.data}
        signedInAs={me.data ? displayName(me.data.user) : null}
      />
    )
  }
  return <AuthShell>{content ?? <InvalidCard />}</AuthShell>
}

function InvalidCard() {
  const { t } = useI18n()
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("apps.invite.invalidTitle")}</CardTitle>
        <CardDescription>{t("apps.invite.invalidDescription")}</CardDescription>
      </CardHeader>
      <CardContent>
        <Button variant="outline" className="w-full" asChild>
          <Link to="/">{t("auth.denied.home")}</Link>
        </Button>
      </CardContent>
    </Card>
  )
}

function InviteCard({
  token,
  preview,
  signedInAs,
}: {
  token: string
  preview: InvitePreview
  signedInAs: string | null
}) {
  const { t, fmt } = useI18n()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState<unknown>(null)
  const [accepted, setAccepted] = React.useState<Accepted | null>(null)
  const name = preview.app.name

  const accept = async () => {
    setBusy(true)
    setError(null)
    try {
      const result = await api.invites.accept(token)
      setAccepted(result.app)
      void queryClient.invalidateQueries({ queryKey: qk.catalog })
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  const switchAccount = async () => {
    setBusy(true)
    try {
      await api.auth.logout()
    } catch (err) {
      if (!hasCode(err, "unauthenticated")) {
        setBusy(false)
        toastError(err, t)
        return
      }
    }
    await queryClient.cancelQueries()
    signedOut()
    navigate(inviteSignInPath(token), { replace: true })
  }

  if (accepted) {
    const homepage = httpUrl(accepted.homepageUrl)
    return (
      <Card>
        <CardHeader>
          <CardTitle className="break-words">
            {t("apps.invite.accepted", { app: accepted.name })}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {homepage && (
            <Button asChild>
              <a href={homepage} rel="noopener noreferrer">
                <ExternalLinkIcon data-icon="inline-start" />
                {t("apps.invite.openApp", { app: accepted.name })}
              </a>
            </Button>
          )}
          <Button variant="outline" asChild>
            <Link to="/apps">{t("apps.invite.allApps")}</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  const problem = hasCode(error, "invite_email_mismatch")
    ? t("apps.invite.emailMismatch")
    : hasCode(error, "blocked")
      ? t("apps.invite.blocked")
      : hasCode(error, "not_found")
        ? t("apps.invite.invalidDescription")
        : error
          ? errorMessage(error, t)
          : null

  return (
    <Card>
      <CardHeader className="flex flex-row items-start gap-3">
        <AppLogo url={preview.app.logoUrl} />
        <div className="grid min-w-0 gap-1">
          <CardTitle className="break-words">
            {t("apps.invite.title", { app: name })}
          </CardTitle>
          <CardDescription>{t("apps.invite.description")}</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {preview.app.description && (
          <p className="text-sm break-words whitespace-pre-line">
            {preview.app.description}
          </p>
        )}
        <div className="grid gap-0.5 text-sm text-muted-foreground">
          {preview.email && (
            <p className="break-all">
              {t("apps.invite.forEmail", { email: preview.email })}
            </p>
          )}
          <p title={fmt.dateTime(preview.expiresAt)}>
            {t("apps.invite.expires", {
              date: fmt.relative(preview.expiresAt),
            })}
          </p>
          {signedInAs && (
            <p className="break-words">
              {t("apps.invite.signedInAs", { name: signedInAs })}
            </p>
          )}
        </div>
        {problem && (
          <Alert variant="destructive">
            <CircleAlertIcon />
            <AlertDescription>{problem}</AlertDescription>
          </Alert>
        )}
        {signedInAs ? (
          <>
            <Button disabled={busy} onClick={() => void accept()}>
              {busy && <Spinner data-icon="inline-start" />}
              {busy ? t("apps.invite.accepting") : t("apps.invite.accept")}
            </Button>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => void switchAccount()}
            >
              <LogOutIcon data-icon="inline-start" />
              {t("apps.invite.switchAccount")}
            </Button>
          </>
        ) : (
          <>
            <Button asChild>
              <Link to={inviteSignInPath(token)}>
                <LogInIcon data-icon="inline-start" />
                {t("apps.invite.signIn")}
              </Link>
            </Button>
            {/* An invite lets people register even while registration is closed. */}
            <Button variant="outline" asChild>
              <Link to={`/register?${new URLSearchParams({ invite: token })}`}>
                <UserPlusIcon data-icon="inline-start" />
                {t("apps.invite.register")}
              </Link>
            </Button>
          </>
        )}
      </CardContent>
    </Card>
  )
}
