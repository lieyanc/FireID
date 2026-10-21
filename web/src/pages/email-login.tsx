import * as React from "react"
import { Link } from "react-router"
import { CircleAlertIcon, LinkIcon } from "lucide-react"

import { AuthShell } from "@/components/layout/auth-shell"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { FieldGroup } from "@/components/ui/field"
import { Spinner } from "@/components/ui/spinner"
import { useSignInFlow } from "@/features/sign-in/flow"
import { SharedStep, StepCard } from "@/features/sign-in/steps"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode } from "@/lib/errors"

type MagicLink = { token: string; authReqId?: string }

/** The link carries its token in the fragment, which never reaches a server. */
function readFragment(): MagicLink | null {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ""))
  const token = params.get("token")
  if (!token) return null
  return { token, authReqId: params.get("auth_req_id") || undefined }
}

export default function EmailLoginPage() {
  const { t } = useI18n()
  const [link] = React.useState(readFragment)
  const flow = useSignInFlow()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  // Drop the token from the address bar and history as soon as it is read.
  // Keep the router's history state so back/forward still work.
  React.useEffect(() => {
    if (!window.location.hash) return
    const { pathname, search } = window.location
    window.history.replaceState(window.history.state, "", pathname + search)
  }, [])

  const signInAgain = (
    <Button variant="outline" asChild>
      <Link
        to={
          link?.authReqId
            ? `/sign-in?auth_req_id=${encodeURIComponent(link.authReqId)}`
            : "/sign-in"
        }
      >
        {t("auth.emailLink.toSignIn")}
      </Link>
    </Button>
  )

  if (!link) {
    return (
      <AuthShell>
        <StepCard
          title={t("auth.emailLink.missingTitle")}
          description={t("auth.emailLink.missingDescription")}
        >
          <div className="flex flex-col">{signInAgain}</div>
        </StepCard>
      </AuthShell>
    )
  }

  // Redeemed only on a button press: mail scanners open links on their own.
  const redeem = async () => {
    setBusy(true)
    setFormError(null)
    const body = { token: link.token, authReqId: link.authReqId }
    try {
      await flow.handle(await api.auth.emailVerify(body), (totp) =>
        api.auth.emailVerify({ ...body, totp })
      )
    } catch (error) {
      setFormError(
        hasCode(error, "invalid_code")
          ? t("auth.emailLink.invalid")
          : errorMessage(error, t)
      )
      setBusy(false)
    }
  }

  return (
    <AuthShell>
      {flow.step.kind === "start" ? (
        <StepCard
          title={t("auth.emailLink.title")}
          description={t("auth.emailLink.description")}
        >
          <FieldGroup>
            {formError && (
              <Alert variant="destructive">
                <CircleAlertIcon />
                <AlertDescription>{formError}</AlertDescription>
              </Alert>
            )}
            <Button
              type="button"
              disabled={busy}
              autoFocus
              onClick={() => void redeem()}
            >
              {busy ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <LinkIcon data-icon="inline-start" />
              )}
              {busy
                ? t("auth.emailLink.submitting")
                : t("auth.emailLink.submit")}
            </Button>
            {formError && signInAgain}
          </FieldGroup>
        </StepCard>
      ) : (
        <SharedStep
          flow={flow}
          onStartOver={() => flow.setStep({ kind: "start" })}
        />
      )}
    </AuthShell>
  )
}
