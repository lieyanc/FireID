import { Link } from "react-router"
import { TriangleAlertIcon } from "lucide-react"
import { toast } from "sonner"

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
import { expectSignedIn, type SignInFlow } from "@/features/sign-in/flow"
import { RecoveryCodes } from "@/features/totp/recovery-codes"
import { SecondFactorForm } from "@/features/totp/second-factor-form"
import { useI18n, type MessageKey } from "@/i18n"
import { errorMessage, hasCode } from "@/lib/errors"

export function StepCard({
  title,
  description,
  children,
}: {
  title: string
  description?: string
  children: React.ReactNode
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

/** Placeholder while the browser is about to leave the page. */
export function BusyCard({ message }: { message?: string }) {
  return (
    <Card>
      <CardContent
        aria-live="polite"
        className="flex flex-col items-center gap-3 py-6 text-sm text-muted-foreground"
      >
        <Spinner className="size-6" />
        {message}
      </CardContent>
    </Card>
  )
}

const REQUEST_ERRORS: Record<string, MessageKey> = {
  expired: "auth.requestError.expired",
  stronger_authentication_required:
    "auth.requestError.stronger_authentication_required",
  internal_error: "auth.requestError.internal_error",
}

/**
 * The screens every sign-in shares once the first factor is through. Renders
 * nothing for the page's own steps.
 */
export function SharedStep({
  flow,
  onStartOver,
}: {
  flow: SignInFlow
  onStartOver: () => void
}) {
  const { t } = useI18n()
  const { step } = flow

  switch (step.kind) {
    case "totp":
      return (
        <StepCard title={t("auth.totp.title")}>
          <SecondFactorForm
            allowRecovery
            description={t("auth.totp.description")}
            recoveryDescription={t("auth.totp.recoveryDescription")}
            submitLabel={t("auth.totp.submit")}
            submittingLabel={t("auth.totp.submitting")}
            onSubmit={async (code) => {
              let result
              try {
                result = expectSignedIn(await step.verify(code))
              } catch (error) {
                // TOTP was turned off meanwhile: the first factor decides
                // again, so go back to it.
                if (!hasCode(error, "second_factor_not_required")) throw error
                toast.info(errorMessage(error, t))
                onStartOver()
                return
              }
              await flow.finish(result)
            }}
          >
            <Button
              type="button"
              variant="link"
              size="sm"
              className="text-muted-foreground"
              onClick={onStartOver}
            >
              {t("auth.totp.startOver")}
            </Button>
          </SecondFactorForm>
        </StepCard>
      )
    case "recovery":
      return (
        <StepCard
          title={t("totp.recovery.title")}
          description={t("totp.recovery.description")}
        >
          <RecoveryCodes
            codes={step.result.recoveryCodes ?? []}
            username={step.result.user.username}
            onDone={() => void flow.complete(step.result)}
          />
        </StepCard>
      )
    case "request-error":
      return (
        <StepCard title={t("auth.requestError.title")}>
          <div className="flex flex-col gap-4">
            <Alert>
              <TriangleAlertIcon />
              <AlertDescription>
                {t(
                  REQUEST_ERRORS[step.error] ??
                    "auth.requestError.internal_error"
                )}
              </AlertDescription>
            </Alert>
            <Button asChild>
              <Link to="/" replace>
                {t("auth.requestError.home")}
              </Link>
            </Button>
          </div>
        </StepCard>
      )
    case "redirecting":
      return <BusyCard message={t("auth.signIn.redirecting")} />
    case "finishing":
      return <BusyCard />
    default:
      return null
  }
}
