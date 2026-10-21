import * as React from "react"
import { useForm } from "react-hook-form"
import { Navigate, useSearchParams } from "react-router"
import { zodResolver } from "@hookform/resolvers/zod"
import { CircleAlertIcon, InfoIcon, KeyRoundIcon, MailIcon } from "lucide-react"
import { toast } from "sonner"
import { z } from "zod"

import { PasswordInput } from "@/components/common/password-input"
import { FullPageSpinner } from "@/components/common/query-state"
import { AuthShell } from "@/components/layout/auth-shell"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldSeparator,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import {
  forwardAuthReturn,
  useSignInFlow,
  type Credentials,
  type SignInFlow,
} from "@/features/sign-in/flow"
import { BusyCard, SharedStep, StepCard } from "@/features/sign-in/steps"
import { TotpEnrolment } from "@/features/totp/enrolment"
import { SecondFactorForm } from "@/features/totp/second-factor-form"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode, toastError } from "@/lib/errors"
import { useMe, useSetupState } from "@/lib/queries"
import type { TotpEnrolment as Enrolment } from "@/lib/types"
import {
  getPasskey,
  isPasskeyCancelled,
  markPasskeysUnavailable,
  passkeysAvailable,
  usePasskeysOffered,
} from "@/lib/webauthn"

export default function SignInPage() {
  const { t } = useI18n()
  const [params] = useSearchParams()
  const authReqId = params.get("auth_req_id") || undefined
  // The backend's /login adds reauth=1 when it sent a signed-in browser here
  // because the session is not enough for the app (prompt=login, max_age, a
  // higher acr). Bouncing back would loop, so the form is shown instead.
  const reauth = params.get("reauth") === "1"
  // A site protected by forward auth sends the browser here with the
  // authorize URL to come back to. An authorization request wins.
  const returnTo = authReqId
    ? undefined
    : forwardAuthReturn(params.get("return"))
  const me = useMe()
  const emailLogin = !!useSetupState().data?.emailLogin
  const flow = useSignInFlow({ returnTo })
  const { step, setStep } = flow

  const atStart = step.kind === "start"
  // A signed-in visitor with an authorization request goes to the backend's
  // /login, which continues at once when the session is good enough.
  const continueToApp = atStart && !!me.data && !!authReqId && !reauth
  // One coming from a protected site goes straight back to its authorize URL.
  const continueToSite = atStart && !!me.data && !!returnTo

  React.useEffect(() => {
    if (!continueToApp || !authReqId) return
    window.location.assign(
      `/login?auth_req_id=${encodeURIComponent(authReqId)}`
    )
  }, [continueToApp, authReqId])

  React.useEffect(() => {
    if (!continueToSite || !returnTo) return
    window.location.assign(returnTo)
  }, [continueToSite, returnTo])

  if (atStart && me.isPending) return <FullPageSpinner />
  if (atStart && me.data && !authReqId && !returnTo) {
    return <Navigate to="/" replace />
  }

  const startOver = () => setStep({ kind: "start" })

  let content: React.ReactNode
  switch (step.kind) {
    case "start":
      content =
        continueToApp || continueToSite ? (
          <BusyCard message={t("auth.signIn.redirecting")} />
        ) : (
          <PasswordStep
            flow={flow}
            authReqId={authReqId}
            emailLogin={emailLogin}
            defaultUsername={me.data?.user.username}
          />
        )
      break
    case "enrol-intro":
      content = <EnrolIntroStep creds={step.creds} flow={flow} />
      break
    case "enrol":
      content = (
        <EnrolStep
          creds={step.creds}
          enrolment={step.enrolment}
          authReqId={authReqId}
          flow={flow}
          onStartOver={startOver}
        />
      )
      break
    case "email":
      content = (
        <EmailStep
          authReqId={authReqId}
          onSent={(email) => setStep({ kind: "email-code", email })}
          onUsePassword={startOver}
        />
      )
      break
    case "email-code":
      content = (
        <EmailCodeStep
          email={step.email}
          authReqId={authReqId}
          flow={flow}
          onChangeEmail={() => setStep({ kind: "email" })}
          onUsePassword={startOver}
        />
      )
      break
    default:
      content = <SharedStep flow={flow} onStartOver={startOver} />
  }

  return <AuthShell>{content}</AuthShell>
}

function FormAlert({ message }: { message: string | null }) {
  if (!message) return null
  return (
    <Alert variant="destructive">
      <CircleAlertIcon />
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

function PasswordStep({
  flow,
  authReqId,
  emailLogin,
  defaultUsername,
}: {
  flow: SignInFlow
  authReqId?: string
  emailLogin: boolean
  defaultUsername?: string
}) {
  const { t } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)
  const [passkeyBusy, setPasskeyBusy] = React.useState(false)
  const passkeysOffered = usePasskeysOffered() && passkeysAvailable()

  const schema = React.useMemo(
    () =>
      z.object({
        username: z
          .string()
          .trim()
          .min(1, t("auth.validation.usernameRequired")),
        password: z.string().min(1, t("auth.validation.passwordRequired")),
      }),
    [t]
  )
  type Values = z.infer<typeof schema>

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { username: defaultUsername ?? "", password: "" },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async (creds: Credentials) => {
    setFormError(null)
    try {
      const result = await api.auth.login({ ...creds, authReqId })
      const challenge = await flow.handle(result, (code) =>
        api.auth.loginTotp({ ...creds, code, authReqId })
      )
      if (challenge === "totp_enrol") {
        flow.setStep({ kind: "enrol-intro", creds })
      }
    } catch (error) {
      setFormError(errorMessage(error, t))
      form.setFocus("password")
    }
  }

  const signInWithPasskey = async () => {
    setFormError(null)
    setPasskeyBusy(true)
    try {
      const ceremony = await api.auth.passkeyBegin()
      const response = await getPasskey(ceremony.publicKey)
      const result = await api.auth.passkeyFinish({
        ceremonyId: ceremony.ceremonyId,
        response,
        authReqId,
      })
      // A passkey is a complete sign-in on its own: no second factor.
      await flow.finish(result)
    } catch (error) {
      setPasskeyBusy(false)
      if (hasCode(error, "passkeys_unavailable")) {
        markPasskeysUnavailable()
        setFormError(t("common.errors.passkeys_unavailable"))
      } else if (isPasskeyCancelled(error)) {
        // Closing the browser's prompt is a choice, not a failure.
      } else if (hasCode(error, "invalid_credentials")) {
        setFormError(t("passkeys.signIn.failed"))
      } else {
        setFormError(errorMessage(error, t))
      }
    }
  }
  const busy = isSubmitting || passkeyBusy

  return (
    <StepCard
      title={t("auth.signIn.title")}
      description={t(
        authReqId ? "auth.signIn.appDescription" : "auth.signIn.description"
      )}
    >
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          <FormAlert message={formError} />
          <Field data-invalid={!!errors.username || undefined}>
            <FieldLabel htmlFor="username">
              {t("auth.fields.username")}
            </FieldLabel>
            <Input
              id="username"
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              autoFocus={!defaultUsername}
              aria-invalid={!!errors.username}
              {...form.register("username")}
            />
            <FieldError errors={[errors.username]} />
          </Field>
          <Field data-invalid={!!errors.password || undefined}>
            <FieldLabel htmlFor="password">
              {t("auth.fields.password")}
            </FieldLabel>
            <PasswordInput
              id="password"
              autoComplete="current-password"
              autoFocus={!!defaultUsername}
              aria-invalid={!!errors.password}
              {...form.register("password")}
            />
            <FieldError errors={[errors.password]} />
          </Field>
          <Button type="submit" disabled={busy}>
            {isSubmitting && <Spinner data-icon="inline-start" />}
            {isSubmitting
              ? t("auth.signIn.submitting")
              : t("auth.signIn.submit")}
          </Button>
          {(passkeysOffered || emailLogin) && <FieldSeparator />}
          {passkeysOffered && (
            <Button
              type="button"
              variant="outline"
              disabled={busy}
              onClick={() => void signInWithPasskey()}
            >
              {passkeyBusy ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <KeyRoundIcon data-icon="inline-start" />
              )}
              {passkeyBusy
                ? t("passkeys.signIn.waiting")
                : t("passkeys.signIn.button")}
            </Button>
          )}
          {emailLogin && (
            <Button
              type="button"
              variant="outline"
              disabled={busy}
              onClick={() => flow.setStep({ kind: "email" })}
            >
              <MailIcon data-icon="inline-start" />
              {t("auth.signIn.useEmail")}
            </Button>
          )}
        </FieldGroup>
      </form>
    </StepCard>
  )
}

function EnrolIntroStep({
  creds,
  flow,
}: {
  creds: Credentials
  flow: SignInFlow
}) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const start = async () => {
    setBusy(true)
    setFormError(null)
    try {
      const enrolment = await api.auth.enrolTotp(creds)
      flow.setStep({ kind: "enrol", creds, enrolment })
    } catch (error) {
      setFormError(errorMessage(error, t))
      setBusy(false)
    }
  }

  return (
    <StepCard title={t("auth.enrol.title")}>
      <FieldGroup>
        <FormAlert message={formError} />
        <Alert>
          <InfoIcon />
          <AlertDescription>{t("auth.enrol.policy")}</AlertDescription>
        </Alert>
        <Button type="button" disabled={busy} onClick={() => void start()}>
          {busy && <Spinner data-icon="inline-start" />}
          {busy ? t("auth.enrol.starting") : t("auth.enrol.start")}
        </Button>
        <Button
          type="button"
          variant="link"
          size="sm"
          className="text-muted-foreground"
          onClick={() => flow.setStep({ kind: "start" })}
        >
          {t("auth.totp.startOver")}
        </Button>
      </FieldGroup>
    </StepCard>
  )
}

function EnrolStep({
  creds,
  enrolment,
  authReqId,
  flow,
  onStartOver,
}: {
  creds: Credentials
  enrolment: Enrolment
  authReqId?: string
  flow: SignInFlow
  onStartOver: () => void
}) {
  const { t } = useI18n()
  return (
    <StepCard title={t("auth.enrol.title")}>
      <TotpEnrolment
        enrolment={enrolment}
        submitLabel={t("auth.enrol.submit")}
        submittingLabel={t("auth.totp.submitting")}
        onSubmit={async (code) => {
          await flow.finish(
            await api.auth.loginTotp({ ...creds, code, authReqId })
          )
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
      </TotpEnrolment>
    </StepCard>
  )
}

function EmailStep({
  authReqId,
  onSent,
  onUsePassword,
}: {
  authReqId?: string
  onSent: (email: string) => void
  onUsePassword: () => void
}) {
  const { t, lang } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(
    () =>
      z.object({
        email: z
          .string()
          .trim()
          .pipe(z.email(t("auth.validation.emailInvalid"))),
      }),
    [t]
  )
  type Values = z.infer<typeof schema>

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { email: "" },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async ({ email }: Values) => {
    setFormError(null)
    try {
      await api.auth.emailStart({ email, authReqId, lang })
      onSent(email)
    } catch (error) {
      if (hasCode(error, "invalid")) {
        form.setError(
          "email",
          { message: t("auth.validation.emailInvalid") },
          { shouldFocus: true }
        )
      } else {
        setFormError(errorMessage(error, t))
      }
    }
  }

  return (
    <StepCard
      title={t("auth.email.title")}
      description={t("auth.email.description")}
    >
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          <FormAlert message={formError} />
          <Field data-invalid={!!errors.email || undefined}>
            <FieldLabel htmlFor="email">{t("auth.fields.email")}</FieldLabel>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              autoCapitalize="none"
              spellCheck={false}
              autoFocus
              aria-invalid={!!errors.email}
              {...form.register("email")}
            />
            <FieldError errors={[errors.email]} />
          </Field>
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting && <Spinner data-icon="inline-start" />}
            {isSubmitting ? t("auth.email.sending") : t("auth.email.send")}
          </Button>
          <Button
            type="button"
            variant="link"
            size="sm"
            className="text-muted-foreground"
            onClick={onUsePassword}
          >
            {t("auth.signIn.usePassword")}
          </Button>
        </FieldGroup>
      </form>
    </StepCard>
  )
}

function EmailCodeStep({
  email,
  authReqId,
  flow,
  onChangeEmail,
  onUsePassword,
}: {
  email: string
  authReqId?: string
  flow: SignInFlow
  onChangeEmail: () => void
  onUsePassword: () => void
}) {
  const { t, lang } = useI18n()
  const [resending, setResending] = React.useState(false)

  const resend = async () => {
    setResending(true)
    try {
      await api.auth.emailStart({ email, authReqId, lang })
      toast.success(t("auth.email.resent"))
    } catch (error) {
      toastError(error, t)
    } finally {
      setResending(false)
    }
  }

  return (
    <StepCard
      title={t("auth.email.codeTitle")}
      description={t("auth.email.sent", { email })}
    >
      <SecondFactorForm
        label={t("auth.email.code")}
        submitLabel={t("auth.email.submit")}
        submittingLabel={t("auth.email.submitting")}
        onSubmit={async (code) => {
          const body = { email, code, authReqId }
          await flow.handle(await api.auth.emailVerify(body), (totp) =>
            api.auth.emailVerify({ ...body, totp })
          )
        }}
      >
        <Button
          type="button"
          variant="link"
          size="sm"
          disabled={resending}
          onClick={() => void resend()}
        >
          {t("auth.email.resend")}
        </Button>
        <Button
          type="button"
          variant="link"
          size="sm"
          className="text-muted-foreground"
          onClick={onChangeEmail}
        >
          {t("auth.email.changeEmail")}
        </Button>
        {/* Also the way out of totp_enrol_required: enrolment needs the
            password. */}
        <Button
          type="button"
          variant="link"
          size="sm"
          className="text-muted-foreground"
          onClick={onUsePassword}
        >
          {t("auth.signIn.usePassword")}
        </Button>
      </SecondFactorForm>
    </StepCard>
  )
}
