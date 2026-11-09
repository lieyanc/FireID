import * as React from "react"
import { useForm } from "react-hook-form"
import { Link, Navigate, useSearchParams } from "react-router"
import { zodResolver } from "@hookform/resolvers/zod"
import { CircleAlertIcon, InfoIcon } from "lucide-react"
import { toast } from "sonner"
import { z } from "zod"

import { PasswordInput } from "@/components/common/password-input"
import { FullPageSpinner } from "@/components/common/query-state"
import { AuthShell } from "@/components/layout/auth-shell"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { forwardAuthReturn, useSignInFlow } from "@/features/sign-in/flow"
import { SharedStep, StepCard } from "@/features/sign-in/steps"
import { SecondFactorForm } from "@/features/totp/second-factor-form"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode } from "@/lib/errors"
import { useMe, useSetupState } from "@/lib/queries"

/** Same shape the invite page accepts; anything else is dropped. */
const TOKEN = /^[A-Za-z0-9_-]{16,200}$/

type Stage =
  { kind: "form" } | { kind: "code"; email: string } | { kind: "done" }

/**
 * Sign-up. `invite` comes from the URL and is only passed to the API, which
 * checks it; after the email is confirmed the browser returns to the
 * invitation so the person can accept it.
 */
export default function RegisterPage() {
  const { t } = useI18n()
  const [params] = useSearchParams()
  const raw = params.get("invite") ?? ""
  const invite = TOKEN.test(raw) ? raw : undefined
  const me = useMe()
  const setup = useSetupState()
  const flow = useSignInFlow({
    returnTo: invite ? forwardAuthReturn(`/invite/${invite}`) : undefined,
  })
  const [stage, setStage] = React.useState<Stage>({ kind: "form" })

  if (me.isPending || setup.isPending) return <FullPageSpinner />
  if (me.data && stage.kind === "form") {
    return <Navigate to={invite ? `/invite/${invite}` : "/"} replace />
  }

  let content: React.ReactNode
  if (flow.step.kind !== "start") {
    content = (
      <SharedStep flow={flow} onStartOver={() => setStage({ kind: "form" })} />
    )
  } else if (stage.kind === "code") {
    content = (
      <StepCard
        title={t("apps.register.codeTitle")}
        description={t("apps.register.codeSent", { email: stage.email })}
      >
        <SecondFactorForm
          label={t("auth.email.code")}
          submitLabel={t("apps.register.codeSubmit")}
          submittingLabel={t("auth.email.submitting")}
          onSubmit={async (code) => {
            const body = { email: stage.email, code }
            await flow.handle(await api.auth.emailVerify(body), (totp) =>
              api.auth.emailVerify({ ...body, totp })
            )
          }}
        />
      </StepCard>
    )
  } else if (stage.kind === "done") {
    content = (
      <StepCard
        title={t("apps.register.noEmailTitle")}
        description={t("apps.register.noEmailDescription")}
      >
        <Button variant="outline" className="w-full" asChild>
          <Link to="/sign-in">{t("apps.register.haveAccount")}</Link>
        </Button>
      </StepCard>
    )
  } else {
    content = (
      <RegisterForm
        invite={invite}
        closed={setup.data?.registration !== "open" && !invite}
        onCreated={(email, verify) =>
          setStage(verify ? { kind: "code", email } : { kind: "done" })
        }
      />
    )
  }
  return <AuthShell>{content}</AuthShell>
}

function RegisterForm({
  invite,
  closed,
  onCreated,
}: {
  invite?: string
  closed: boolean
  onCreated: (email: string, emailVerification: boolean) => void
}) {
  const { t, lang } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(
    () =>
      z
        .object({
          username: z
            .string()
            .trim()
            .min(1, t("auth.validation.usernameRequired")),
          email: z
            .string()
            .trim()
            .pipe(z.email(t("auth.validation.emailInvalid"))),
          displayName: z.string().trim(),
          password: z.string().min(1, t("auth.validation.passwordNew")),
          confirm: z.string(),
        })
        .refine((v) => v.password === v.confirm, {
          path: ["confirm"],
          message: t("auth.validation.passwordMismatch"),
        }),
    [t]
  )
  type FormIn = z.input<typeof schema>
  type FormOut = z.output<typeof schema>

  const form = useForm<FormIn, unknown, FormOut>({
    resolver: zodResolver(schema),
    defaultValues: {
      username: "",
      email: "",
      displayName: "",
      password: "",
      confirm: "",
    },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async (values: FormOut) => {
    setFormError(null)
    let result: { emailVerification: boolean }
    try {
      result = await api.register({
        username: values.username,
        email: values.email,
        password: values.password,
        displayName: values.displayName || undefined,
        invite,
        lang,
      })
    } catch (error) {
      if (hasCode(error, "weak_password")) {
        form.setError(
          "password",
          { message: t("common.errors.weak_password") },
          { shouldFocus: true }
        )
      } else if (hasCode(error, "conflict")) {
        setFormError(t("apps.register.taken"))
      } else if (hasCode(error, "not_found")) {
        setFormError(t("apps.register.invalidInvite"))
      } else if (hasCode(error, "forbidden")) {
        setFormError(t("apps.register.closed"))
      } else {
        setFormError(errorMessage(error, t))
      }
      return
    }
    toast.success(t("apps.register.created"))
    onCreated(values.email, result.emailVerification)
  }

  const signIn = invite
    ? `/sign-in?${new URLSearchParams({ return: `/invite/${invite}` })}`
    : "/sign-in"

  return (
    <StepCard
      title={t("apps.register.title")}
      description={t("apps.register.description")}
    >
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          {formError && (
            <Alert variant="destructive">
              <CircleAlertIcon />
              <AlertDescription>{formError}</AlertDescription>
            </Alert>
          )}
          {invite && (
            <Alert>
              <InfoIcon />
              <AlertDescription>
                {t("apps.register.inviteNote")}
              </AlertDescription>
            </Alert>
          )}
          {closed ? (
            <Alert>
              <InfoIcon />
              <AlertDescription>{t("apps.register.closed")}</AlertDescription>
            </Alert>
          ) : (
            <>
              <Field data-invalid={!!errors.username || undefined}>
                <FieldLabel htmlFor="username">
                  {t("auth.fields.username")}
                </FieldLabel>
                <Input
                  id="username"
                  autoComplete="username"
                  autoCapitalize="none"
                  spellCheck={false}
                  autoFocus
                  aria-invalid={!!errors.username}
                  {...form.register("username")}
                />
                <FieldError errors={[errors.username]} />
              </Field>
              <Field data-invalid={!!errors.email || undefined}>
                <FieldLabel htmlFor="email">
                  {t("auth.fields.email")}
                </FieldLabel>
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  autoCapitalize="none"
                  spellCheck={false}
                  aria-invalid={!!errors.email}
                  {...form.register("email")}
                />
                <FieldError errors={[errors.email]} />
              </Field>
              <Field>
                <FieldLabel htmlFor="displayName">
                  {t("auth.fields.displayName")}
                </FieldLabel>
                <Input
                  id="displayName"
                  autoComplete="name"
                  {...form.register("displayName")}
                />
                <FieldDescription>
                  {t("auth.fields.displayNameHint")}
                </FieldDescription>
              </Field>
              <Field data-invalid={!!errors.password || undefined}>
                <FieldLabel htmlFor="password">
                  {t("auth.fields.password")}
                </FieldLabel>
                <PasswordInput
                  id="password"
                  autoComplete="new-password"
                  aria-invalid={!!errors.password}
                  {...form.register("password")}
                />
                <FieldError errors={[errors.password]} />
              </Field>
              <Field data-invalid={!!errors.confirm || undefined}>
                <FieldLabel htmlFor="confirm">
                  {t("auth.fields.confirmPassword")}
                </FieldLabel>
                <PasswordInput
                  id="confirm"
                  autoComplete="new-password"
                  aria-invalid={!!errors.confirm}
                  {...form.register("confirm")}
                />
                <FieldError errors={[errors.confirm]} />
              </Field>
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting && <Spinner data-icon="inline-start" />}
                {isSubmitting
                  ? t("apps.register.submitting")
                  : t("apps.register.submit")}
              </Button>
            </>
          )}
          <Button
            variant="link"
            size="sm"
            className="text-muted-foreground"
            asChild
          >
            <Link to={signIn}>{t("apps.register.haveAccount")}</Link>
          </Button>
        </FieldGroup>
      </form>
    </StepCard>
  )
}
