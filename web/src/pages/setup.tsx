import * as React from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { CircleAlertIcon, InfoIcon } from "lucide-react"
import { toast } from "sonner"
import { z } from "zod"

import { PasswordInput } from "@/components/common/password-input"
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
import { StepCard } from "@/features/sign-in/steps"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode } from "@/lib/errors"
import { qk, queryClient, setupQuery } from "@/lib/queries"
import { refreshSession } from "@/lib/session"
import type { SetupState } from "@/lib/types"

export default function SetupPage() {
  const { t } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(
    () =>
      z
        .object({
          setupToken: z
            .string()
            .trim()
            .min(1, t("auth.validation.tokenRequired")),
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
      setupToken: "",
      username: "admin",
      email: "",
      displayName: "",
      password: "",
      confirm: "",
    },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async (values: FormOut) => {
    setFormError(null)
    try {
      await api.setup.create({
        setupToken: values.setupToken,
        username: values.username,
        email: values.email,
        displayName: values.displayName,
        password: values.password,
      })
    } catch (error) {
      if (hasCode(error, "invalid_token")) {
        form.setError(
          "setupToken",
          { message: t("common.errors.invalid_token") },
          { shouldFocus: true }
        )
      } else if (hasCode(error, "weak_password")) {
        form.setError(
          "password",
          { message: t("common.errors.weak_password") },
          { shouldFocus: true }
        )
      } else if (hasCode(error, "setup_unavailable")) {
        // Someone else finished setup; the gate moves on to /sign-in.
        toast.info(t("auth.setup.alreadyDone"))
        await queryClient.fetchQuery({ ...setupQuery, staleTime: 0 })
      } else {
        setFormError(errorMessage(error, t))
      }
      return
    }
    toast.success(t("auth.setup.success"))
    await refreshSession().catch(() => {})
    // The setup gate sends /setup to "/" once setup is no longer required.
    queryClient.setQueryData<SetupState>(qk.setup, (prev) =>
      prev ? { ...prev, setupRequired: false } : prev
    )
    void queryClient.invalidateQueries({ queryKey: qk.setup })
  }

  return (
    <AuthShell>
      <StepCard
        title={t("auth.setup.title")}
        description={t("auth.setup.description")}
      >
        <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
          <FieldGroup>
            {formError && (
              <Alert variant="destructive">
                <CircleAlertIcon />
                <AlertDescription>{formError}</AlertDescription>
              </Alert>
            )}
            <Alert>
              <InfoIcon />
              <AlertDescription>{t("auth.setup.tokenHelp")}</AlertDescription>
            </Alert>
            <Field data-invalid={!!errors.setupToken || undefined}>
              <FieldLabel htmlFor="setupToken">
                {t("auth.setup.token")}
              </FieldLabel>
              <Input
                id="setupToken"
                autoComplete="off"
                spellCheck={false}
                autoFocus
                className="font-mono"
                placeholder={t("auth.setup.tokenPlaceholder")}
                aria-invalid={!!errors.setupToken}
                {...form.register("setupToken")}
              />
              <FieldError errors={[errors.setupToken]} />
            </Field>
            <Field data-invalid={!!errors.username || undefined}>
              <FieldLabel htmlFor="username">
                {t("auth.fields.username")}
              </FieldLabel>
              <Input
                id="username"
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                aria-invalid={!!errors.username}
                {...form.register("username")}
              />
              <FieldError errors={[errors.username]} />
            </Field>
            <Field data-invalid={!!errors.email || undefined}>
              <FieldLabel htmlFor="email">{t("auth.fields.email")}</FieldLabel>
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
            <Field data-invalid={!!errors.displayName || undefined}>
              <FieldLabel htmlFor="displayName">
                {t("auth.fields.displayName")}
              </FieldLabel>
              <Input
                id="displayName"
                autoComplete="name"
                aria-invalid={!!errors.displayName}
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
                ? t("auth.setup.submitting")
                : t("auth.setup.submit")}
            </Button>
          </FieldGroup>
        </form>
      </StepCard>
    </AuthShell>
  )
}
