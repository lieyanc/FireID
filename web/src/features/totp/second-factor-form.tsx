import * as React from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { CircleAlertIcon } from "lucide-react"
import { z } from "zod"

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
import { useI18n } from "@/i18n"
import { errorMessage } from "@/lib/errors"

const TOTP_RE = /^\d{6}$/
// Recovery codes are ten base32 characters shown as xxxxx-xxxxx; the server
// accepts any case, with or without the hyphen.
const RECOVERY_RE = /^[a-z0-9]{10}$/i

type Mode = "totp" | "recovery"

/**
 * Asks for a 6-digit code and, when allowed, lets the person switch to a
 * recovery code. onSubmit throws to report a failure; describeError can turn
 * specific API errors into a message of the caller's own.
 */
export function SecondFactorForm({
  onSubmit,
  submitLabel,
  submittingLabel,
  allowRecovery = false,
  label,
  description,
  recoveryDescription,
  describeError,
  autoFocus = true,
  children,
}: {
  onSubmit: (code: string) => Promise<void>
  submitLabel: string
  submittingLabel: string
  allowRecovery?: boolean
  label?: string
  description?: string
  recoveryDescription?: string
  describeError?: (error: unknown) => string | undefined
  autoFocus?: boolean
  /** Extra actions below the submit button. */
  children?: React.ReactNode
}) {
  const { t } = useI18n()
  const [mode, setMode] = React.useState<Mode>("totp")
  const [formError, setFormError] = React.useState<string | null>(null)
  const id = React.useId()

  const schema = React.useMemo(
    () =>
      z.object({
        code:
          mode === "totp"
            ? z
                .string()
                .transform((v) => v.replace(/\s/g, ""))
                .refine((v) => TOTP_RE.test(v), t("totp.codeInvalid"))
            : z
                .string()
                .trim()
                .refine(
                  (v) => RECOVERY_RE.test(v.replace(/[\s-]/g, "")),
                  t("totp.recoveryInvalid")
                ),
      }),
    [mode, t]
  )
  type FormIn = z.input<typeof schema>
  type FormOut = z.output<typeof schema>

  const form = useForm<FormIn, unknown, FormOut>({
    resolver: zodResolver(schema),
    defaultValues: { code: "" },
  })
  const { errors, isSubmitting } = form.formState

  const submit = async ({ code }: FormOut) => {
    setFormError(null)
    try {
      await onSubmit(code)
    } catch (error) {
      setFormError(describeError?.(error) ?? errorMessage(error, t))
      form.setValue("code", "")
      form.setFocus("code")
    }
  }

  const switchMode = () => {
    setMode((m) => (m === "totp" ? "recovery" : "totp"))
    setFormError(null)
    form.reset({ code: "" })
    // The input remounts with the new mode; focus it on the next frame.
    requestAnimationFrame(() => form.setFocus("code"))
  }

  const hint = mode === "totp" ? description : recoveryDescription

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate>
      <FieldGroup>
        {formError && (
          <Alert variant="destructive">
            <CircleAlertIcon />
            <AlertDescription>{formError}</AlertDescription>
          </Alert>
        )}
        <Field data-invalid={!!errors.code || undefined}>
          <FieldLabel htmlFor={id}>
            {mode === "totp"
              ? (label ?? t("totp.code"))
              : t("totp.recoveryCode")}
          </FieldLabel>
          {mode === "totp" ? (
            <Input
              key="totp"
              id={id}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="123456"
              autoFocus={autoFocus}
              className="font-mono tracking-widest"
              aria-invalid={!!errors.code}
              {...form.register("code")}
            />
          ) : (
            <Input
              key="recovery"
              id={id}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              maxLength={16}
              placeholder="xxxxx-xxxxx"
              className="font-mono tracking-wider"
              aria-invalid={!!errors.code}
              {...form.register("code")}
            />
          )}
          {errors.code ? (
            <FieldError errors={[errors.code]} />
          ) : (
            hint && <FieldDescription>{hint}</FieldDescription>
          )}
        </Field>
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting && <Spinner data-icon="inline-start" />}
          {isSubmitting ? submittingLabel : submitLabel}
        </Button>
        {(allowRecovery || children) && (
          <div className="flex flex-col items-center gap-1">
            {allowRecovery && (
              <Button
                type="button"
                variant="link"
                size="sm"
                onClick={switchMode}
              >
                {mode === "totp" ? t("totp.useRecovery") : t("totp.useApp")}
              </Button>
            )}
            {children}
          </div>
        )}
      </FieldGroup>
    </form>
  )
}
