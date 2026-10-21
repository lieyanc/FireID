import * as React from "react"
import { Controller, useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { HourglassIcon } from "lucide-react"
import { toast } from "sonner"
import { z } from "zod"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { FormAlert } from "@/features/admin/app-form"
import { redirectUriProblem } from "@/features/admin/uri-rules"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { App } from "@/lib/types"

type Values = {
  backchannelLogoutUri: string
  backchannelLogoutSessionRequired: boolean
}

/**
 * Where Fire ID posts a logout token when a session that signed in to the
 * app ends (OpenID Connect Back-Channel Logout). `pending` counts the
 * notifications still queued for delivery.
 */
export function BackchannelLogout({
  app,
  pending,
}: {
  app: App
  pending: number
}) {
  const { t } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  // Same rule as a redirect URI on a confidential client
  // (store.validateBackchannelURI); empty turns notifications off.
  const schema = React.useMemo(
    () =>
      z.object({
        backchannelLogoutUri: z
          .string()
          .trim()
          .superRefine((uri, ctx) => {
            const problem = uri ? redirectUriProblem(uri) : null
            if (problem) {
              ctx.addIssue({ code: "custom", message: t(problem, { uri }) })
            }
          }),
        backchannelLogoutSessionRequired: z.boolean(),
      }),
    [t]
  )

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: {
      backchannelLogoutUri: app.backchannelLogoutUri ?? "",
      backchannelLogoutSessionRequired: !!app.backchannelLogoutSessionRequired,
    },
  })
  const { errors, isSubmitting, isDirty } = form.formState

  const submit = async (values: Values) => {
    setFormError(null)
    try {
      await api.admin.updateApp(app.slug, values)
    } catch (error) {
      setFormError(errorMessage(error, t))
      return
    }
    // The saved values become the new baseline for "unchanged".
    form.reset(values)
    await queryClient.invalidateQueries({ queryKey: qk.app(app.slug) })
    toast.success(t("admin.backchannel.saved"))
  }

  const id = (name: string) => `app-backchannel-${name}`

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.backchannel.title")}</CardTitle>
        <CardDescription>{t("admin.backchannel.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={form.handleSubmit(submit)} noValidate>
          <FieldGroup>
            <FormAlert message={formError} />
            {pending > 0 && (
              <Alert>
                <HourglassIcon />
                <AlertDescription>
                  {pending === 1
                    ? t("admin.backchannel.pendingOne")
                    : t("admin.backchannel.pendingMany", { count: pending })}
                </AlertDescription>
              </Alert>
            )}
            <Field data-invalid={!!errors.backchannelLogoutUri || undefined}>
              <FieldLabel htmlFor={id("uri")}>
                {t("admin.backchannel.uri.label")}
              </FieldLabel>
              <Input
                id={id("uri")}
                type="url"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                placeholder="https://app.example.com/auth/backchannel-logout"
                aria-invalid={!!errors.backchannelLogoutUri}
                {...form.register("backchannelLogoutUri")}
              />
              <FieldDescription>
                {t("admin.backchannel.uri.hint")}
              </FieldDescription>
              <FieldError errors={[errors.backchannelLogoutUri]} />
            </Field>
            <Controller
              control={form.control}
              name="backchannelLogoutSessionRequired"
              render={({ field }) => (
                <Field orientation="horizontal">
                  <Checkbox
                    id={id("session")}
                    checked={field.value}
                    onCheckedChange={(v) => field.onChange(v === true)}
                    onBlur={field.onBlur}
                    ref={field.ref}
                  />
                  <FieldContent>
                    <FieldLabel htmlFor={id("session")} className="font-normal">
                      {t("admin.backchannel.session.label")}
                    </FieldLabel>
                    <FieldDescription>
                      {t("admin.backchannel.session.hint")}
                    </FieldDescription>
                  </FieldContent>
                </Field>
              )}
            />
            <Button type="submit" disabled={isSubmitting || !isDirty}>
              {isSubmitting && <Spinner data-icon="inline-start" />}
              {isSubmitting
                ? t("common.actions.saving")
                : t("common.actions.save")}
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}
