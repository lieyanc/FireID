import * as React from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { CircleAlertIcon, KeyRoundIcon, PencilIcon } from "lucide-react"
import { toast } from "sonner"
import { z } from "zod"

import { PasswordInput } from "@/components/common/password-input"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
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
import { api } from "@/lib/api"
import { errorMessage, hasCode } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { User } from "@/lib/types"

// Matches store.DisplayMaxLen.
const DISPLAY_NAME_MAX = 64
// The server's auth.passwordMinLength defaults to 10; it has the final say
// and answers weak_password when its setting is stricter.
const PASSWORD_MIN = 10

function FormAlert({ message }: { message: string | null }) {
  if (!message) return null
  return (
    <Alert variant="destructive">
      <CircleAlertIcon />
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

/** Edit-profile and change-password buttons, with their dialogs. */
export function ProfileActions({ user }: { user: User }) {
  const { t } = useI18n()
  const [open, setOpen] = React.useState<"profile" | "password" | null>(null)
  const close = () => setOpen(null)
  const onOpenChange = (next: boolean) => {
    if (!next) close()
  }
  const closeLabel = t("common.actions.close")

  return (
    <>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => setOpen("profile")}>
          <PencilIcon data-icon="inline-start" />
          {t("account.profile.edit")}
        </Button>
        {/* Changing needs the current password; an account without one
            (email or passkey only) has nothing to change. */}
        {user.hasPassword && (
          <Button variant="outline" onClick={() => setOpen("password")}>
            <KeyRoundIcon data-icon="inline-start" />
            {t("account.password.change")}
          </Button>
        )}
      </div>

      <Dialog open={open === "profile"} onOpenChange={onOpenChange}>
        <DialogContent closeLabel={closeLabel}>
          {open === "profile" && <EditProfileFlow user={user} onDone={close} />}
        </DialogContent>
      </Dialog>
      <Dialog open={open === "password"} onOpenChange={onOpenChange}>
        <DialogContent closeLabel={closeLabel}>
          {open === "password" && (
            <ChangePasswordFlow user={user} onDone={close} />
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}

function EditProfileFlow({ user, onDone }: { user: User; onDone: () => void }) {
  const { t } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(
    () =>
      z.object({
        displayName: z
          .string()
          .trim()
          .max(
            DISPLAY_NAME_MAX,
            t("account.profile.displayNameTooLong", { max: DISPLAY_NAME_MAX })
          ),
      }),
    [t]
  )
  type Values = z.infer<typeof schema>

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { displayName: user.displayName },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async ({ displayName }: Values) => {
    setFormError(null)
    try {
      await api.account.updateProfile(displayName)
    } catch (error) {
      setFormError(errorMessage(error, t))
      return
    }
    await queryClient.invalidateQueries({ queryKey: qk.me })
    toast.success(t("account.profile.saved"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("account.profile.editTitle")}</DialogTitle>
        <DialogDescription>
          {t("account.profile.editDescription")}
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          <FormAlert message={formError} />
          <Field data-invalid={!!errors.displayName || undefined}>
            <FieldLabel htmlFor="profile-display-name">
              {t("auth.fields.displayName")}
            </FieldLabel>
            <Input
              id="profile-display-name"
              autoComplete="name"
              autoFocus
              maxLength={DISPLAY_NAME_MAX}
              placeholder={user.username}
              aria-invalid={!!errors.displayName}
              {...form.register("displayName")}
            />
            <FieldDescription>{t("auth.fields.displayNameHint")}</FieldDescription>
            <FieldError errors={[errors.displayName]} />
          </Field>
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting && <Spinner data-icon="inline-start" />}
            {isSubmitting
              ? t("common.actions.saving")
              : t("common.actions.save")}
          </Button>
        </FieldGroup>
      </form>
    </>
  )
}

function ChangePasswordFlow({
  user,
  onDone,
}: {
  user: User
  onDone: () => void
}) {
  const { t } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(
    () =>
      z
        .object({
          currentPassword: z
            .string()
            .min(1, t("auth.validation.passwordRequired")),
          newPassword: z
            .string()
            .min(1, t("auth.validation.passwordNew"))
            .min(
              PASSWORD_MIN,
              t("account.password.tooShort", { min: PASSWORD_MIN })
            ),
          confirmPassword: z.string(),
        })
        .refine((v) => v.newPassword === v.confirmPassword, {
          path: ["confirmPassword"],
          message: t("auth.validation.passwordMismatch"),
        })
        .refine((v) => v.newPassword !== v.currentPassword, {
          path: ["newPassword"],
          message: t("account.password.same"),
        }),
    [t]
  )
  type Values = z.infer<typeof schema>

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { currentPassword: "", newPassword: "", confirmPassword: "" },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async ({ currentPassword, newPassword }: Values) => {
    setFormError(null)
    try {
      await api.account.changePassword(currentPassword, newPassword)
    } catch (error) {
      if (hasCode(error, "invalid_credentials")) {
        form.setError(
          "currentPassword",
          { message: t("account.password.wrongCurrent") },
          { shouldFocus: true }
        )
      } else if (hasCode(error, "weak_password")) {
        form.setError(
          "newPassword",
          { message: errorMessage(error, t) },
          { shouldFocus: true }
        )
      } else {
        setFormError(errorMessage(error, t))
      }
      return
    }
    // Every other session was signed out with the change.
    void queryClient.invalidateQueries({ queryKey: qk.sessions })
    void queryClient.invalidateQueries({ queryKey: qk.me })
    toast.success(t("account.password.changed"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("account.password.title")}</DialogTitle>
        <DialogDescription>{t("account.password.description")}</DialogDescription>
      </DialogHeader>
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          <FormAlert message={formError} />
          {/* Lets password managers update the saved login. */}
          <input
            type="text"
            name="username"
            autoComplete="username"
            value={user.username}
            readOnly
            hidden
          />
          <Field data-invalid={!!errors.currentPassword || undefined}>
            <FieldLabel htmlFor="current-password">
              {t("account.password.current")}
            </FieldLabel>
            <PasswordInput
              id="current-password"
              autoComplete="current-password"
              autoFocus
              aria-invalid={!!errors.currentPassword}
              {...form.register("currentPassword")}
            />
            <FieldError errors={[errors.currentPassword]} />
          </Field>
          <Field data-invalid={!!errors.newPassword || undefined}>
            <FieldLabel htmlFor="new-password">
              {t("account.password.new")}
            </FieldLabel>
            <PasswordInput
              id="new-password"
              autoComplete="new-password"
              aria-invalid={!!errors.newPassword}
              {...form.register("newPassword")}
            />
            <FieldError errors={[errors.newPassword]} />
          </Field>
          <Field data-invalid={!!errors.confirmPassword || undefined}>
            <FieldLabel htmlFor="confirm-password">
              {t("account.password.confirm")}
            </FieldLabel>
            <PasswordInput
              id="confirm-password"
              autoComplete="new-password"
              aria-invalid={!!errors.confirmPassword}
              {...form.register("confirmPassword")}
            />
            <FieldError errors={[errors.confirmPassword]} />
          </Field>
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting && <Spinner data-icon="inline-start" />}
            {isSubmitting
              ? t("account.password.submitting")
              : t("account.password.submit")}
          </Button>
        </FieldGroup>
      </form>
    </>
  )
}
