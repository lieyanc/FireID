import * as React from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { CircleAlertIcon, TriangleAlertIcon } from "lucide-react"
import { toast } from "sonner"
import { z } from "zod"

import { PasswordInput } from "@/components/common/password-input"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Spinner } from "@/components/ui/spinner"
import { TotpEnrolment } from "@/features/totp/enrolment"
import { RecoveryCodes } from "@/features/totp/recovery-codes"
import { SecondFactorForm } from "@/features/totp/second-factor-form"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { TotpEnrolment as Enrolment, User } from "@/lib/types"

function refreshMe() {
  return queryClient.invalidateQueries({ queryKey: qk.me })
}

type DialogKind = "enable" | "disable" | "regenerate"

// At or below this many unused recovery codes, suggest creating new ones.
const LOW_RECOVERY_CODES = 3

export function TwoStepCard({
  user,
  recoveryCodesLeft,
}: {
  user: User
  recoveryCodesLeft: number
}) {
  const { t } = useI18n()
  const [open, setOpen] = React.useState<DialogKind | null>(null)
  // While fresh recovery codes are on screen the dialog cannot be dismissed:
  // they are never shown again.
  const [locked, setLocked] = React.useState(false)

  const onOpenChange = (next: boolean) => {
    if (next || locked) return
    setOpen(null)
  }
  const close = () => {
    setLocked(false)
    setOpen(null)
  }
  const closeLabel = t("common.actions.close")
  const show = (kind: DialogKind) => {
    setLocked(false)
    setOpen(kind)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("account.twoStep.title")}</CardTitle>
        <CardDescription>{t("account.twoStep.description")}</CardDescription>
        <CardAction>
          <Badge variant={user.totpEnabled ? "success" : "secondary"}>
            {user.totpEnabled
              ? t("account.twoStep.on")
              : t("account.twoStep.off")}
          </Badge>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm text-muted-foreground">
        <p>
          {user.totpEnabled
            ? t("account.twoStep.onHint")
            : t("account.twoStep.offHint")}
        </p>
        {user.totpEnabled && (
          <p>{t("account.twoStep.codesLeft", { count: recoveryCodesLeft })}</p>
        )}
        {user.totpEnabled && recoveryCodesLeft <= LOW_RECOVERY_CODES && (
          <Alert>
            <TriangleAlertIcon />
            <AlertDescription>{t("account.twoStep.codesLow")}</AlertDescription>
          </Alert>
        )}
      </CardContent>
      <CardFooter className="flex flex-wrap gap-2">
        {user.totpEnabled ? (
          <>
            <Button variant="outline" onClick={() => show("regenerate")}>
              {t("account.twoStep.regenerate")}
            </Button>
            <Button variant="destructive" onClick={() => show("disable")}>
              {t("account.twoStep.disable")}
            </Button>
          </>
        ) : (
          <Button onClick={() => show("enable")}>
            {t("account.twoStep.enable")}
          </Button>
        )}
      </CardFooter>

      {/* Mounted regardless of the current state: turning TOTP on flips
          user.totpEnabled while the recovery codes are still on screen. */}
      <Dialog open={open === "enable"} onOpenChange={onOpenChange}>
        <DialogContent showCloseButton={!locked} closeLabel={closeLabel}>
          <EnableFlow
            user={user}
            onLock={() => setLocked(true)}
            onDone={close}
          />
        </DialogContent>
      </Dialog>
      <Dialog open={open === "regenerate"} onOpenChange={onOpenChange}>
        <DialogContent showCloseButton={!locked} closeLabel={closeLabel}>
          <RegenerateFlow
            user={user}
            onLock={() => setLocked(true)}
            onDone={close}
          />
        </DialogContent>
      </Dialog>
      <Dialog open={open === "disable"} onOpenChange={onOpenChange}>
        <DialogContent closeLabel={closeLabel}>
          <DisableFlow onDone={close} />
        </DialogContent>
      </Dialog>
    </Card>
  )
}

type FlowProps = { user: User; onLock: () => void; onDone: () => void }

function EnableFlow({ user, onLock, onDone }: FlowProps) {
  const { t } = useI18n()
  const [enrolment, setEnrolment] = React.useState<Enrolment | null>(null)
  const [codes, setCodes] = React.useState<string[] | null>(null)

  if (codes) {
    return (
      <>
        <DialogHeader>
          <DialogTitle>{t("totp.recovery.title")}</DialogTitle>
          <DialogDescription>
            {t("totp.recovery.description")}
          </DialogDescription>
        </DialogHeader>
        <RecoveryCodes
          codes={codes}
          username={user.username}
          doneLabel={t("common.actions.close")}
          onDone={() => {
            toast.success(t("account.twoStep.enabled"))
            onDone()
          }}
        />
      </>
    )
  }

  if (enrolment) {
    return (
      <>
        <DialogHeader>
          <DialogTitle>{t("account.twoStep.enableTitle")}</DialogTitle>
          <DialogDescription>{t("totp.enrol.scan")}</DialogDescription>
        </DialogHeader>
        <TotpEnrolment
          enrolment={enrolment}
          showScanHint={false}
          submitLabel={t("account.twoStep.enableSubmit")}
          submittingLabel={t("account.twoStep.enableSubmitting")}
          onSubmit={async (code) => {
            const res = await api.account.confirmTotp(code)
            onLock()
            setCodes(res.recoveryCodes)
            void refreshMe()
          }}
        />
      </>
    )
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("account.twoStep.enableTitle")}</DialogTitle>
        <DialogDescription>
          {user.hasPassword
            ? t("account.twoStep.passwordPrompt")
            : t("account.twoStep.noPasswordPrompt")}
        </DialogDescription>
      </DialogHeader>
      <PasswordGate
        user={user}
        onEnrolled={setEnrolment}
        onAlreadyOn={() => {
          void refreshMe()
          onDone()
        }}
      />
    </>
  )
}

/** First screen of enabling TOTP: re-enter the password when there is one. */
function PasswordGate({
  user,
  onEnrolled,
  onAlreadyOn,
}: {
  user: User
  onEnrolled: (enrolment: Enrolment) => void
  onAlreadyOn: () => void
}) {
  const { t } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(
    () =>
      z.object({
        password: user.hasPassword
          ? z.string().min(1, t("auth.validation.passwordRequired"))
          : z.string(),
      }),
    [t, user.hasPassword]
  )
  type Values = z.infer<typeof schema>

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { password: "" },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async ({ password }: Values) => {
    setFormError(null)
    try {
      onEnrolled(
        await api.account.enrolTotp(user.hasPassword ? password : undefined)
      )
    } catch (error) {
      if (hasCode(error, "invalid_credentials")) {
        form.setError(
          "password",
          { message: t("account.twoStep.wrongPassword") },
          { shouldFocus: true }
        )
      } else if (hasCode(error, "totp_enabled")) {
        toast.info(t("common.errors.totp_enabled"))
        onAlreadyOn()
      } else {
        setFormError(errorMessage(error, t))
      }
    }
  }

  return (
    <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
      <FieldGroup>
        {formError && (
          <Alert variant="destructive">
            <CircleAlertIcon />
            <AlertDescription>{formError}</AlertDescription>
          </Alert>
        )}
        {user.hasPassword && (
          <Field data-invalid={!!errors.password || undefined}>
            {/* Lets password managers match the saved login. */}
            <input
              type="text"
              name="username"
              autoComplete="username"
              value={user.username}
              readOnly
              hidden
            />
            <FieldLabel htmlFor="totp-password">
              {t("auth.fields.password")}
            </FieldLabel>
            <PasswordInput
              id="totp-password"
              autoComplete="current-password"
              autoFocus
              aria-invalid={!!errors.password}
              {...form.register("password")}
            />
            <FieldError errors={[errors.password]} />
          </Field>
        )}
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting && <Spinner data-icon="inline-start" />}
          {t("common.actions.continue")}
        </Button>
      </FieldGroup>
    </form>
  )
}

function RegenerateFlow({ user, onLock, onDone }: FlowProps) {
  const { t } = useI18n()
  const [codes, setCodes] = React.useState<string[] | null>(null)

  if (codes) {
    return (
      <>
        <DialogHeader>
          <DialogTitle>{t("totp.recovery.title")}</DialogTitle>
          <DialogDescription>
            {t("totp.recovery.description")}
          </DialogDescription>
        </DialogHeader>
        <RecoveryCodes
          codes={codes}
          username={user.username}
          doneLabel={t("common.actions.close")}
          onDone={onDone}
        />
      </>
    )
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("account.twoStep.regenerateTitle")}</DialogTitle>
        <DialogDescription>
          {t("account.twoStep.regenerateDescription")}
        </DialogDescription>
      </DialogHeader>
      <SecondFactorForm
        allowRecovery
        submitLabel={t("account.twoStep.regenerateSubmit")}
        submittingLabel={t("account.twoStep.regenerateSubmitting")}
        onSubmit={async (code) => {
          const res = await api.account.regenerateRecoveryCodes(code)
          onLock()
          setCodes(res.recoveryCodes)
          void refreshMe()
          toast.success(t("account.twoStep.regenerated"))
        }}
      />
    </>
  )
}

function DisableFlow({ onDone }: { onDone: () => void }) {
  const { t } = useI18n()
  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("account.twoStep.disableTitle")}</DialogTitle>
        <DialogDescription>
          {t("account.twoStep.disableDescription")}
        </DialogDescription>
      </DialogHeader>
      <SecondFactorForm
        allowRecovery
        submitLabel={t("account.twoStep.disableSubmit")}
        submittingLabel={t("account.twoStep.disableSubmitting")}
        describeError={(error) =>
          hasCode(error, "forbidden") ? t("account.twoStep.policy") : undefined
        }
        onSubmit={async (code) => {
          await api.account.disableTotp(code)
          toast.success(t("account.twoStep.disabled"))
          await refreshMe()
          onDone()
        }}
      />
    </>
  )
}
