import * as React from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { useQuery } from "@tanstack/react-query"
import {
  CircleAlertIcon,
  CloudIcon,
  KeyRoundIcon,
  PencilIcon,
  SmartphoneIcon,
  Trash2Icon,
} from "lucide-react"
import { toast } from "sonner"
import { z } from "zod"

import { PasswordInput } from "@/components/common/password-input"
import { QueryError } from "@/components/common/query-state"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
} from "@/components/ui/empty"
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
import type { Passkey, User } from "@/lib/types"
import {
  createPasskey,
  markPasskeysUnavailable,
  passkeysAvailable,
  usePasskeysOffered,
} from "@/lib/webauthn"

// Matches store.PasskeyNameMaxLen.
const NAME_MAX = 64

function refreshPasskeys() {
  return queryClient.invalidateQueries({ queryKey: qk.passkeys })
}

type DialogState =
  | { kind: "add" }
  | { kind: "rename"; passkey: Passkey }
  | { kind: "delete"; passkey: Passkey }

export function PasskeysCard({ user }: { user: User }) {
  const { t } = useI18n()
  const supported = passkeysAvailable()
  const offered = usePasskeysOffered()
  const query = useQuery({
    queryKey: qk.passkeys,
    queryFn: async () => (await api.account.passkeys.list()).passkeys ?? [],
  })
  const [dialog, setDialog] = React.useState<DialogState | null>(null)
  const close = () => setDialog(null)
  const onOpenChange = (open: boolean) => {
    if (!open) close()
  }
  const closeLabel = t("common.actions.close")

  // The server has no passkeys (404 passkeys_unavailable from begin): hide
  // the card, unless old passkeys are still listed and may need removing.
  if (!offered && !query.data?.length) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("passkeys.title")}</CardTitle>
        <CardDescription>{t("passkeys.description")}</CardDescription>
        {offered && (
          <CardAction>
            <Button
              size="sm"
              disabled={!supported}
              onClick={() => setDialog({ kind: "add" })}
            >
              <KeyRoundIcon data-icon="inline-start" />
              {t("passkeys.add")}
            </Button>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {!offered && (
          <Alert>
            <CircleAlertIcon />
            <AlertDescription>
              {t("common.errors.passkeys_unavailable")}
            </AlertDescription>
          </Alert>
        )}
        {offered && !supported && (
          <Alert>
            <CircleAlertIcon />
            <AlertDescription>{t("passkeys.unsupported")}</AlertDescription>
          </Alert>
        )}
        {query.isPending ? (
          <div className="flex justify-center py-4">
            <Spinner className="size-5 text-muted-foreground" />
          </div>
        ) : query.isError ? (
          <QueryError
            error={query.error}
            onRetry={() => void query.refetch()}
          />
        ) : query.data.length === 0 ? (
          <Empty className="border p-4">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <KeyRoundIcon />
              </EmptyMedia>
              <EmptyDescription>{t("passkeys.empty")}</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <ul className="flex flex-col divide-y rounded-lg border">
            {query.data.map((passkey) => (
              <PasskeyRow
                key={passkey.id}
                passkey={passkey}
                onRename={() => setDialog({ kind: "rename", passkey })}
                onDelete={() => setDialog({ kind: "delete", passkey })}
              />
            ))}
          </ul>
        )}
      </CardContent>

      <Dialog open={dialog?.kind === "add"} onOpenChange={onOpenChange}>
        <DialogContent closeLabel={closeLabel}>
          {dialog?.kind === "add" && (
            <AddPasskeyFlow user={user} onDone={close} />
          )}
        </DialogContent>
      </Dialog>
      <Dialog open={dialog?.kind === "rename"} onOpenChange={onOpenChange}>
        <DialogContent closeLabel={closeLabel}>
          {dialog?.kind === "rename" && (
            <RenameFlow passkey={dialog.passkey} onDone={close} />
          )}
        </DialogContent>
      </Dialog>
      <Dialog open={dialog?.kind === "delete"} onOpenChange={onOpenChange}>
        <DialogContent closeLabel={closeLabel}>
          {dialog?.kind === "delete" && (
            <DeleteFlow passkey={dialog.passkey} onDone={close} />
          )}
        </DialogContent>
      </Dialog>
    </Card>
  )
}

function usePasskeyName() {
  const { t } = useI18n()
  return (passkey: Passkey) => passkey.name || t("passkeys.unnamed")
}

function PasskeyRow({
  passkey,
  onRename,
  onDelete,
}: {
  passkey: Passkey
  onRename: () => void
  onDelete: () => void
}) {
  const { t, fmt } = useI18n()
  const name = usePasskeyName()(passkey)
  return (
    <li className="flex items-start gap-3 p-3">
      <KeyRoundIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      <div className="grid min-w-0 flex-1 gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate text-sm font-medium">{name}</span>
          <BackupBadge passkey={passkey} />
        </div>
        <p className="text-xs text-muted-foreground">
          <span title={fmt.dateTime(passkey.createdAt)}>
            {t("passkeys.created", { date: fmt.date(passkey.createdAt) })}
          </span>
          {" · "}
          {passkey.lastUsedAt ? (
            <span title={fmt.dateTime(passkey.lastUsedAt)}>
              {t("passkeys.lastUsed", {
                date: fmt.relative(passkey.lastUsedAt),
              })}
            </span>
          ) : (
            t("passkeys.neverUsed")
          )}
        </p>
      </div>
      <div
        className="flex shrink-0 gap-1"
        role="group"
        aria-label={t("passkeys.actions", { name })}
      >
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label={t("common.actions.rename")}
          title={t("common.actions.rename")}
          onClick={onRename}
        >
          <PencilIcon />
        </Button>
        <Button
          variant="ghost"
          size="icon-sm"
          className="text-destructive hover:text-destructive"
          aria-label={t("common.actions.delete")}
          title={t("common.actions.delete")}
          onClick={onDelete}
        >
          <Trash2Icon />
        </Button>
      </div>
    </li>
  )
}

/** Whether the passkey syncs: backed up now, could be, or device-bound. */
function BackupBadge({ passkey }: { passkey: Passkey }) {
  const { t } = useI18n()
  if (passkey.backupState) {
    return (
      <Badge variant="success" title={t("passkeys.syncedHint")}>
        <CloudIcon data-icon="inline-start" />
        {t("passkeys.synced")}
      </Badge>
    )
  }
  if (passkey.backupEligible) {
    return (
      <Badge variant="outline" title={t("passkeys.syncableHint")}>
        <CloudIcon data-icon="inline-start" />
        {t("passkeys.syncable")}
      </Badge>
    )
  }
  return (
    <Badge variant="secondary" title={t("passkeys.deviceBoundHint")}>
      <SmartphoneIcon data-icon="inline-start" />
      {t("passkeys.deviceBound")}
    </Badge>
  )
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

/** A default name from the platform, so the list is legible without typing. */
function suggestedName() {
  const ua = navigator.userAgent
  if (/iPhone/.test(ua)) return "iPhone"
  if (/iPad/.test(ua)) return "iPad"
  if (/Android/.test(ua)) return "Android"
  if (/Mac OS X|Macintosh/.test(ua)) return "Mac"
  if (/Windows/.test(ua)) return "Windows"
  if (/Linux/.test(ua)) return "Linux"
  return ""
}

/**
 * Adding a passkey: the password (when the account has one) and a name, then
 * the browser's prompt. Each ceremony is single-use, so a retry starts over.
 */
function AddPasskeyFlow({ user, onDone }: { user: User; onDone: () => void }) {
  const { t } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(
    () =>
      z.object({
        password: user.hasPassword
          ? z.string().min(1, t("auth.validation.passwordRequired"))
          : z.string(),
        name: z
          .string()
          .trim()
          .max(
            NAME_MAX,
            t("passkeys.addDialog.nameTooLong", { max: NAME_MAX })
          ),
      }),
    [t, user.hasPassword]
  )
  type Values = z.infer<typeof schema>

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { password: "", name: suggestedName() },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async ({ password, name }: Values) => {
    setFormError(null)
    let ceremony
    try {
      ceremony = await api.account.passkeys.begin(
        user.hasPassword ? password : undefined
      )
    } catch (error) {
      if (hasCode(error, "invalid_credentials")) {
        form.setError(
          "password",
          { message: t("passkeys.addDialog.wrongPassword") },
          { shouldFocus: true }
        )
      } else if (hasCode(error, "passkeys_unavailable")) {
        toast.info(t("common.errors.passkeys_unavailable"))
        markPasskeysUnavailable()
        onDone()
      } else {
        setFormError(errorMessage(error, t))
      }
      return
    }
    try {
      const response = await createPasskey(ceremony.publicKey)
      await api.account.passkeys.finish({
        ceremonyId: ceremony.ceremonyId,
        name,
        response,
      })
    } catch (error) {
      // The store reports an already-registered credential as a conflict;
      // the generic wording for that code is about usernames.
      if (hasCode(error, "invalid")) {
        form.setError(
          "name",
          { message: t("passkeys.addDialog.nameTooLong", { max: NAME_MAX }) },
          { shouldFocus: true }
        )
        return
      }
      setFormError(
        hasCode(error, "conflict")
          ? t("common.errors.webauthn_already_registered")
          : errorMessage(error, t)
      )
      return
    }
    await refreshPasskeys()
    toast.success(t("passkeys.addDialog.added"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("passkeys.addDialog.title")}</DialogTitle>
        <DialogDescription>
          {user.hasPassword
            ? t("passkeys.addDialog.passwordPrompt")
            : t("passkeys.addDialog.noPasswordPrompt")}
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          <FormAlert message={formError} />
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
              <FieldLabel htmlFor="passkey-password">
                {t("auth.fields.password")}
              </FieldLabel>
              <PasswordInput
                id="passkey-password"
                autoComplete="current-password"
                autoFocus
                aria-invalid={!!errors.password}
                {...form.register("password")}
              />
              <FieldError errors={[errors.password]} />
            </Field>
          )}
          <Field data-invalid={!!errors.name || undefined}>
            <FieldLabel htmlFor="passkey-name">
              {t("passkeys.addDialog.name")}
            </FieldLabel>
            <Input
              id="passkey-name"
              autoComplete="off"
              autoFocus={!user.hasPassword}
              maxLength={NAME_MAX}
              placeholder={t("passkeys.addDialog.namePlaceholder")}
              aria-invalid={!!errors.name}
              {...form.register("name")}
            />
            <FieldDescription>
              {t("passkeys.addDialog.nameHint")}
            </FieldDescription>
            <FieldError errors={[errors.name]} />
          </Field>
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting && <Spinner data-icon="inline-start" />}
            {isSubmitting
              ? t("passkeys.addDialog.waiting")
              : t("passkeys.addDialog.submit")}
          </Button>
        </FieldGroup>
      </form>
    </>
  )
}

function RenameFlow({
  passkey,
  onDone,
}: {
  passkey: Passkey
  onDone: () => void
}) {
  const { t } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(
    () =>
      z.object({
        name: z
          .string()
          .trim()
          .max(
            NAME_MAX,
            t("passkeys.addDialog.nameTooLong", { max: NAME_MAX })
          ),
      }),
    [t]
  )
  type Values = z.infer<typeof schema>

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: { name: passkey.name },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async ({ name }: Values) => {
    setFormError(null)
    try {
      await api.account.passkeys.rename(passkey.id, name)
    } catch (error) {
      if (hasCode(error, "invalid")) {
        form.setError(
          "name",
          { message: t("passkeys.addDialog.nameTooLong", { max: NAME_MAX }) },
          { shouldFocus: true }
        )
        return
      }
      if (hasCode(error, "not_found")) void refreshPasskeys()
      setFormError(errorMessage(error, t))
      return
    }
    await refreshPasskeys()
    toast.success(t("passkeys.renameDialog.renamed"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("passkeys.renameDialog.title")}</DialogTitle>
        <DialogDescription>
          {t("passkeys.renameDialog.description")}
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          <FormAlert message={formError} />
          <Field data-invalid={!!errors.name || undefined}>
            <FieldLabel htmlFor="passkey-rename">
              {t("passkeys.addDialog.name")}
            </FieldLabel>
            <Input
              id="passkey-rename"
              autoComplete="off"
              autoFocus
              maxLength={NAME_MAX}
              placeholder={t("passkeys.addDialog.namePlaceholder")}
              aria-invalid={!!errors.name}
              {...form.register("name")}
            />
            <FieldError errors={[errors.name]} />
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

function DeleteFlow({
  passkey,
  onDone,
}: {
  passkey: Passkey
  onDone: () => void
}) {
  const { t } = useI18n()
  const name = usePasskeyName()(passkey)
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const remove = async () => {
    setBusy(true)
    setFormError(null)
    try {
      await api.account.passkeys.delete(passkey.id)
    } catch (error) {
      setBusy(false)
      if (hasCode(error, "not_found")) {
        // Already gone (another tab): the outcome the person wanted.
        await refreshPasskeys()
        onDone()
        return
      }
      setFormError(errorMessage(error, t))
      return
    }
    await refreshPasskeys()
    toast.success(t("passkeys.deleteDialog.deleted"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("passkeys.deleteDialog.title")}</DialogTitle>
        <DialogDescription>
          {t("passkeys.deleteDialog.description", { name })}
        </DialogDescription>
      </DialogHeader>
      <FormAlert message={formError} />
      <DialogFooter>
        <Button variant="outline" disabled={busy} onClick={onDone}>
          {t("common.actions.cancel")}
        </Button>
        <Button
          variant="destructive"
          disabled={busy}
          onClick={() => void remove()}
        >
          {busy && <Spinner data-icon="inline-start" />}
          {busy
            ? t("passkeys.deleteDialog.submitting")
            : t("passkeys.deleteDialog.submit")}
        </Button>
      </DialogFooter>
    </>
  )
}
