import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { PlusIcon, TriangleAlertIcon, XIcon } from "lucide-react"
import { toast } from "sonner"

import { CopyButton } from "@/components/common/copy-button"
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
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { FormAlert } from "@/features/admin/app-form"
import { ROLE_LABELS } from "@/features/admin/labels"
import { NativeSelect } from "@/features/admin/native-select"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode } from "@/lib/errors"
import { qk, queryClient, useMe } from "@/lib/queries"
import type { App, Invite } from "@/lib/types"
import { displayName } from "@/lib/user"

// Mirrors the limits of POST /api/admin/apps/:slug/invites.
const DAYS = { min: 1, max: 30, default: 7 }
const USES = { min: 1, max: 100, default: 1 }
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+$/

/** "revoked", "expired", "usedUp" or null for an invite that still works. */
function inviteState(invite: Invite, now: number) {
  if (invite.revokedAt) return "revoked" as const
  if (invite.uses >= invite.maxUses) return "usedUp" as const
  if (new Date(invite.expiresAt).getTime() <= now) return "expired" as const
  return null
}

function refreshInvites(slug: string) {
  return queryClient.invalidateQueries({ queryKey: qk.invites(slug) })
}

/** Invite links of an app: create one (shown once), list and revoke them. */
export function Invites({ app }: { app: App }) {
  const { t, fmt } = useI18n()
  const { data: me } = useMe()
  const [creating, setCreating] = React.useState(false)
  const [url, setUrl] = React.useState<string | null>(null)
  const [revoking, setRevoking] = React.useState<Invite | null>(null)
  const query = useQuery({
    queryKey: qk.invites(app.slug),
    queryFn: async () => (await api.admin.invites(app.slug)).invites,
  })
  // The owner and super admins may invite admins (the API checks too).
  const mayInviteAdmins =
    !!me && (me.user.superAdmin || me.user.id === app.ownerUserId)
  const [now] = React.useState(() => Date.now())

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.invites.title")}</CardTitle>
        <CardDescription>{t("admin.invites.description")}</CardDescription>
        <CardAction>
          <Button
            variant="outline"
            size="sm"
            disabled={app.status !== "active"}
            onClick={() => setCreating(true)}
          >
            <PlusIcon data-icon="inline-start" />
            {t("admin.invites.create")}
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {query.isPending ? (
          <div className="flex justify-center py-4">
            <Spinner className="text-muted-foreground" />
          </div>
        ) : query.isError ? (
          <QueryError
            error={query.error}
            onRetry={() => void query.refetch()}
          />
        ) : (
          <ul className="flex flex-col divide-y rounded-lg border">
            {query.data.map((invite) => {
              const state = inviteState(invite, now)
              const target = invite.email || t("admin.invites.anyone")
              return (
                <li
                  key={invite.id}
                  className="flex flex-wrap items-start gap-3 p-3"
                >
                  <div className="grid min-w-0 flex-1 gap-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium break-all">
                        {target}
                      </span>
                      <Badge variant="outline">
                        {t(ROLE_LABELS[invite.role])}
                      </Badge>
                      {state && (
                        <Badge
                          variant={
                            state === "revoked" ? "destructive" : "secondary"
                          }
                        >
                          {t(`admin.invites.${state}`)}
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {t("admin.invites.uses", {
                        uses: invite.uses,
                        max: invite.maxUses,
                      })}
                      {" · "}
                      <span title={fmt.dateTime(invite.expiresAt)}>
                        {t("admin.invites.expiresAt", {
                          date: fmt.relative(invite.expiresAt),
                        })}
                      </span>
                    </p>
                    <p
                      className="text-xs text-muted-foreground"
                      title={fmt.dateTime(invite.createdAt)}
                    >
                      {t("admin.invites.byWhom", {
                        name: displayName(invite.createdBy),
                        date: fmt.relative(invite.createdAt),
                      })}
                    </p>
                  </div>
                  {!state && (
                    <Button
                      variant="outline"
                      size="sm"
                      aria-label={t("admin.invites.revokeLabel", { target })}
                      onClick={() => setRevoking(invite)}
                    >
                      <XIcon data-icon="inline-start" />
                      {t("admin.invites.revoke")}
                    </Button>
                  )}
                </li>
              )
            })}
            {query.data.length === 0 && (
              <li className="p-3 text-sm text-muted-foreground">
                {t("admin.invites.empty")}
              </li>
            )}
          </ul>
        )}
      </CardContent>

      <Dialog open={creating} onOpenChange={setCreating}>
        <DialogContent closeLabel={t("common.actions.close")}>
          {creating && (
            <CreateFlow
              app={app}
              mayInviteAdmins={mayInviteAdmins}
              onCancel={() => setCreating(false)}
              onCreated={(created) => {
                setCreating(false)
                setUrl(created)
              }}
            />
          )}
        </DialogContent>
      </Dialog>
      <Dialog
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) setRevoking(null)
        }}
      >
        <DialogContent closeLabel={t("common.actions.close")}>
          {revoking && (
            <RevokeFlow
              app={app}
              invite={revoking}
              onDone={() => setRevoking(null)}
            />
          )}
        </DialogContent>
      </Dialog>
      <InviteUrlDialog url={url} onClose={() => setUrl(null)} />
    </Card>
  )
}

/** A whole number in [min, max], or null. */
function parseCount(value: string, min: number, max: number) {
  if (!/^\d+$/.test(value.trim())) return null
  const n = Number(value)
  return n >= min && n <= max ? n : null
}

function CreateFlow({
  app,
  mayInviteAdmins,
  onCancel,
  onCreated,
}: {
  app: App
  mayInviteAdmins: boolean
  onCancel: () => void
  onCreated: (url: string) => void
}) {
  const { t } = useI18n()
  const id = React.useId()
  const [email, setEmail] = React.useState("")
  const [role, setRole] = React.useState<Invite["role"]>("member")
  const [days, setDays] = React.useState(String(DAYS.default))
  const [uses, setUses] = React.useState(String(USES.default))
  const [submitted, setSubmitted] = React.useState(false)
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const trimmedEmail = email.trim()
  const emailBad = trimmedEmail !== "" && !EMAIL_PATTERN.test(trimmedEmail)
  const daysValue = parseCount(days, DAYS.min, DAYS.max)
  const usesValue = parseCount(uses, USES.min, USES.max)
  const invalid = emailBad || daysValue === null || usesValue === null

  const run = async (event: React.FormEvent) => {
    event.preventDefault()
    setSubmitted(true)
    if (invalid) return
    setBusy(true)
    setFormError(null)
    let created: { url: string }
    try {
      created = await api.admin.createInvite(app.slug, {
        email: trimmedEmail || undefined,
        role,
        expiresInDays: daysValue,
        maxUses: usesValue,
      })
    } catch (error) {
      setBusy(false)
      setFormError(errorMessage(error, t))
      return
    }
    void refreshInvites(app.slug)
    toast.success(t("admin.invites.created"))
    onCreated(created.url)
  }

  return (
    <form onSubmit={(event) => void run(event)} noValidate>
      <DialogHeader>
        <DialogTitle>{t("admin.invites.createTitle")}</DialogTitle>
        <DialogDescription>
          {t("admin.invites.createDescription")}
        </DialogDescription>
      </DialogHeader>
      <FieldGroup className="py-4">
        <FormAlert message={formError} />
        <Field data-invalid={(submitted && emailBad) || undefined}>
          <FieldLabel htmlFor={`${id}-email`}>
            {t("admin.invites.email")}
          </FieldLabel>
          <Input
            id={`${id}-email`}
            type="email"
            autoComplete="off"
            value={email}
            aria-invalid={submitted && emailBad}
            onChange={(event) => setEmail(event.target.value)}
          />
          <FieldDescription>{t("admin.invites.emailHint")}</FieldDescription>
          {submitted && emailBad && (
            <FieldError>{t("admin.invites.emailInvalid")}</FieldError>
          )}
        </Field>
        <Field>
          <FieldLabel htmlFor={`${id}-role`}>
            {t("admin.invites.role")}
          </FieldLabel>
          <NativeSelect
            id={`${id}-role`}
            value={role}
            onChange={(event) =>
              setRole(event.target.value === "admin" ? "admin" : "member")
            }
          >
            <option value="member">{t(ROLE_LABELS.member)}</option>
            <option value="admin" disabled={!mayInviteAdmins}>
              {t(ROLE_LABELS.admin)}
            </option>
          </NativeSelect>
          {!mayInviteAdmins && (
            <FieldDescription>
              {t("admin.invites.roleAdminHint")}
            </FieldDescription>
          )}
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field data-invalid={(submitted && daysValue === null) || undefined}>
            <FieldLabel htmlFor={`${id}-days`}>
              {t("admin.invites.expires")}
            </FieldLabel>
            <Input
              id={`${id}-days`}
              type="number"
              inputMode="numeric"
              min={DAYS.min}
              max={DAYS.max}
              value={days}
              aria-invalid={submitted && daysValue === null}
              onChange={(event) => setDays(event.target.value)}
            />
            {submitted && daysValue === null && (
              <FieldError>{t("admin.invites.rangeError", DAYS)}</FieldError>
            )}
          </Field>
          <Field data-invalid={(submitted && usesValue === null) || undefined}>
            <FieldLabel htmlFor={`${id}-uses`}>
              {t("admin.invites.maxUses")}
            </FieldLabel>
            <Input
              id={`${id}-uses`}
              type="number"
              inputMode="numeric"
              min={USES.min}
              max={USES.max}
              value={uses}
              aria-invalid={submitted && usesValue === null}
              onChange={(event) => setUses(event.target.value)}
            />
            {submitted && usesValue === null && (
              <FieldError>{t("admin.invites.rangeError", USES)}</FieldError>
            )}
          </Field>
        </div>
      </FieldGroup>
      <DialogFooter>
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          disabled={busy}
        >
          {t("common.actions.cancel")}
        </Button>
        <Button type="submit" disabled={busy}>
          {busy && <Spinner data-icon="inline-start" />}
          {busy ? t("admin.invites.creating") : t("admin.invites.create")}
        </Button>
      </DialogFooter>
    </form>
  )
}

/**
 * Shows a new invite link once. Like SecretDialog, the link lives only in the
 * caller's state and is dropped when the dialog closes.
 */
function InviteUrlDialog({
  url,
  onClose,
}: {
  url: string | null
  onClose: () => void
}) {
  const { t } = useI18n()
  const labelId = React.useId()
  return (
    <Dialog
      open={url !== null}
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <DialogContent
        closeLabel={t("common.actions.close")}
        onPointerDownOutside={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{t("admin.invites.urlTitle")}</DialogTitle>
          <DialogDescription>
            {t("admin.invites.urlDescription")}
          </DialogDescription>
        </DialogHeader>
        <FieldGroup>
          <Alert>
            <TriangleAlertIcon className="text-warning" />
            <AlertDescription>{t("admin.invites.urlWarning")}</AlertDescription>
          </Alert>
          <Field>
            <FieldLabel id={labelId}>{t("admin.invites.urlTitle")}</FieldLabel>
            <div className="flex items-center gap-2">
              <code
                aria-labelledby={labelId}
                className="min-w-0 flex-1 rounded-lg border bg-muted/50 px-2.5 py-1.5 font-mono text-xs break-all select-all"
              >
                {url}
              </code>
              {url && (
                <CopyButton value={url} label={t("admin.invites.copyUrl")} />
              )}
            </div>
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" onClick={onClose}>
            {t("admin.invites.done")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function RevokeFlow({
  app,
  invite,
  onDone,
}: {
  app: App
  invite: Invite
  onDone: () => void
}) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setFormError(null)
    try {
      await api.admin.revokeInvite(app.slug, invite.id)
    } catch (error) {
      // Already gone: the refresh shows it.
      if (!hasCode(error, "not_found")) {
        setBusy(false)
        setFormError(errorMessage(error, t))
        return
      }
    }
    await refreshInvites(app.slug)
    toast.success(t("admin.invites.revokedToast"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("admin.invites.revokeTitle")}</DialogTitle>
        <DialogDescription>
          {t("admin.invites.revokeDescription")}
        </DialogDescription>
      </DialogHeader>
      <FormAlert message={formError} />
      <DialogFooter>
        <Button variant="outline" onClick={onDone} disabled={busy}>
          {t("common.actions.cancel")}
        </Button>
        <Button
          variant="destructive"
          onClick={() => void run()}
          disabled={busy}
        >
          {busy && <Spinner data-icon="inline-start" />}
          {busy ? t("admin.invites.revoking") : t("admin.invites.revoke")}
        </Button>
      </DialogFooter>
    </>
  )
}
