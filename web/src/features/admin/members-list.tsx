import * as React from "react"
import { PencilIcon, Trash2Icon, UserPlusIcon } from "lucide-react"
import { toast } from "sonner"

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
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Spinner } from "@/components/ui/spinner"
import { FormAlert } from "@/features/admin/app-form"
import {
  MEMBER_STATUS_LABELS,
  ROLE_LABELS,
  optionsOf,
} from "@/features/admin/labels"
import { NativeSelect } from "@/features/admin/native-select"
import { UserRow, UserSearch } from "@/features/admin/user-search"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage } from "@/lib/errors"
import { qk, queryClient, useMe } from "@/lib/queries"
import type {
  App,
  AppMember,
  MemberRole,
  MemberStatus,
  User,
} from "@/lib/types"
import { displayName } from "@/lib/user"

const STATUS_BADGE = {
  active: "success",
  pending: "warning",
  blocked: "destructive",
} as const

function refreshApp(slug: string) {
  return queryClient.invalidateQueries({ queryKey: qk.app(slug) })
}

type Editing =
  | { kind: "add" }
  | { kind: "edit"; member: AppMember }
  | { kind: "remove"; member: AppMember }

/** The app's members: add, change role or status, remove. */
export function MembersList({
  app,
  members,
}: {
  app: App
  members: AppMember[]
}) {
  const { t } = useI18n()
  const [editing, setEditing] = React.useState<Editing | null>(null)
  const close = () => setEditing(null)

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.members.title")}</CardTitle>
        <CardDescription>{t("admin.members.description")}</CardDescription>
        <CardAction>
          <Button variant="outline" onClick={() => setEditing({ kind: "add" })}>
            <UserPlusIcon data-icon="inline-start" />
            {t("admin.members.add")}
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col divide-y rounded-lg border">
          {members.map((member) => {
            // The owner's membership is fixed (store.RemoveMembership and
            // adminAppMemberSet both refuse it).
            const isOwner =
              member.role === "owner" || member.user.id === app.ownerUserId
            const name = displayName(member.user)
            return (
              <li
                key={member.user.id}
                className="flex flex-wrap items-center gap-3 p-3"
              >
                <div className="min-w-0 flex-1">
                  <UserRow user={member.user} />
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge variant="outline">{t(ROLE_LABELS[member.role])}</Badge>
                  <Badge variant={STATUS_BADGE[member.status]}>
                    {t(MEMBER_STATUS_LABELS[member.status])}
                  </Badge>
                </div>
                {isOwner ? (
                  <span className="text-xs text-muted-foreground">
                    {t("admin.members.ownerHint")}
                  </span>
                ) : (
                  <div className="flex gap-1">
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={t("admin.members.editLabel", { name })}
                      title={t("admin.members.edit")}
                      onClick={() => setEditing({ kind: "edit", member })}
                    >
                      <PencilIcon />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={t("admin.members.removeLabel", { name })}
                      title={t("admin.members.remove")}
                      onClick={() => setEditing({ kind: "remove", member })}
                    >
                      <Trash2Icon />
                    </Button>
                  </div>
                )}
              </li>
            )
          })}
          {members.length === 0 && (
            <li className="p-3 text-sm text-muted-foreground">
              {t("admin.members.empty")}
            </li>
          )}
        </ul>
      </CardContent>

      <Dialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) close()
        }}
      >
        <DialogContent closeLabel={t("common.actions.close")}>
          {editing?.kind === "add" && (
            <MemberFlow app={app} members={members} onDone={close} />
          )}
          {editing?.kind === "edit" && (
            <MemberFlow
              app={app}
              members={members}
              member={editing.member}
              onDone={close}
            />
          )}
          {editing?.kind === "remove" && (
            <RemoveFlow app={app} member={editing.member} onDone={close} />
          )}
        </DialogContent>
      </Dialog>
    </Card>
  )
}

/**
 * Adds someone (pick a user, then role and status) or, given `member`,
 * changes an existing membership. The endpoint upserts either way.
 */
function MemberFlow({
  app,
  members,
  member,
  onDone,
}: {
  app: App
  members: AppMember[]
  member?: AppMember
  onDone: () => void
}) {
  const { t } = useI18n()
  const { data: me } = useMe()
  const [user, setUser] = React.useState<User | null>(member?.user ?? null)
  const [role, setRole] = React.useState<MemberRole>(member?.role ?? "member")
  const [status, setStatus] = React.useState<MemberStatus>(
    member?.status ?? "active"
  )
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)
  const roleId = React.useId()
  const statusId = React.useId()

  // Only the super admin may hand out the owner role (adminAppMemberSet).
  const roles = optionsOf(ROLE_LABELS).filter(
    (r) => r !== "owner" || me?.permissions.superAdmin
  )
  const existing = user ? members.find((m) => m.user.id === user.id) : undefined
  const pickedOwner = !!user && user.id === app.ownerUserId

  const pick = (picked: User) => {
    setUser(picked)
    setFormError(null)
    const current = members.find((m) => m.user.id === picked.id)
    if (current) {
      setRole(current.role)
      setStatus(current.status)
    }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user || pickedOwner) return
    setBusy(true)
    setFormError(null)
    try {
      await api.admin.addAppMember(app.slug, { userId: user.id, role, status })
    } catch (error) {
      setBusy(false)
      setFormError(errorMessage(error, t))
      return
    }
    await refreshApp(app.slug)
    toast.success(
      member || existing ? t("admin.members.updated") : t("admin.members.added")
    )
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>
          {member ? t("admin.members.editTitle") : t("admin.members.addTitle")}
        </DialogTitle>
        <DialogDescription>
          {member
            ? t("admin.members.editDescription", {
                name: displayName(member.user),
              })
            : t("admin.members.addDescription")}
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={(e) => void submit(e)} noValidate>
        <FieldGroup>
          <FormAlert message={formError} />
          {!member && (
            <UserSearch
              autoFocus
              onPick={pick}
              selectedIds={user ? new Set([user.id]) : undefined}
            />
          )}
          {user && (
            <div className="rounded-lg border p-3">
              <UserRow user={user} />
              {pickedOwner ? (
                <p className="mt-2 text-xs text-muted-foreground">
                  {t("admin.members.ownerHint")}
                </p>
              ) : (
                existing &&
                !member && (
                  <p className="mt-2 text-xs text-muted-foreground">
                    {t("admin.members.alreadyMember")}
                  </p>
                )
              )}
            </div>
          )}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel htmlFor={roleId}>
                {t("admin.members.roleField")}
              </FieldLabel>
              <NativeSelect
                id={roleId}
                value={role}
                disabled={!user || pickedOwner}
                onChange={(e) => setRole(e.target.value as MemberRole)}
              >
                {roles.map((r) => (
                  <option key={r} value={r}>
                    {t(ROLE_LABELS[r])}
                  </option>
                ))}
              </NativeSelect>
            </Field>
            <Field>
              <FieldLabel htmlFor={statusId}>
                {t("admin.members.statusField")}
              </FieldLabel>
              <NativeSelect
                id={statusId}
                value={status}
                disabled={!user || pickedOwner}
                onChange={(e) => setStatus(e.target.value as MemberStatus)}
              >
                {optionsOf(MEMBER_STATUS_LABELS).map((s) => (
                  <option key={s} value={s}>
                    {t(MEMBER_STATUS_LABELS[s])}
                  </option>
                ))}
              </NativeSelect>
            </Field>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onDone}>
              {t("common.actions.cancel")}
            </Button>
            <Button type="submit" disabled={!user || pickedOwner || busy}>
              {busy && <Spinner data-icon="inline-start" />}
              {busy ? t("common.actions.saving") : t("common.actions.save")}
            </Button>
          </DialogFooter>
        </FieldGroup>
      </form>
    </>
  )
}

function RemoveFlow({
  app,
  member,
  onDone,
}: {
  app: App
  member: AppMember
  onDone: () => void
}) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setFormError(null)
    try {
      await api.admin.removeAppMember(app.slug, member.user.id)
    } catch (error) {
      setBusy(false)
      setFormError(errorMessage(error, t))
      return
    }
    await refreshApp(app.slug)
    toast.success(t("admin.members.removed"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("admin.members.removeTitle")}</DialogTitle>
        <DialogDescription>
          {t("admin.members.removeDescription", {
            name: displayName(member.user),
          })}
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
          {busy
            ? t("admin.members.removing")
            : t("admin.members.removeConfirm")}
        </Button>
      </DialogFooter>
    </>
  )
}
