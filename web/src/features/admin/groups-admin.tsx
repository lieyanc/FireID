import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import {
  PencilIcon,
  PlusIcon,
  Trash2Icon,
  UsersIcon,
  XIcon,
} from "lucide-react"
import { toast } from "sonner"
import { z } from "zod"

import { QueryError } from "@/components/common/query-state"
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
  EmptyTitle,
} from "@/components/ui/empty"
import {
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"
import { FormAlert } from "@/features/admin/app-form"
import { UserRow, UserSearch } from "@/features/admin/user-search"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { Group, User } from "@/lib/types"
import { displayName } from "@/lib/user"

// Mirrors store.validateGroup.
const NAME_MAX = 100
const DESCRIPTION_MAX = 500

const NO_USERS: User[] = []

function refreshGroups() {
  // Prefix match: the list and every group's members.
  return queryClient.invalidateQueries({ queryKey: qk.groups })
}

type Editing =
  | { kind: "create" }
  | { kind: "edit"; group: Group }
  | { kind: "delete"; group: Group }
  | { kind: "members"; group: Group }

/** Groups of users (super admin): list, create, edit, delete, membership. */
export function GroupsAdmin() {
  const { t } = useI18n()
  const query = useQuery({
    queryKey: qk.groups,
    queryFn: async () => (await api.admin.groups()).groups ?? [],
  })
  const [editing, setEditing] = React.useState<Editing | null>(null)
  const close = () => setEditing(null)

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.groups.listTitle")}</CardTitle>
        <CardDescription>{t("admin.groups.description")}</CardDescription>
        <CardAction>
          <Button onClick={() => setEditing({ kind: "create" })}>
            <PlusIcon data-icon="inline-start" />
            {t("admin.groups.create")}
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
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
          <Empty className="border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <UsersIcon />
              </EmptyMedia>
              <EmptyTitle>{t("admin.groups.empty")}</EmptyTitle>
              <EmptyDescription>{t("admin.groups.emptyHint")}</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <ul className="flex flex-col divide-y rounded-lg border">
            {query.data.map((group) => (
              <li
                key={group.id}
                className="flex flex-wrap items-center gap-3 p-3"
              >
                <div className="grid min-w-0 flex-1 gap-0.5">
                  <span className="truncate text-sm font-medium">
                    {group.name}
                  </span>
                  {group.description && (
                    <span className="text-xs break-words text-muted-foreground">
                      {group.description}
                    </span>
                  )}
                  <span className="text-xs text-muted-foreground">
                    {t("admin.groups.memberCount", {
                      count: group.memberCount,
                    })}
                  </span>
                </div>
                <div className="flex gap-1">
                  <Button
                    variant="outline"
                    size="sm"
                    aria-label={t("admin.groups.manageLabel", {
                      name: group.name,
                    })}
                    onClick={() => setEditing({ kind: "members", group })}
                  >
                    <UsersIcon data-icon="inline-start" />
                    {t("admin.groups.members.manage")}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={t("admin.groups.editLabel", {
                      name: group.name,
                    })}
                    title={t("admin.groups.edit")}
                    onClick={() => setEditing({ kind: "edit", group })}
                  >
                    <PencilIcon />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={t("admin.groups.deleteLabel", {
                      name: group.name,
                    })}
                    title={t("admin.groups.delete")}
                    onClick={() => setEditing({ kind: "delete", group })}
                  >
                    <Trash2Icon />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <Dialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) close()
        }}
      >
        <DialogContent closeLabel={t("common.actions.close")}>
          {editing?.kind === "create" && <GroupFlow onDone={close} />}
          {editing?.kind === "edit" && (
            <GroupFlow group={editing.group} onDone={close} />
          )}
          {editing?.kind === "delete" && (
            <DeleteFlow group={editing.group} onDone={close} />
          )}
          {editing?.kind === "members" && (
            <MembersFlow group={editing.group} onDone={close} />
          )}
        </DialogContent>
      </Dialog>
    </Card>
  )
}

/** Creates a group, or with `group` renames and redescribes it. */
function GroupFlow({ group, onDone }: { group?: Group; onDone: () => void }) {
  const { t } = useI18n()
  const [formError, setFormError] = React.useState<string | null>(null)

  const schema = React.useMemo(
    () =>
      z.object({
        name: z
          .string()
          .trim()
          .min(1, t("admin.groups.name.required"))
          .max(NAME_MAX, t("admin.groups.name.tooLong", { max: NAME_MAX })),
        description: z
          .string()
          .max(
            DESCRIPTION_MAX,
            t("admin.groups.descriptionField.tooLong", { max: DESCRIPTION_MAX })
          ),
      }),
    [t]
  )
  type Values = z.infer<typeof schema>

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: group?.name ?? "",
      description: group?.description ?? "",
    },
  })
  const { errors, isSubmitting } = form.formState

  const onSubmit = async (values: Values) => {
    setFormError(null)
    try {
      if (group) await api.admin.updateGroup(group.id, values)
      else await api.admin.createGroup(values)
    } catch (error) {
      if (hasCode(error, "conflict")) {
        form.setError(
          "name",
          { message: t("admin.groups.name.taken") },
          { shouldFocus: true }
        )
      } else {
        setFormError(errorMessage(error, t))
      }
      return
    }
    await refreshGroups()
    toast.success(group ? t("admin.groups.updated") : t("admin.groups.created"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>
          {group ? t("admin.groups.editTitle") : t("admin.groups.createTitle")}
        </DialogTitle>
        <DialogDescription>
          {group
            ? t("admin.groups.editDescription")
            : t("admin.groups.createDescription")}
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          <FormAlert message={formError} />
          <Field data-invalid={!!errors.name || undefined}>
            <FieldLabel htmlFor="group-name">
              {t("admin.groups.name.label")}
            </FieldLabel>
            <Input
              id="group-name"
              autoFocus
              maxLength={NAME_MAX}
              aria-invalid={!!errors.name}
              {...form.register("name")}
            />
            <FieldError errors={[errors.name]} />
          </Field>
          <Field data-invalid={!!errors.description || undefined}>
            <FieldLabel htmlFor="group-description">
              {t("admin.groups.descriptionField.label")}
            </FieldLabel>
            <Textarea
              id="group-description"
              maxLength={DESCRIPTION_MAX}
              aria-invalid={!!errors.description}
              {...form.register("description")}
            />
            <FieldError errors={[errors.description]} />
          </Field>
          <Button type="submit" disabled={isSubmitting}>
            {isSubmitting && <Spinner data-icon="inline-start" />}
            {isSubmitting
              ? t("common.actions.saving")
              : group
                ? t("common.actions.save")
                : t("admin.groups.create")}
          </Button>
        </FieldGroup>
      </form>
    </>
  )
}

function DeleteFlow({ group, onDone }: { group: Group; onDone: () => void }) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setFormError(null)
    try {
      await api.admin.deleteGroup(group.id)
    } catch (error) {
      if (!hasCode(error, "not_found")) {
        setBusy(false)
        setFormError(errorMessage(error, t))
        return
      }
    }
    await refreshGroups()
    // Apps that granted the group show it in their detail view.
    void queryClient.invalidateQueries({ queryKey: qk.apps })
    toast.success(t("admin.groups.deleted"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("admin.groups.deleteTitle")}</DialogTitle>
        <DialogDescription>
          {t("admin.groups.deleteDescription", { name: group.name })}
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
          {busy ? t("admin.groups.deleting") : t("admin.groups.deleteConfirm")}
        </Button>
      </DialogFooter>
    </>
  )
}

/**
 * Edits a group's membership as a draft: search to add, remove from the
 * list, then save the whole set (the endpoint replaces it).
 */
function MembersFlow({ group, onDone }: { group: Group; onDone: () => void }) {
  const { t } = useI18n()
  const query = useQuery({
    queryKey: qk.groupMembers(group.id),
    queryFn: async () => (await api.admin.groupMembers(group.id)).users ?? [],
  })
  const [draft, setDraft] = React.useState<User[] | null>(null)
  // A stable empty list, so the memo below does not change on every render.
  const serverMembers = query.data ?? NO_USERS
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const members = draft ?? serverMembers
  const ids = React.useMemo(() => new Set(members.map((u) => u.id)), [members])

  const add = (user: User) => {
    if (ids.has(user.id)) return
    setDraft([...members, user])
  }
  const remove = (user: User) => {
    setDraft(members.filter((u) => u.id !== user.id))
  }

  const save = async () => {
    setBusy(true)
    setFormError(null)
    try {
      await api.admin.setGroupMembers(group.id, [...ids])
    } catch (error) {
      setBusy(false)
      setFormError(errorMessage(error, t))
      return
    }
    await refreshGroups()
    toast.success(t("admin.groups.members.saved"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("admin.groups.members.title")}</DialogTitle>
        <DialogDescription>
          {t("admin.groups.members.description", { name: group.name })}
        </DialogDescription>
      </DialogHeader>
      <FieldGroup>
        <FormAlert message={formError} />
        <UserSearch autoFocus onPick={add} selectedIds={ids} />
        {query.isPending ? (
          <div className="flex justify-center py-4">
            <Spinner className="size-5 text-muted-foreground" />
          </div>
        ) : query.isError ? (
          <QueryError
            error={query.error}
            onRetry={() => void query.refetch()}
          />
        ) : (
          <div className="grid gap-2">
            <p className="text-sm font-medium" aria-live="polite">
              {t("admin.groups.members.count", { count: members.length })}
            </p>
            <ul className="flex max-h-64 flex-col divide-y overflow-y-auto rounded-lg border">
              {members.map((user) => (
                <li key={user.id} className="flex items-center gap-3 p-2.5">
                  <div className="min-w-0 flex-1">
                    <UserRow user={user} />
                  </div>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    disabled={busy}
                    aria-label={t("admin.groups.members.removeLabel", {
                      name: displayName(user),
                    })}
                    title={t("admin.groups.members.remove")}
                    onClick={() => remove(user)}
                  >
                    <XIcon />
                  </Button>
                </li>
              ))}
              {members.length === 0 && (
                <li className="p-3 text-sm text-muted-foreground">
                  {t("admin.groups.members.empty")}
                </li>
              )}
            </ul>
          </div>
        )}
      </FieldGroup>
      <DialogFooter>
        <Button variant="outline" onClick={onDone} disabled={busy}>
          {t("common.actions.cancel")}
        </Button>
        <Button
          onClick={() => void save()}
          disabled={busy || draft === null || !query.isSuccess}
        >
          {busy && <Spinner data-icon="inline-start" />}
          {busy ? t("common.actions.saving") : t("admin.groups.members.save")}
        </Button>
      </DialogFooter>
    </>
  )
}
