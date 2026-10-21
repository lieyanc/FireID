import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { toast } from "sonner"

import { InfoList } from "@/components/common/info-list"
import { QueryError } from "@/components/common/query-state"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field"
import { Spinner } from "@/components/ui/spinner"
import { FormAlert } from "@/features/admin/app-form"
import {
  DEFAULT_ACCESS_LABELS,
  REGISTRATION_MODE_LABELS,
} from "@/features/admin/labels"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { App, GroupRef } from "@/lib/types"

function sameSet(a: ReadonlySet<number>, b: ReadonlySet<number>) {
  return a.size === b.size && [...a].every((id) => b.has(id))
}

/**
 * Who may use the app besides its members: the registration policy (edited
 * with the settings) and the groups granted to it.
 */
export function AppAccess({ app, granted }: { app: App; granted: GroupRef[] }) {
  const { t } = useI18n()
  const groups = useQuery({
    queryKey: qk.groups,
    queryFn: async () => (await api.admin.groups()).groups ?? [],
  })
  // Derived from the IDs, so a refetch with the same grants does not discard
  // the person's unsaved changes.
  const grantedKey = granted
    .map((g) => g.id)
    .sort((a, b) => a - b)
    .join(",")
  const initial = React.useMemo(
    () => new Set(grantedKey ? grantedKey.split(",").map(Number) : []),
    [grantedKey]
  )
  // Follow the server after a save or a refetch (React's "adjust state when a
  // prop changes" pattern: set it during render, not in an effect).
  const [selection, setSelection] = React.useState({
    base: initial,
    value: initial,
  })
  if (selection.base !== initial) {
    setSelection({ base: initial, value: initial })
  }
  const selected = selection.value
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const toggle = (id: number, on: boolean) => {
    setSelection((prev) => {
      const next = new Set(prev.value)
      if (on) next.add(id)
      else next.delete(id)
      return { base: prev.base, value: next }
    })
  }

  const save = async () => {
    setBusy(true)
    setFormError(null)
    try {
      await api.admin.setAppGroups(app.slug, [...selected])
    } catch (error) {
      setBusy(false)
      setFormError(errorMessage(error, t))
      return
    }
    await queryClient.invalidateQueries({ queryKey: qk.app(app.slug) })
    setBusy(false)
    toast.success(t("admin.access.saved"))
  }

  const changed = !sameSet(selected, initial)

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.access.title")}</CardTitle>
        <CardDescription>{t("admin.access.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <FieldGroup>
          <InfoList
            rows={[
              {
                label: t("admin.apps.registrationMode.label"),
                value: t(REGISTRATION_MODE_LABELS[app.registrationMode]),
              },
              {
                label: t("admin.apps.defaultAccess.label"),
                value: t(DEFAULT_ACCESS_LABELS[app.defaultAccess]),
              },
            ]}
          />
          <FormAlert message={formError} />
          <FieldSet>
            <FieldLegend variant="label">
              {t("admin.access.groups")}
            </FieldLegend>
            <FieldDescription>{t("admin.access.groupsHint")}</FieldDescription>
            {groups.isPending ? (
              <div className="flex justify-center py-4">
                <Spinner className="size-5 text-muted-foreground" />
              </div>
            ) : groups.isError ? (
              <QueryError
                error={groups.error}
                onRetry={() => void groups.refetch()}
              />
            ) : groups.data.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {t("admin.access.noGroups")}
              </p>
            ) : (
              <FieldGroup data-slot="checkbox-group" className="gap-3">
                {groups.data.map((group) => {
                  const id = `app-group-${group.id}`
                  return (
                    <Field key={group.id} orientation="horizontal">
                      <Checkbox
                        id={id}
                        checked={selected.has(group.id)}
                        disabled={busy}
                        onCheckedChange={(v) => toggle(group.id, v === true)}
                      />
                      <FieldContent>
                        <FieldLabel htmlFor={id} className="font-normal">
                          {group.name}
                        </FieldLabel>
                        {group.description && (
                          <FieldDescription>
                            {group.description}
                          </FieldDescription>
                        )}
                      </FieldContent>
                    </Field>
                  )
                })}
              </FieldGroup>
            )}
          </FieldSet>
        </FieldGroup>
      </CardContent>
      {groups.isSuccess && groups.data.length > 0 && (
        <CardFooter>
          <Button disabled={!changed || busy} onClick={() => void save()}>
            {busy && <Spinner data-icon="inline-start" />}
            {busy ? t("common.actions.saving") : t("admin.access.save")}
          </Button>
        </CardFooter>
      )}
    </Card>
  )
}
