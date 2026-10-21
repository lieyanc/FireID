import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { FilterXIcon } from "lucide-react"
import { useSearchParams } from "react-router"

import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Field, FieldError, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { AuditLog, EventSelect } from "@/features/admin/audit-log"
import { type AuditCategory } from "@/features/admin/labels"
import { NativeSelect } from "@/features/admin/native-select"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { qk, useAuditLog } from "@/lib/queries"
import type { AuditFilter } from "@/lib/types"

const ALL_CATEGORIES: AuditCategory[] = [
  "auth",
  "account",
  "app",
  "group",
  "key",
  "oauth",
  "backchannel",
  "setup",
]

/** A user ID typed by hand: a positive integer, as the API parses it. */
const USER_ID = /^[1-9]\d*$/

/** The filters live in the URL, so a filtered view can be linked to. */
function filterOf(params: URLSearchParams): AuditFilter {
  const user = params.get("user") ?? ""
  return {
    event: params.get("event") || undefined,
    app: params.get("app") || undefined,
    user: USER_ID.test(user) ? Number(user) : undefined,
  }
}

/** Every audit entry (super admin), filtered by event, app and person. */
export function AuditBrowser() {
  const { t } = useI18n()
  const [params, setParams] = useSearchParams()
  const filter = React.useMemo(() => filterOf(params), [params])
  const query = useAuditLog(qk.audit(filter), (before) =>
    api.admin.audit(filter, before)
  )
  const apps = useQuery({
    queryKey: qk.apps,
    queryFn: async () => (await api.admin.apps()).apps ?? [],
  })

  const set = (name: keyof AuditFilter, value: string) => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        if (value) next.set(name, value)
        else next.delete(name)
        return next
      },
      { replace: true }
    )
  }

  // The user ID is applied on submit, not on every keystroke; the draft
  // follows the URL when it changes underneath (back button, clear).
  const applied = filter.user !== undefined ? String(filter.user) : ""
  const [user, setUser] = React.useState({ base: applied, value: applied })
  if (user.base !== applied) setUser({ base: applied, value: applied })
  const userDraft = user.value.trim()
  const userInvalid = userDraft !== "" && !USER_ID.test(userDraft)

  const applyUser = (e: React.FormEvent) => {
    e.preventDefault()
    if (!userInvalid) set("user", userDraft)
  }

  const filtered = !!(filter.event || filter.app || filter.user !== undefined)
  const appSlugs = new Set((apps.data ?? []).map((app) => app.slug))

  const id = (name: string) => `audit-filter-${name}`

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.audit.listTitle")}</CardTitle>
        <CardDescription>{t("admin.audit.listDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid items-start gap-3 sm:grid-cols-3">
          <Field>
            <FieldLabel htmlFor={id("event")}>
              {t("admin.audit.filter.event")}
            </FieldLabel>
            <EventSelect
              id={id("event")}
              value={filter.event ?? ""}
              onChange={(value) => set("event", value)}
              categories={ALL_CATEGORIES}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor={id("app")}>
              {t("admin.audit.filter.app")}
            </FieldLabel>
            <NativeSelect
              id={id("app")}
              value={filter.app ?? ""}
              disabled={apps.isPending}
              onChange={(e) => set("app", e.target.value)}
            >
              <option value="">{t("admin.audit.filter.allApps")}</option>
              {filter.app && !appSlugs.has(filter.app) && (
                <option value={filter.app}>{filter.app}</option>
              )}
              {(apps.data ?? []).map((app) => (
                <option key={app.slug} value={app.slug}>
                  {app.name}
                </option>
              ))}
            </NativeSelect>
          </Field>
          <form onSubmit={applyUser} noValidate>
            <Field data-invalid={userInvalid || undefined}>
              <FieldLabel htmlFor={id("user")}>
                {t("admin.audit.filter.user")}
              </FieldLabel>
              <div className="flex gap-2">
                <Input
                  id={id("user")}
                  inputMode="numeric"
                  autoComplete="off"
                  placeholder={t("admin.audit.filter.userPlaceholder")}
                  aria-invalid={userInvalid}
                  value={user.value}
                  onChange={(e) =>
                    setUser({ base: applied, value: e.target.value })
                  }
                />
                <Button
                  type="submit"
                  variant="outline"
                  disabled={userInvalid || userDraft === applied}
                >
                  {t("admin.audit.filter.apply")}
                </Button>
              </div>
              {userInvalid && (
                <FieldError>{t("admin.audit.filter.userInvalid")}</FieldError>
              )}
            </Field>
          </form>
        </div>
        {filtered && (
          <Button
            variant="ghost"
            size="sm"
            className="justify-self-start"
            onClick={() => setParams(new URLSearchParams(), { replace: true })}
          >
            <FilterXIcon data-icon="inline-start" />
            {t("admin.audit.filter.clear")}
          </Button>
        )}
        <AuditLog query={query} showApp filtered={filtered} />
      </CardContent>
    </Card>
  )
}
