import * as React from "react"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Field, FieldLabel } from "@/components/ui/field"
import { AuditLog, EventSelect } from "@/features/admin/audit-log"
import type { AuditCategory } from "@/features/admin/labels"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { qk, useAuditLog } from "@/lib/queries"
import type { App } from "@/lib/types"

/** Entries per page: the card shares the page with the app's settings. */
const PAGE_SIZE = 10

/** The kinds of event that can name an app. */
const APP_CATEGORIES: AuditCategory[] = ["app", "auth", "oauth", "backchannel"]

/** The audit log of one app, for anyone who manages it. */
export function AppActivity({ app }: { app: App }) {
  const { t } = useI18n()
  const eventId = React.useId()
  const [event, setEvent] = React.useState("")
  const filter = React.useMemo(() => ({ event: event || undefined }), [event])
  const query = useAuditLog(qk.appAudit(app.slug, filter), (before) =>
    api.admin.appAudit(app.slug, filter, before, PAGE_SIZE)
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.audit.appTitle")}</CardTitle>
        <CardDescription>{t("admin.audit.appDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <Field className="sm:max-w-xs">
          <FieldLabel htmlFor={eventId}>
            {t("admin.audit.filter.event")}
          </FieldLabel>
          <EventSelect
            id={eventId}
            value={event}
            onChange={setEvent}
            categories={APP_CATEGORIES}
          />
        </Field>
        <AuditLog query={query} showApp={false} filtered={event !== ""} />
      </CardContent>
    </Card>
  )
}
