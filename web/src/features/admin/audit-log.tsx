import * as React from "react"
import { ChevronRightIcon, ScrollTextIcon } from "lucide-react"
import { Link } from "react-router"

import { InfoList, type InfoRow } from "@/components/common/info-list"
import { QueryError } from "@/components/common/query-state"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Spinner } from "@/components/ui/spinner"
import {
  AUDIT_ACTOR_LABELS,
  AUDIT_CATEGORY_LABELS,
  AUDIT_SEVERITY_LABELS,
  auditEventLabel,
  auditEventsIn,
  type AuditCategory,
} from "@/features/admin/labels"
import { NativeSelect } from "@/features/admin/native-select"
import { useI18n } from "@/i18n"
import type { useAuditLog } from "@/lib/queries"
import type { AuditEntry, AuditPerson } from "@/lib/types"

const SEVERITY_BADGE = {
  info: "outline",
  warning: "warning",
  critical: "destructive",
} as const

type AuditLogQuery = ReturnType<typeof useAuditLog>

function personName(person: AuditPerson) {
  return person.displayName || person.username
}

/** Name, login and ID of a person, for the expanded view. */
function personDetail(person: AuditPerson) {
  return (
    <span>
      {personName(person)}{" "}
      <span className="text-muted-foreground">
        @{person.username} · #{person.id}
      </span>
    </span>
  )
}

/**
 * Picks an event filter: everything, one category (a prefix such as
 * "auth.") or a single event. A value outside the catalogue, e.g. from a
 * link, is kept as an extra option so the select shows what is applied.
 */
export function EventSelect({
  id,
  value,
  onChange,
  categories,
}: {
  id: string
  value: string
  onChange: (value: string) => void
  categories: AuditCategory[]
}) {
  const { t } = useI18n()
  const known =
    value === "" ||
    categories.some(
      (category) =>
        value === `${category}.` || auditEventsIn(category).includes(value)
    )

  return (
    <NativeSelect
      id={id}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      <option value="">{t("admin.audit.filter.allEvents")}</option>
      {!known && <option value={value}>{value}</option>}
      {categories.map((category) => {
        const name = t(AUDIT_CATEGORY_LABELS[category])
        return (
          <optgroup key={category} label={name}>
            <option value={`${category}.`}>
              {t("admin.audit.filter.allIn", { category: name })}
            </option>
            {auditEventsIn(category).map((event) => {
              const label = auditEventLabel(event)
              return (
                <option key={event} value={event}>
                  {label ? t(label) : event}
                </option>
              )
            })}
          </optgroup>
        )
      })}
    </NativeSelect>
  )
}

/**
 * Audit entries with a "load more" button. `showApp` adds the app to each
 * entry; the log of a single app leaves it out.
 */
export function AuditLog({
  query,
  showApp,
  filtered,
}: {
  query: AuditLogQuery
  showApp: boolean
  /** A filter is applied, so an empty result says so. */
  filtered: boolean
}) {
  const { t } = useI18n()

  if (query.isPending) {
    return (
      <div className="flex justify-center py-4">
        <Spinner className="size-5 text-muted-foreground" />
      </div>
    )
  }
  if (query.isError && !query.isFetchNextPageError) {
    return (
      <QueryError error={query.error} onRetry={() => void query.refetch()} />
    )
  }

  const entries = query.data.pages.flatMap((page) => page.entries ?? [])
  if (entries.length === 0) {
    return (
      <Empty className="border">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ScrollTextIcon />
          </EmptyMedia>
          <EmptyTitle>
            {filtered ? t("admin.audit.noMatches") : t("admin.audit.empty")}
          </EmptyTitle>
          <EmptyDescription>
            {filtered
              ? t("admin.audit.noMatchesHint")
              : t("admin.audit.emptyHint")}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="grid gap-3">
      <ul
        aria-label={t("admin.audit.entries")}
        className="flex flex-col divide-y rounded-lg border"
      >
        {entries.map((entry) => (
          <AuditRow key={entry.id} entry={entry} showApp={showApp} />
        ))}
      </ul>
      {query.isFetchNextPageError && (
        <QueryError
          error={query.error}
          onRetry={() => void query.fetchNextPage()}
        />
      )}
      {query.hasNextPage && !query.isFetchNextPageError && (
        <Button
          variant="outline"
          className="justify-self-center"
          disabled={query.isFetchingNextPage}
          onClick={() => void query.fetchNextPage()}
        >
          {query.isFetchingNextPage && <Spinner data-icon="inline-start" />}
          {query.isFetchingNextPage
            ? t("admin.audit.loadingMore")
            : t("admin.audit.loadMore")}
        </Button>
      )}
    </div>
  )
}

function AuditRow({ entry, showApp }: { entry: AuditEntry; showApp: boolean }) {
  const { t, fmt } = useI18n()
  const label = auditEventLabel(entry.event)
  const actorType = AUDIT_ACTOR_LABELS[entry.actorType]
  const actorTypeText = actorType ? t(actorType) : entry.actorType
  const severity = AUDIT_SEVERITY_LABELS[entry.severity]
  const hasDetail = !!entry.detail && Object.keys(entry.detail).length > 0

  const facts: { label: string; value: React.ReactNode }[] = [
    {
      label: t("admin.audit.field.actor"),
      value: entry.actor ? personName(entry.actor) : actorTypeText,
    },
  ]
  if (entry.user && entry.user.id !== entry.actor?.id) {
    facts.push({
      label: t("admin.audit.field.user"),
      value: personName(entry.user),
    })
  }
  if (showApp && entry.app) {
    facts.push({
      label: t("admin.audit.field.app"),
      value: (
        <Link
          to={`/apps/${encodeURIComponent(entry.app.slug)}`}
          className="rounded underline-offset-4 outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50"
        >
          {entry.app.name}
        </Link>
      ),
    })
  }
  if (entry.ip) {
    facts.push({ label: t("admin.audit.field.ip"), value: entry.ip })
  }

  const rows: InfoRow[] = [
    {
      label: t("admin.audit.field.actor"),
      value: entry.actor ? (
        <span>
          {personDetail(entry.actor)}{" "}
          <Badge variant="outline">{actorTypeText}</Badge>
        </span>
      ) : (
        actorTypeText
      ),
    },
  ]
  if (entry.user) {
    rows.push({
      label: t("admin.audit.field.user"),
      value: personDetail(entry.user),
    })
  }
  if (entry.app) {
    rows.push({
      label: t("admin.audit.field.app"),
      value: (
        <span>
          {entry.app.name}{" "}
          <span className="font-mono text-xs text-muted-foreground">
            {entry.app.slug}
          </span>
        </span>
      ),
    })
  }
  rows.push(
    { label: t("admin.audit.field.ip"), value: entry.ip || "–" },
    {
      label: t("admin.audit.field.userAgent"),
      value: entry.userAgent || "–",
    },
    {
      label: t("admin.audit.field.event"),
      value: entry.event,
      mono: true,
    },
    { label: t("admin.audit.field.id"), value: entry.id, mono: true }
  )

  return (
    <li className="grid gap-1.5 p-3">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <Badge variant={SEVERITY_BADGE[entry.severity] ?? "outline"}>
          {severity ? t(severity) : entry.severity}
        </Badge>
        <span className="text-sm font-medium">
          {label ? t(label) : entry.event}
        </span>
        <time
          dateTime={entry.at}
          title={fmt.relative(entry.at)}
          className="ml-auto text-xs whitespace-nowrap text-muted-foreground"
        >
          {fmt.dateTime(entry.at)}
        </time>
      </div>
      <dl className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs">
        {facts.map((fact) => (
          <div key={fact.label} className="flex min-w-0 gap-1">
            <dt className="text-muted-foreground">{fact.label}</dt>
            <dd className="min-w-0 break-all">{fact.value}</dd>
          </div>
        ))}
      </dl>
      <details className="group">
        <summary className="flex w-fit cursor-pointer list-none items-center gap-1 rounded text-xs text-muted-foreground outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 [&::-webkit-details-marker]:hidden">
          <ChevronRightIcon
            aria-hidden
            className="size-3.5 transition-transform group-open:rotate-90"
          />
          {t("admin.audit.details")}
        </summary>
        <div className="mt-2 grid gap-3 rounded-lg border bg-muted/30 p-3">
          <InfoList rows={rows} className="text-xs" />
          {hasDetail && (
            /* Focusable so the scrollable region can be scrolled by keyboard. */
            <pre
              tabIndex={0}
              aria-label={t("admin.audit.field.detail")}
              className="overflow-x-auto rounded-md border bg-background p-2.5 font-mono text-xs leading-5 outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
            >
              <code>{JSON.stringify(entry.detail, null, 2)}</code>
            </pre>
          )}
        </div>
      </details>
    </li>
  )
}
