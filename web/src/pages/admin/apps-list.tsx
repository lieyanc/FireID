import { useQuery } from "@tanstack/react-query"
import { AppWindowIcon, ChevronRightIcon, PlusIcon } from "lucide-react"
import { Link, Navigate } from "react-router"

import { QueryError } from "@/components/common/query-state"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Spinner } from "@/components/ui/spinner"
import { APP_STATUS_LABELS, CLIENT_TYPE_LABELS } from "@/features/admin/labels"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { qk, useMe } from "@/lib/queries"

export default function AppsListPage() {
  const { t } = useI18n()
  const { data: me } = useMe()
  const manageApps = !!me?.permissions.manageApps
  const query = useQuery({
    queryKey: qk.apps,
    queryFn: async () => (await api.admin.apps()).apps ?? [],
    enabled: manageApps,
  })

  if (!me) return null
  if (!manageApps) return <Navigate to="/" replace />
  const createApps = me.permissions.createApps

  return (
    <>
      <div className="flex flex-wrap items-end gap-3">
        <div className="grid flex-1 gap-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            {t("admin.apps.title")}
          </h1>
          <p className="text-sm text-muted-foreground">
            {t("admin.apps.description")}
          </p>
        </div>
        {createApps && (
          <Button asChild>
            <Link to="/apps/new">
              <PlusIcon data-icon="inline-start" />
              {t("admin.apps.create")}
            </Link>
          </Button>
        )}
      </div>

      {query.isPending ? (
        <div className="flex justify-center py-8">
          <Spinner className="size-5 text-muted-foreground" />
        </div>
      ) : query.isError ? (
        <QueryError error={query.error} onRetry={() => void query.refetch()} />
      ) : query.data.length === 0 ? (
        <Empty className="border bg-card">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <AppWindowIcon />
            </EmptyMedia>
            <EmptyTitle>{t("admin.apps.empty")}</EmptyTitle>
            {createApps && (
              <EmptyDescription>{t("admin.apps.emptyHint")}</EmptyDescription>
            )}
          </EmptyHeader>
          {createApps && (
            <EmptyContent>
              <Button asChild>
                <Link to="/apps/new">
                  <PlusIcon data-icon="inline-start" />
                  {t("admin.apps.create")}
                </Link>
              </Button>
            </EmptyContent>
          )}
        </Empty>
      ) : (
        <ul className="flex flex-col divide-y overflow-hidden rounded-xl border bg-card">
          {query.data.map((app) => (
            <li key={app.id}>
              <Link
                to={`/apps/${encodeURIComponent(app.slug)}`}
                className="flex items-center gap-3 p-4 outline-none hover:bg-muted/50 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:ring-inset"
              >
                <AppWindowIcon
                  aria-hidden
                  className="size-5 shrink-0 text-muted-foreground"
                />
                <div className="grid min-w-0 flex-1 gap-0.5">
                  <span className="truncate font-medium">{app.name}</span>
                  <span className="truncate font-mono text-xs text-muted-foreground">
                    {app.slug}
                  </span>
                </div>
                <div className="hidden flex-wrap gap-1.5 sm:flex">
                  <Badge variant="outline">
                    {t(CLIENT_TYPE_LABELS[app.clientType])}
                  </Badge>
                </div>
                <Badge
                  variant={app.status === "active" ? "success" : "warning"}
                >
                  {t(APP_STATUS_LABELS[app.status])}
                </Badge>
                <ChevronRightIcon
                  aria-hidden
                  className="size-4 shrink-0 text-muted-foreground"
                />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </>
  )
}
