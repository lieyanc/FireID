import { useQuery } from "@tanstack/react-query"
import { ArrowLeftIcon } from "lucide-react"
import { Link, Navigate, useParams } from "react-router"

import { QueryError } from "@/components/common/query-state"
import { Badge } from "@/components/ui/badge"
import { Spinner } from "@/components/ui/spinner"
import { AccessRequests } from "@/features/admin/access-requests"
import { AppActivity } from "@/features/admin/app-activity"
import { AppAccess } from "@/features/admin/app-access"
import { AppDanger } from "@/features/admin/app-danger"
import { AppSettings } from "@/features/admin/app-settings"
import { BackchannelLogout } from "@/features/admin/backchannel-logout"
import { ForwardAuth } from "@/features/admin/forward-auth"
import { APP_STATUS_LABELS, CLIENT_TYPE_LABELS } from "@/features/admin/labels"
import { MembersList } from "@/features/admin/members-list"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { qk, useMe } from "@/lib/queries"

export default function AppDetailPage() {
  const { t } = useI18n()
  const { slug = "" } = useParams()
  const { data: me } = useMe()
  const manageApps = !!me?.permissions.manageApps
  const query = useQuery({
    queryKey: qk.app(slug),
    queryFn: () => api.admin.app(slug),
    enabled: manageApps && slug !== "",
  })

  if (!me) return null
  if (!manageApps) return <Navigate to="/" replace />

  if (query.isPending) {
    return (
      <div className="flex flex-1 items-center justify-center py-16">
        <Spinner className="size-6 text-muted-foreground" />
      </div>
    )
  }
  if (query.isError) {
    return (
      <QueryError error={query.error} onRetry={() => void query.refetch()} />
    )
  }

  const {
    app,
    members,
    groups,
    pendingRequests,
    canDelete,
    backchannelPending,
  } = query.data

  return (
    <>
      <div className="grid gap-2">
        <Link
          to="/apps"
          className="flex w-fit items-center gap-1.5 rounded text-sm text-muted-foreground outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50"
        >
          <ArrowLeftIcon aria-hidden className="size-4" />
          {t("admin.detail.backToList")}
        </Link>
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-semibold tracking-tight">{app.name}</h1>
          <Badge variant={app.status === "active" ? "success" : "warning"}>
            {t(APP_STATUS_LABELS[app.status])}
          </Badge>
          <Badge variant="outline">
            {t(CLIENT_TYPE_LABELS[app.clientType])}
          </Badge>
        </div>
        <p className="font-mono text-xs text-muted-foreground">{app.slug}</p>
        {app.description && (
          <p className="text-sm break-words whitespace-pre-line">
            {app.description}
          </p>
        )}
      </div>

      <AppSettings app={app} />
      <BackchannelLogout app={app} pending={backchannelPending ?? 0} />
      <MembersList app={app} members={members} />
      <AppAccess app={app} granted={groups} />
      <ForwardAuth app={app} />
      <AccessRequests app={app} requests={pendingRequests} />
      <AppActivity app={app} />
      <AppDanger app={app} canDelete={canDelete} />
    </>
  )
}
