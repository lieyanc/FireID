import { Navigate } from "react-router"

import { GroupsAdmin } from "@/features/admin/groups-admin"
import { useI18n } from "@/i18n"
import { useMe } from "@/lib/queries"

export default function GroupsPage() {
  const { t } = useI18n()
  const { data: me } = useMe()

  if (!me) return null
  // Group writes are super-admin only (guard(true) on every group route).
  if (!me.permissions.superAdmin) return <Navigate to="/" replace />

  return (
    <>
      <div className="grid gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("admin.groups.pageTitle")}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t("admin.groups.pageDescription")}
        </p>
      </div>
      <GroupsAdmin />
    </>
  )
}
