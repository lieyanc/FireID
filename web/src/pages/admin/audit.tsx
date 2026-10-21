import { Navigate } from "react-router"

import { AuditBrowser } from "@/features/admin/audit-browser"
import { useI18n } from "@/i18n"
import { useMe } from "@/lib/queries"

export default function AuditPage() {
  const { t } = useI18n()
  const { data: me } = useMe()
  const viewAudit = !!me?.permissions.viewAudit

  if (!me) return null
  if (!viewAudit) return <Navigate to="/" replace />

  return (
    <>
      <div className="grid gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("admin.audit.pageTitle")}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t("admin.audit.pageDescription")}
        </p>
      </div>
      <AuditBrowser />
    </>
  )
}
