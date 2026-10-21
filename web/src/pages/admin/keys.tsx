import { Navigate } from "react-router"

import { SigningKeys } from "@/features/admin/signing-keys"
import { useI18n } from "@/i18n"
import { useMe } from "@/lib/queries"

export default function SigningKeysPage() {
  const { t } = useI18n()
  const { data: me } = useMe()

  if (!me) return null
  if (!me.permissions.manageKeys) return <Navigate to="/" replace />

  return (
    <>
      <div className="grid gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("admin.keys.pageTitle")}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t("admin.keys.pageDescription")}
        </p>
      </div>
      <SigningKeys />
    </>
  )
}
