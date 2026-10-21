import * as React from "react"
import { AppWindowIcon } from "lucide-react"
import { Navigate, useNavigate } from "react-router"
import { toast } from "sonner"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { AppForm, type AppFormValues } from "@/features/admin/app-form"
import { SecretDialog } from "@/features/admin/secret-dialog"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { qk, queryClient, useMe } from "@/lib/queries"

export default function AppsNewPage() {
  const { t } = useI18n()
  const navigate = useNavigate()
  const { data: me } = useMe()
  const [result, setResult] = React.useState<{
    clientSecret: string
    clientId: string
    slug: string
  } | null>(null)

  const onSubmit = async (values: AppFormValues) => {
    const { app, clientSecret } = await api.admin.createApp(values)
    await queryClient.invalidateQueries({ queryKey: qk.apps })
    toast.success(t("admin.apps.created"))
    // Only confidential clients have a secret to show.
    const target = `/apps/${encodeURIComponent(app.slug)}`
    if (!clientSecret) {
      navigate(target)
      return
    }
    setResult({ clientSecret, clientId: app.clientId, slug: app.slug })
  }

  if (!me) return null
  if (!me.permissions.createApps) return <Navigate to="/apps" replace />

  return (
    <>
      <div className="flex items-center gap-3 text-muted-foreground">
        <AppWindowIcon aria-hidden className="size-5" />
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          {t("admin.apps.createTitle")}
        </h1>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>{t("admin.apps.createDescription")}</CardTitle>
        </CardHeader>
        <CardContent>
          <AppForm
            onSubmit={onSubmit}
            submitLabel={t("admin.apps.create")}
            submittingLabel={t("admin.apps.creating")}
          />
        </CardContent>
      </Card>

      <SecretDialog
        secret={result?.clientSecret ?? null}
        clientId={result?.clientId}
        onClose={() => {
          if (result) navigate(`/apps/${encodeURIComponent(result.slug)}`)
        }}
      />
    </>
  )
}
