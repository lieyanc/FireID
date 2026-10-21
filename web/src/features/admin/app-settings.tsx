import * as React from "react"
import { KeyRoundIcon } from "lucide-react"
import { toast } from "sonner"

import { CopyButton } from "@/components/common/copy-button"
import { InfoList } from "@/components/common/info-list"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Spinner } from "@/components/ui/spinner"
import {
  AppForm,
  FormAlert,
  type AppFormValues,
} from "@/features/admin/app-form"
import { CLIENT_TYPE_LABELS } from "@/features/admin/labels"
import { SecretDialog } from "@/features/admin/secret-dialog"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { App, AppUpdate } from "@/lib/types"

/** Only the fields PATCH accepts; slug and client type are fixed. */
function updateFrom(values: AppFormValues): AppUpdate {
  return {
    name: values.name,
    description: values.description,
    homepageUrl: values.homepageUrl,
    tokenEndpointAuthMethod: values.tokenEndpointAuthMethod,
    redirectUris: values.redirectUris,
    postLogoutRedirectUris: values.postLogoutRedirectUris,
    registrationMode: values.registrationMode,
    defaultAccess: values.defaultAccess,
  }
}

/**
 * Client ID, secret rotation and the editable settings of an app.
 */
export function AppSettings({ app }: { app: App }) {
  const { t, fmt } = useI18n()
  const [rotating, setRotating] = React.useState(false)
  const [secret, setSecret] = React.useState<string | null>(null)

  const submit = async (values: AppFormValues) => {
    await api.admin.updateApp(app.slug, updateFrom(values))
    // Also refetches qk.forwardAuth: its hosts come from the redirect URIs.
    await queryClient.invalidateQueries({ queryKey: qk.app(app.slug) })
    void queryClient.invalidateQueries({ queryKey: qk.apps })
    toast.success(t("admin.detail.updated"))
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.detail.settings")}</CardTitle>
        <CardDescription>
          {t("admin.detail.settingsDescription")}
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-6">
        <div className="grid gap-3">
          <InfoList
            rows={[
              {
                label: t("admin.detail.clientId"),
                value: (
                  <span className="flex items-center gap-2">
                    <code className="min-w-0 font-mono text-xs break-all">
                      {app.clientId}
                    </code>
                    <CopyButton value={app.clientId} size="icon-xs" />
                  </span>
                ),
              },
              {
                label: t("admin.apps.clientType.label"),
                value: t(CLIENT_TYPE_LABELS[app.clientType]),
              },
              {
                label: t("admin.detail.pkce"),
                value: app.requirePkce
                  ? t("admin.detail.pkceRequired")
                  : t("admin.detail.pkceOptional"),
              },
              ...(app.clientType === "confidential"
                ? [
                    {
                      label: t("admin.detail.clientSecret"),
                      value: app.secretRotatedAt
                        ? t("admin.detail.secretLastRotated", {
                            date: fmt.dateTime(app.secretRotatedAt),
                          })
                        : t("admin.detail.secretNever"),
                    },
                  ]
                : []),
            ]}
          />
          {app.clientType === "confidential" && (
            <div>
              <Button variant="outline" onClick={() => setRotating(true)}>
                <KeyRoundIcon data-icon="inline-start" />
                {t("admin.detail.rotate")}
              </Button>
            </div>
          )}
        </div>
        <AppForm
          app={app}
          onSubmit={submit}
          submitLabel={t("common.actions.save")}
          submittingLabel={t("common.actions.saving")}
        />
      </CardContent>

      <Dialog open={rotating} onOpenChange={setRotating}>
        <DialogContent closeLabel={t("common.actions.close")}>
          {rotating && (
            <RotateFlow
              slug={app.slug}
              showSecret={setSecret}
              onDone={() => setRotating(false)}
            />
          )}
        </DialogContent>
      </Dialog>
      <SecretDialog
        secret={secret}
        clientId={app.clientId}
        onClose={() => setSecret(null)}
      />
    </Card>
  )
}

function RotateFlow({
  slug,
  showSecret,
  onDone,
}: {
  slug: string
  showSecret: (secret: string) => void
  onDone: () => void
}) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setFormError(null)
    let rotated: { clientSecret: string }
    try {
      rotated = await api.admin.rotateAppSecret(slug)
    } catch (error) {
      setBusy(false)
      setFormError(errorMessage(error, t))
      return
    }
    await queryClient.invalidateQueries({ queryKey: qk.app(slug) })
    toast.success(t("admin.detail.rotated"))
    onDone()
    showSecret(rotated.clientSecret)
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("admin.detail.rotateTitle")}</DialogTitle>
        <DialogDescription>
          {t("admin.detail.rotateDescription")}
        </DialogDescription>
      </DialogHeader>
      <FormAlert message={formError} />
      <DialogFooter>
        <Button variant="outline" onClick={onDone} disabled={busy}>
          {t("common.actions.cancel")}
        </Button>
        <Button onClick={() => void run()} disabled={busy}>
          {busy && <Spinner data-icon="inline-start" />}
          {busy
            ? t("admin.detail.rotateConfirming")
            : t("admin.detail.rotateConfirm")}
        </Button>
      </DialogFooter>
    </>
  )
}
