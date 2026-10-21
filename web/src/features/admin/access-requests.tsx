import * as React from "react"
import { CheckIcon, XIcon } from "lucide-react"
import { toast } from "sonner"

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
import { FormAlert } from "@/features/admin/app-form"
import { UserRow } from "@/features/admin/user-search"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { AccessRequest, App } from "@/lib/types"
import { displayName } from "@/lib/user"

type Deciding = { request: AccessRequest; approve: boolean }

/** Pending requests to use an app, each approved or denied after a confirm. */
export function AccessRequests({
  app,
  requests,
}: {
  app: App
  requests: AccessRequest[]
}) {
  const { t, fmt } = useI18n()
  const [deciding, setDeciding] = React.useState<Deciding | null>(null)

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.requests.title")}</CardTitle>
        <CardDescription>{t("admin.requests.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col divide-y rounded-lg border">
          {requests.map((request) => {
            const name = displayName(request.user)
            return (
              <li
                key={request.id}
                className="flex flex-wrap items-start gap-3 p-3"
              >
                <div className="grid min-w-0 flex-1 gap-1.5">
                  <UserRow user={request.user} />
                  {request.message && (
                    <p className="text-sm break-words whitespace-pre-line">
                      {request.message}
                    </p>
                  )}
                  <p
                    className="text-xs text-muted-foreground"
                    title={fmt.dateTime(request.createdAt)}
                  >
                    {t("admin.requests.requested", {
                      date: fmt.relative(request.createdAt),
                    })}
                  </p>
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    aria-label={t("admin.requests.denyLabel", { name })}
                    onClick={() => setDeciding({ request, approve: false })}
                  >
                    <XIcon data-icon="inline-start" />
                    {t("admin.requests.deny")}
                  </Button>
                  <Button
                    size="sm"
                    aria-label={t("admin.requests.approveLabel", { name })}
                    onClick={() => setDeciding({ request, approve: true })}
                  >
                    <CheckIcon data-icon="inline-start" />
                    {t("admin.requests.approve")}
                  </Button>
                </div>
              </li>
            )
          })}
          {requests.length === 0 && (
            <li className="p-3 text-sm text-muted-foreground">
              {t("admin.requests.empty")}
            </li>
          )}
        </ul>
      </CardContent>

      <Dialog
        open={deciding !== null}
        onOpenChange={(open) => {
          if (!open) setDeciding(null)
        }}
      >
        <DialogContent closeLabel={t("common.actions.close")}>
          {deciding && (
            <DecideFlow
              app={app}
              {...deciding}
              onDone={() => setDeciding(null)}
            />
          )}
        </DialogContent>
      </Dialog>
    </Card>
  )
}

function DecideFlow({
  app,
  request,
  approve,
  onDone,
}: Deciding & { app: App; onDone: () => void }) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)
  const name = displayName(request.user)

  const run = async () => {
    setBusy(true)
    setFormError(null)
    let message = approve
      ? t("admin.requests.approved")
      : t("admin.requests.denied")
    try {
      await api.admin.decideAccessRequest(app.slug, request.id, approve)
    } catch (error) {
      // Someone else decided it first: the refresh below shows the outcome.
      if (!hasCode(error, "conflict", "not_found")) {
        setBusy(false)
        setFormError(errorMessage(error, t))
        return
      }
      message = t("admin.requests.alreadyDecided")
    }
    // Approval adds a membership, so the whole detail view is refreshed.
    await queryClient.invalidateQueries({ queryKey: qk.app(app.slug) })
    toast.success(message)
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>
          {approve
            ? t("admin.requests.approveTitle")
            : t("admin.requests.denyTitle")}
        </DialogTitle>
        <DialogDescription>
          {approve
            ? t("admin.requests.approveDescription", { name })
            : t("admin.requests.denyDescription", { name })}
        </DialogDescription>
      </DialogHeader>
      <FormAlert message={formError} />
      <DialogFooter>
        <Button variant="outline" onClick={onDone} disabled={busy}>
          {t("common.actions.cancel")}
        </Button>
        <Button
          variant={approve ? "default" : "destructive"}
          onClick={() => void run()}
          disabled={busy}
        >
          {busy && <Spinner data-icon="inline-start" />}
          {busy
            ? t("admin.requests.deciding")
            : approve
              ? t("admin.requests.approve")
              : t("admin.requests.deny")}
        </Button>
      </DialogFooter>
    </>
  )
}
