import * as React from "react"
import { PowerIcon, Trash2Icon } from "lucide-react"
import { useNavigate } from "react-router"
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
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { FormAlert } from "@/features/admin/app-form"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { App, AppStatus } from "@/lib/types"

function refreshApp(slug: string) {
  void queryClient.invalidateQueries({ queryKey: qk.app(slug) })
  void queryClient.invalidateQueries({ queryKey: qk.apps })
}

/** Suspending is reversible; deleting is not and needs the slug typed. */
export function AppDanger({
  app,
  canDelete,
}: {
  app: App
  canDelete: boolean
}) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [status, setStatus] = React.useState<AppStatus | null>(null)
  const [deleting, setDeleting] = React.useState(false)
  const suspending = app.status === "active"

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.danger.title")}</CardTitle>
        <CardDescription>
          {suspending
            ? t("admin.danger.suspendHint")
            : t("admin.danger.activateHint")}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            onClick={() => setStatus(suspending ? "suspended" : "active")}
          >
            <PowerIcon data-icon="inline-start" />
            {suspending
              ? t("admin.detail.suspend")
              : t("admin.detail.activate")}
          </Button>
          {canDelete && (
            <Button variant="destructive" onClick={() => setDeleting(true)}>
              <Trash2Icon data-icon="inline-start" />
              {t("admin.detail.delete")}
            </Button>
          )}
        </div>
      </CardContent>

      <Dialog
        open={status !== null}
        onOpenChange={(open) => {
          if (!open) setStatus(null)
        }}
      >
        <DialogContent closeLabel={t("common.actions.close")}>
          {status && (
            <StatusFlow
              app={app}
              status={status}
              onDone={() => setStatus(null)}
            />
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={deleting} onOpenChange={setDeleting}>
        <DialogContent closeLabel={t("common.actions.close")}>
          {deleting && (
            <DeleteFlow
              app={app}
              onDone={() => {
                setDeleting(false)
                navigate("/apps", { replace: true })
              }}
            />
          )}
        </DialogContent>
      </Dialog>
    </Card>
  )
}

function StatusFlow({
  app,
  status,
  onDone,
}: {
  app: App
  status: AppStatus
  onDone: () => void
}) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)
  const activate = status === "active"

  const run = async () => {
    setBusy(true)
    setFormError(null)
    try {
      await api.admin.setAppStatus(app.slug, status)
    } catch (error) {
      setBusy(false)
      setFormError(errorMessage(error, t))
      return
    }
    refreshApp(app.slug)
    toast.success(
      activate ? t("admin.detail.activated") : t("admin.detail.suspended")
    )
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>
          {activate
            ? t("admin.detail.activateTitle")
            : t("admin.detail.suspendTitle")}
        </DialogTitle>
        <DialogDescription>
          {activate
            ? t("admin.detail.activateDescription")
            : t("admin.detail.suspendDescription")}
        </DialogDescription>
      </DialogHeader>
      <FormAlert message={formError} />
      <DialogFooter>
        <Button variant="outline" onClick={onDone} disabled={busy}>
          {t("common.actions.cancel")}
        </Button>
        <Button
          variant={activate ? "default" : "destructive"}
          onClick={() => void run()}
          disabled={busy}
        >
          {busy && <Spinner data-icon="inline-start" />}
          {busy
            ? activate
              ? t("admin.detail.activateConfirming")
              : t("admin.detail.suspendConfirming")
            : activate
              ? t("admin.detail.activateConfirm")
              : t("admin.detail.suspendConfirm")}
        </Button>
      </DialogFooter>
    </>
  )
}

function DeleteFlow({ app, onDone }: { app: App; onDone: () => void }) {
  const { t } = useI18n()
  const [typed, setTyped] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)
  const inputId = React.useId()
  const matches = typed.trim() === app.slug

  const run = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!matches) return
    setBusy(true)
    setFormError(null)
    try {
      await api.admin.deleteApp(app.slug)
    } catch (error) {
      setBusy(false)
      setFormError(errorMessage(error, t))
      return
    }
    void queryClient.invalidateQueries({ queryKey: qk.apps })
    toast.success(t("admin.detail.deleted"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("admin.detail.deleteTitle")}</DialogTitle>
        <DialogDescription>
          {t("admin.detail.deleteDescription")}
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={(e) => void run(e)} noValidate>
        <FieldGroup>
          <FormAlert message={formError} />
          <Field data-invalid={typed !== "" && !matches ? true : undefined}>
            <FieldLabel htmlFor={inputId}>
              {t("admin.detail.deletePrompt", { slug: app.slug })}
            </FieldLabel>
            <Input
              id={inputId}
              autoFocus
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              aria-invalid={typed !== "" && !matches}
            />
          </Field>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={onDone}
              disabled={busy}
            >
              {t("common.actions.cancel")}
            </Button>
            <Button
              type="submit"
              variant="destructive"
              disabled={!matches || busy}
            >
              {busy && <Spinner data-icon="inline-start" />}
              {busy
                ? t("admin.detail.deleteConfirming")
                : t("admin.detail.deleteConfirm")}
            </Button>
          </DialogFooter>
        </FieldGroup>
      </form>
    </>
  )
}
