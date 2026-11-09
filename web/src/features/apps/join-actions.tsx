import * as React from "react"
import { LogInIcon, SendIcon } from "lucide-react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Field, FieldError, FieldLabel } from "@/components/ui/field"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"
import { FormAlert } from "@/features/admin/app-form"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode, toastError } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"

/** Same cap as POST /api/apps/:slug/request. */
const MESSAGE_MAX = 500

type Target = {
  /** Only ever sent to the API, which decides again. */
  slug: string
  name: string
  /** Called after the catalog was refreshed. */
  onDone?: () => void
}

async function refreshCatalog() {
  await queryClient.invalidateQueries({ queryKey: qk.catalog })
}

/** Becomes a member of an app whose registration is open. */
export function JoinButton({
  slug,
  name,
  onDone,
  className,
}: Target & { className?: string }) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)

  const run = async () => {
    setBusy(true)
    try {
      await api.catalog.join(slug)
      toast.success(t("apps.join.joined", { app: name }))
    } catch (error) {
      // The app changed (or was never joinable): the refresh shows how.
      if (hasCode(error, "conflict", "not_found")) {
        toast.error(t("apps.join.unavailable"))
      } else {
        setBusy(false)
        toastError(error, t)
        return
      }
    }
    await refreshCatalog()
    setBusy(false)
    onDone?.()
  }

  return (
    <Button
      className={className}
      disabled={busy}
      aria-label={t("apps.join.joinLabel", { app: name })}
      onClick={() => void run()}
    >
      {busy ? (
        <Spinner data-icon="inline-start" />
      ) : (
        <LogInIcon data-icon="inline-start" />
      )}
      {busy ? t("apps.join.joining") : t("apps.join.join")}
    </Button>
  )
}

/** Asks the managers of an app whose registration needs approval. */
export function RequestAccessButton({
  slug,
  name,
  onDone,
  className,
}: Target & { className?: string }) {
  const { t } = useI18n()
  const [open, setOpen] = React.useState(false)
  return (
    <>
      <Button
        className={className}
        variant="outline"
        aria-label={t("apps.join.requestLabel", { app: name })}
        onClick={() => setOpen(true)}
      >
        <SendIcon data-icon="inline-start" />
        {t("apps.join.request")}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent closeLabel={t("common.actions.close")}>
          {open && (
            <RequestFlow
              slug={slug}
              name={name}
              onCancel={() => setOpen(false)}
              onDone={() => {
                setOpen(false)
                onDone?.()
              }}
            />
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}

function RequestFlow({
  slug,
  name,
  onCancel,
  onDone,
}: Target & { onCancel: () => void; onDone: () => void }) {
  const { t } = useI18n()
  const id = React.useId()
  const [message, setMessage] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)
  const tooLong = Array.from(message.trim()).length > MESSAGE_MAX

  const run = async (event: React.FormEvent) => {
    event.preventDefault()
    if (tooLong) return
    setBusy(true)
    setFormError(null)
    try {
      await api.catalog.request(slug, message.trim() || undefined)
      toast.success(t("apps.join.requested", { app: name }))
    } catch (error) {
      if (hasCode(error, "conflict")) {
        toast.info(t("apps.join.alreadyPending"))
      } else if (hasCode(error, "not_found")) {
        toast.error(t("apps.join.unavailable"))
      } else {
        setBusy(false)
        setFormError(errorMessage(error, t))
        return
      }
    }
    await refreshCatalog()
    onDone()
  }

  return (
    <form onSubmit={(event) => void run(event)} className="grid gap-4">
      <DialogHeader>
        <DialogTitle className="break-words">
          {t("apps.join.requestTitle", { app: name })}
        </DialogTitle>
        <DialogDescription>
          {t("apps.join.requestDescription")}
        </DialogDescription>
      </DialogHeader>
      <FormAlert message={formError} />
      <Field data-invalid={tooLong || undefined}>
        <FieldLabel htmlFor={id}>{t("apps.join.message")}</FieldLabel>
        <Textarea
          id={id}
          value={message}
          placeholder={t("apps.join.messagePlaceholder")}
          aria-invalid={tooLong}
          onChange={(event) => setMessage(event.target.value)}
        />
        {tooLong && (
          <FieldError>
            {t("apps.join.messageTooLong", { max: MESSAGE_MAX })}
          </FieldError>
        )}
      </Field>
      <DialogFooter>
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          disabled={busy}
        >
          {t("common.actions.cancel")}
        </Button>
        <Button type="submit" disabled={busy || tooLong}>
          {busy && <Spinner data-icon="inline-start" />}
          {busy ? t("apps.join.sending") : t("apps.join.send")}
        </Button>
      </DialogFooter>
    </form>
  )
}
