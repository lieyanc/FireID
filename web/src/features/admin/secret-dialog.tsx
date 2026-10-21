import * as React from "react"
import { TriangleAlertIcon } from "lucide-react"

import { CopyButton } from "@/components/common/copy-button"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { useI18n } from "@/i18n"

/**
 * Shows a client secret once. The secret lives only in the caller's component
 * state, never in the query cache or storage; closing the dialog should drop
 * it. The person confirms they stored it before the dialog lets them go.
 */
export function SecretDialog({
  secret,
  clientId,
  onClose,
}: {
  secret: string | null
  clientId?: string
  onClose: () => void
}) {
  const { t } = useI18n()
  const checkboxId = React.useId()
  const secretId = React.useId()
  const clientIdLabel = React.useId()

  // A new secret needs a new confirmation: reset while rendering.
  const [confirmation, setConfirmation] = React.useState({
    secret,
    saved: false,
  })
  if (confirmation.secret !== secret) {
    setConfirmation({ secret, saved: false })
  }
  const saved = confirmation.saved
  const setSaved = (value: boolean) => setConfirmation({ secret, saved: value })

  return (
    <Dialog
      open={secret !== null}
      onOpenChange={(open) => {
        if (!open && saved) onClose()
      }}
    >
      <DialogContent
        closeLabel={t("common.actions.close")}
        showCloseButton={false}
        onEscapeKeyDown={(e) => {
          if (!saved) e.preventDefault()
        }}
        onPointerDownOutside={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{t("admin.secret.title")}</DialogTitle>
          <DialogDescription>{t("admin.secret.description")}</DialogDescription>
        </DialogHeader>
        <FieldGroup>
          <Alert>
            <TriangleAlertIcon className="text-warning" />
            <AlertDescription>{t("admin.secret.warning")}</AlertDescription>
          </Alert>
          {clientId && (
            <Field>
              <FieldLabel id={clientIdLabel}>
                {t("admin.detail.clientId")}
              </FieldLabel>
              <div className="flex items-center gap-2">
                <code
                  aria-labelledby={clientIdLabel}
                  className="min-w-0 flex-1 rounded-lg border bg-muted/50 px-2.5 py-1.5 font-mono text-xs break-all"
                >
                  {clientId}
                </code>
                <CopyButton value={clientId} />
              </div>
            </Field>
          )}
          <Field>
            <FieldLabel id={secretId}>
              {t("admin.detail.clientSecret")}
            </FieldLabel>
            <div className="flex items-center gap-2">
              <code
                aria-labelledby={secretId}
                className="min-w-0 flex-1 rounded-lg border bg-muted/50 px-2.5 py-1.5 font-mono text-xs break-all select-all"
              >
                {secret}
              </code>
              {secret && (
                <CopyButton value={secret} label={t("admin.secret.copy")} />
              )}
            </div>
          </Field>
          <Field orientation="horizontal">
            <Checkbox
              id={checkboxId}
              checked={saved}
              onCheckedChange={(value) => setSaved(value === true)}
            />
            <FieldLabel htmlFor={checkboxId} className="font-normal">
              {t("admin.secret.saved")}
            </FieldLabel>
          </Field>
        </FieldGroup>
        <DialogFooter>
          <Button type="button" disabled={!saved} onClick={onClose}>
            {t("admin.secret.done")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
