import * as React from "react"
import { DownloadIcon } from "lucide-react"

import { CopyButton } from "@/components/common/copy-button"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { useI18n } from "@/i18n"

function downloadText(name: string, text: string) {
  const url = URL.createObjectURL(
    new Blob([text], { type: "text/plain;charset=utf-8" })
  )
  const a = document.createElement("a")
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/**
 * Shows freshly issued recovery codes. They exist only in this response, so
 * the person must confirm they saved them before moving on.
 */
export function RecoveryCodes({
  codes,
  username,
  onDone,
  doneLabel,
}: {
  codes: string[]
  username: string
  onDone: () => void
  doneLabel?: string
}) {
  const { t, fmt } = useI18n()
  const [saved, setSaved] = React.useState(false)
  const id = React.useId()
  const list = codes.join("\n")

  const download = () => {
    const text = [
      t("totp.recovery.fileHeader", { username }),
      "",
      list,
      "",
      t("totp.recovery.fileNote", { date: fmt.dateTime(new Date()) }),
      "",
    ].join("\n")
    downloadText(`fireid-recovery-codes-${username}.txt`, text)
  }

  return (
    <FieldGroup>
      <ul
        aria-label={t("totp.recoveryCode")}
        className="grid grid-cols-2 gap-x-4 gap-y-1.5 rounded-lg border bg-muted/50 p-4 font-mono text-sm"
      >
        {codes.map((code) => (
          <li key={code} className="text-center tracking-wider">
            {code}
          </li>
        ))}
      </ul>
      <div className="grid grid-cols-2 gap-2">
        <CopyButton
          value={list}
          label={t("totp.recovery.copy")}
          size="default"
        />
        <Button type="button" variant="outline" onClick={download}>
          <DownloadIcon data-icon="inline-start" />
          {t("totp.recovery.download")}
        </Button>
      </div>
      <Field orientation="horizontal">
        <Checkbox
          id={id}
          checked={saved}
          onCheckedChange={(value) => setSaved(value === true)}
        />
        <FieldLabel htmlFor={id} className="font-normal">
          {t("totp.recovery.saved")}
        </FieldLabel>
      </Field>
      <Button type="button" disabled={!saved} onClick={onDone}>
        {doneLabel ?? t("common.actions.continue")}
      </Button>
    </FieldGroup>
  )
}
