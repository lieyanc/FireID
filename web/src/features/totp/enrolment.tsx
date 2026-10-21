import { CopyButton } from "@/components/common/copy-button"
import { FieldGroup, FieldSeparator } from "@/components/ui/field"
import { SecondFactorForm } from "@/features/totp/second-factor-form"
import { QrCode } from "@/features/totp/qr-code"
import { useI18n } from "@/i18n"
import type { TotpEnrolment as Enrolment } from "@/lib/types"

/** Groups a base32 secret in fours so it is easier to type. */
function groupSecret(secret: string) {
  return secret.replace(/(.{4})(?=.)/g, "$1 ")
}

/**
 * Links an authenticator app: QR code, the same key for manual entry, then
 * the first code from the app.
 */
export function TotpEnrolment({
  enrolment,
  onSubmit,
  submitLabel,
  submittingLabel,
  showScanHint = true,
  children,
}: {
  enrolment: Enrolment
  /** Off when the surrounding dialog already says it. */
  showScanHint?: boolean
  onSubmit: (code: string) => Promise<void>
  submitLabel: string
  submittingLabel: string
  children?: React.ReactNode
}) {
  const { t } = useI18n()
  return (
    <FieldGroup>
      <div className="flex flex-col items-center gap-3 text-center">
        {showScanHint && (
          <p className="text-sm text-muted-foreground">
            {t("totp.enrol.scan")}
          </p>
        )}
        <QrCode
          value={enrolment.uri}
          label={t("totp.enrol.qrLabel")}
          className="size-44 border p-1"
        />
      </div>
      <div className="flex flex-col gap-2">
        <p className="text-sm text-muted-foreground">
          {t("totp.enrol.manual")}
        </p>
        <div className="flex items-center gap-2">
          <code
            aria-label={t("totp.enrol.secret")}
            className="min-w-0 flex-1 rounded-md border bg-muted/50 px-3 py-1.5 font-mono text-sm break-all select-all"
          >
            {groupSecret(enrolment.secret)}
          </code>
          <CopyButton value={enrolment.secret} />
        </div>
      </div>
      <FieldSeparator />
      <SecondFactorForm
        label={t("totp.enrol.code")}
        description={t("totp.enrol.codeHint")}
        submitLabel={submitLabel}
        submittingLabel={submittingLabel}
        onSubmit={onSubmit}
        autoFocus={false}
      >
        {children}
      </SecondFactorForm>
    </FieldGroup>
  )
}
