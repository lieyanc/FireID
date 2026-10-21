import { FingerprintPatternIcon } from "lucide-react"

import { useI18n } from "@/i18n"

/** The Fire ID wordmark. */
export function Brand() {
  const { t } = useI18n()
  return (
    <span className="flex items-center gap-2 font-semibold">
      <span className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
        <FingerprintPatternIcon className="size-4" />
      </span>
      {t("common.appName")}
    </span>
  )
}
