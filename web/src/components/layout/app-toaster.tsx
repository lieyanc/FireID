import { Toaster } from "@/components/ui/sonner"
import { useI18n } from "@/i18n"

/** The toast region, with its accessible labels in the active language. */
export function AppToaster() {
  const { t } = useI18n()
  return (
    <Toaster
      richColors
      closeButton
      position="top-right"
      containerAriaLabel={t("shell.notifications")}
      toastOptions={{ closeButtonAriaLabel: t("common.actions.close") }}
    />
  )
}
