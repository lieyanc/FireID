import { CircleAlertIcon, RotateCwIcon } from "lucide-react"

import {
  Alert,
  AlertAction,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { useI18n } from "@/i18n"
import { errorMessage } from "@/lib/errors"

/** Inline error for a failed query, with a retry button. */
export function QueryError({
  error,
  onRetry,
  title,
}: {
  error: unknown
  onRetry?: () => void
  title?: string
}) {
  const { t } = useI18n()
  return (
    <Alert variant="destructive">
      <CircleAlertIcon />
      <AlertTitle>{title ?? t("common.errors.loadFailed")}</AlertTitle>
      <AlertDescription>{errorMessage(error, t)}</AlertDescription>
      {onRetry && (
        <AlertAction>
          <Button variant="outline" size="sm" onClick={onRetry}>
            <RotateCwIcon data-icon="inline-start" />
            {t("common.actions.retry")}
          </Button>
        </AlertAction>
      )}
    </Alert>
  )
}

export function FullPageSpinner() {
  return (
    <div className="flex min-h-svh items-center justify-center">
      <Spinner className="size-6 text-muted-foreground" />
    </div>
  )
}

/** Suspense fallback inside the app layout, below the header. */
export function PageSpinner() {
  return (
    <div className="flex flex-1 items-center justify-center py-16">
      <Spinner className="size-6 text-muted-foreground" />
    </div>
  )
}
