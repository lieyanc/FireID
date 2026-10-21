import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { CircleAlertIcon, LogOutIcon, MonitorIcon } from "lucide-react"
import { toast } from "sonner"

import { QueryError } from "@/components/common/query-state"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
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
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode, toastError } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { AccountSession } from "@/lib/types"

const AMR_LABELS: Record<string, MessageKey> = {
  pwd: "account.session.amr.pwd",
  otp: "account.session.amr.otp",
  email: "account.session.amr.email",
  webauthn: "account.session.amr.webauthn",
}

function refreshSessions() {
  return queryClient.invalidateQueries({ queryKey: qk.sessions })
}

function amrList(amr: AccountSession["amr"]) {
  if (Array.isArray(amr)) return amr
  return amr ? amr.split(/\s+/).filter(Boolean) : []
}

/** "Firefox on macOS" from a user agent; good enough to recognise a device. */
function describeAgent(ua: string) {
  if (!ua) return ""
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /OPR\/|Opera/.test(ua)
      ? "Opera"
      : /Firefox\//.test(ua)
        ? "Firefox"
        : /Chrome\//.test(ua)
          ? "Chrome"
          : /Safari\//.test(ua)
            ? "Safari"
            : ""
  const os = /iPhone|iPad|iPod/.test(ua)
    ? "iOS"
    : /Android/.test(ua)
      ? "Android"
      : /Mac OS X|Macintosh/.test(ua)
        ? "macOS"
        : /Windows/.test(ua)
          ? "Windows"
          : /CrOS/.test(ua)
            ? "ChromeOS"
            : /Linux/.test(ua)
              ? "Linux"
              : ""
  if (browser && os) return `${browser} · ${os}`
  return browser || os || ua
}

export function SessionsCard() {
  const { t } = useI18n()
  const query = useQuery({
    queryKey: qk.sessions,
    queryFn: async () => (await api.account.sessions.list()).sessions ?? [],
  })
  const [confirmOthers, setConfirmOthers] = React.useState(false)
  const [revoking, setRevoking] = React.useState<number | null>(null)

  // Current session first, then the most recently active.
  const sessions = React.useMemo(
    () =>
      [...(query.data ?? [])].sort((a, b) =>
        a.current !== b.current
          ? a.current
            ? -1
            : 1
          : b.lastSeenAt.localeCompare(a.lastSeenAt)
      ),
    [query.data]
  )
  const others = sessions.filter((s) => !s.current)

  const revoke = async (session: AccountSession) => {
    setRevoking(session.id)
    try {
      await api.account.sessions.revoke(session.id)
      toast.success(t("sessions.revoked"))
    } catch (error) {
      // Already ended elsewhere: the list refresh below shows that.
      if (!hasCode(error, "not_found")) toastError(error, t)
    } finally {
      setRevoking(null)
      void refreshSessions()
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("sessions.title")}</CardTitle>
        <CardDescription>{t("sessions.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        {query.isPending ? (
          <div className="flex justify-center py-4">
            <Spinner className="size-5 text-muted-foreground" />
          </div>
        ) : query.isError ? (
          <QueryError
            error={query.error}
            onRetry={() => void query.refetch()}
          />
        ) : (
          <ul className="flex flex-col divide-y rounded-lg border">
            {sessions.map((session) => (
              <SessionRow
                key={session.id}
                session={session}
                busy={revoking === session.id}
                disabled={revoking !== null}
                onRevoke={() => void revoke(session)}
              />
            ))}
            {others.length === 0 && (
              <li className="p-3 text-sm text-muted-foreground">
                {t("sessions.empty")}
              </li>
            )}
          </ul>
        )}
      </CardContent>
      {others.length > 0 && (
        <CardFooter>
          <Button
            variant="outline"
            disabled={revoking !== null}
            onClick={() => setConfirmOthers(true)}
          >
            <LogOutIcon data-icon="inline-start" />
            {t("sessions.revokeOthers")}
          </Button>
        </CardFooter>
      )}

      <Dialog open={confirmOthers} onOpenChange={setConfirmOthers}>
        <DialogContent closeLabel={t("common.actions.close")}>
          {confirmOthers && (
            <RevokeOthersFlow
              sessions={others}
              onDone={() => setConfirmOthers(false)}
            />
          )}
        </DialogContent>
      </Dialog>
    </Card>
  )
}

function SessionRow({
  session,
  busy,
  disabled,
  onRevoke,
}: {
  session: AccountSession
  busy: boolean
  disabled: boolean
  onRevoke: () => void
}) {
  const { t, fmt } = useI18n()
  const device = describeAgent(session.userAgent) || t("sessions.unknownDevice")
  const amr = amrList(session.amr)
  return (
    <li className="flex items-start gap-3 p-3">
      <MonitorIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      <div className="grid min-w-0 flex-1 gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className="truncate text-sm font-medium"
            title={session.userAgent || undefined}
          >
            {device}
          </span>
          {session.current && (
            <Badge variant="success">{t("sessions.thisDevice")}</Badge>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          <span className="font-mono">
            {session.ip || t("sessions.unknownIp")}
          </span>
          {" · "}
          <span title={fmt.dateTime(session.lastSeenAt)}>
            {t("sessions.lastActive", {
              date: fmt.relative(session.lastSeenAt),
            })}
          </span>
          {" · "}
          <span title={fmt.dateTime(session.createdAt)}>
            {t("sessions.signedIn", { date: fmt.date(session.createdAt) })}
          </span>
        </p>
        {amr.length > 0 && (
          <span className="flex flex-wrap gap-1.5">
            {amr.map((m) => (
              <Badge key={m} variant="outline">
                {AMR_LABELS[m] ? t(AMR_LABELS[m]) : m}
              </Badge>
            ))}
          </span>
        )}
      </div>
      {!session.current && (
        <Button
          variant="outline"
          size="sm"
          className="shrink-0"
          disabled={disabled}
          aria-label={t("sessions.revokeLabel", { device })}
          onClick={onRevoke}
        >
          {busy && <Spinner data-icon="inline-start" />}
          {busy ? t("sessions.revoking") : t("sessions.revoke")}
        </Button>
      )}
    </li>
  )
}

/**
 * Signs out every other session one by one: there is no bulk endpoint. A
 * session that already ended (404) counts as done.
 */
function RevokeOthersFlow({
  sessions,
  onDone,
}: {
  sessions: AccountSession[]
  onDone: () => void
}) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)
  // Fixed when the dialog opens, so a background refetch does not change the
  // count under the person's eyes.
  const [targets] = React.useState(sessions)

  const run = async () => {
    setBusy(true)
    setFormError(null)
    const results = await Promise.allSettled(
      targets.map((s) => api.account.sessions.revoke(s.id))
    )
    const failures = results.filter(
      (r): r is PromiseRejectedResult =>
        r.status === "rejected" && !hasCode(r.reason, "not_found")
    )
    await refreshSessions()
    setBusy(false)
    if (failures.length === 0) {
      toast.success(t("sessions.revokeOthersDialog.done"))
      onDone()
      return
    }
    const done = targets.length - failures.length
    setFormError(
      done > 0
        ? t("sessions.revokeOthersDialog.partial", {
            done,
            total: targets.length,
          })
        : errorMessage(failures[0].reason, t)
    )
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("sessions.revokeOthersDialog.title")}</DialogTitle>
        <DialogDescription>
          {t("sessions.revokeOthersDialog.description", {
            count: targets.length,
          })}
        </DialogDescription>
      </DialogHeader>
      {formError && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertDescription>{formError}</AlertDescription>
        </Alert>
      )}
      <DialogFooter>
        <Button variant="outline" disabled={busy} onClick={onDone}>
          {t("common.actions.cancel")}
        </Button>
        <Button
          variant="destructive"
          disabled={busy}
          onClick={() => void run()}
        >
          {busy && <Spinner data-icon="inline-start" />}
          {busy
            ? t("sessions.revokeOthersDialog.submitting")
            : t("sessions.revokeOthersDialog.submit")}
        </Button>
      </DialogFooter>
    </>
  )
}
