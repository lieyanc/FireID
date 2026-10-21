import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { ArchiveXIcon, RefreshCwIcon, TriangleAlertIcon } from "lucide-react"
import { toast } from "sonner"

import { QueryError } from "@/components/common/query-state"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
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
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage, hasCode } from "@/lib/errors"
import { qk, queryClient } from "@/lib/queries"
import type { SigningKey } from "@/lib/types"

function refreshKeys() {
  // A rotation or retirement is audited as well.
  void queryClient.invalidateQueries({ queryKey: ["admin", "audit"] })
  return queryClient.invalidateQueries({ queryKey: qk.signingKeys })
}

type Action = { kind: "rotate" } | { kind: "retire"; key: SigningKey }

/**
 * The OIDC signing keys (super admin): rotate to a new current key, retire
 * old ones once no valid token needs them.
 */
export function SigningKeys() {
  const { t, fmt } = useI18n()
  const query = useQuery({
    queryKey: qk.signingKeys,
    queryFn: async () => (await api.admin.signingKeys()).keys ?? [],
  })
  const [action, setAction] = React.useState<Action | null>(null)
  const close = () => setAction(null)
  const current = query.data?.find((key) => key.current)

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.keys.listTitle")}</CardTitle>
        <CardDescription>{t("admin.keys.listDescription")}</CardDescription>
        <CardAction>
          <Button
            disabled={!query.isSuccess}
            onClick={() => setAction({ kind: "rotate" })}
          >
            <RefreshCwIcon data-icon="inline-start" />
            {t("admin.keys.rotate")}
          </Button>
        </CardAction>
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
        ) : query.data.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t("admin.keys.empty")}
          </p>
        ) : (
          <ul className="flex flex-col divide-y rounded-lg border">
            {query.data.map((key) => (
              <li
                key={key.kid}
                className="flex flex-wrap items-center gap-3 p-3"
              >
                <div className="grid min-w-0 flex-1 gap-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <code className="min-w-0 font-mono text-xs break-all">
                      {key.kid}
                    </code>
                    <Badge variant="outline">{key.alg}</Badge>
                    {key.current && (
                      <Badge variant="success">{t("admin.keys.current")}</Badge>
                    )}
                    {key.retiredAt && (
                      <Badge variant="secondary">
                        {t("admin.keys.retired")}
                      </Badge>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-muted-foreground">
                    <span>
                      {t("admin.keys.createdAt", {
                        date: fmt.dateTime(key.createdAt),
                      })}
                    </span>
                    {key.activatedAt && (
                      <span>
                        {t("admin.keys.activatedAt", {
                          date: fmt.dateTime(key.activatedAt),
                        })}
                      </span>
                    )}
                    {key.retiredAt && (
                      <span>
                        {t("admin.keys.retiredAt", {
                          date: fmt.dateTime(key.retiredAt),
                        })}
                      </span>
                    )}
                  </div>
                </div>
                {!key.current && !key.retiredAt && (
                  <Button
                    variant="outline"
                    size="sm"
                    aria-label={t("admin.keys.retireLabel", { kid: key.kid })}
                    onClick={() => setAction({ kind: "retire", key })}
                  >
                    <ArchiveXIcon data-icon="inline-start" />
                    {t("admin.keys.retire")}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <Dialog
        open={action !== null}
        onOpenChange={(open) => {
          if (!open) close()
        }}
      >
        <DialogContent closeLabel={t("common.actions.close")}>
          {action?.kind === "rotate" && <RotateFlow onDone={close} />}
          {action?.kind === "retire" && (
            <RetireFlow
              signingKey={action.key}
              current={current}
              onDone={close}
            />
          )}
        </DialogContent>
      </Dialog>
    </Card>
  )
}

function RotateFlow({ onDone }: { onDone: () => void }) {
  const { t } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setFormError(null)
    let rotated: { kid: string }
    try {
      rotated = await api.admin.rotateSigningKey()
    } catch (error) {
      setBusy(false)
      setFormError(errorMessage(error, t))
      return
    }
    await refreshKeys()
    toast.success(t("admin.keys.rotated"), { description: rotated.kid })
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("admin.keys.rotateTitle")}</DialogTitle>
        <DialogDescription>
          {t("admin.keys.rotateDescription")}
        </DialogDescription>
      </DialogHeader>
      <FormAlert message={formError} />
      <DialogFooter>
        <Button variant="outline" onClick={onDone} disabled={busy}>
          {t("common.actions.cancel")}
        </Button>
        <Button onClick={() => void run()} disabled={busy}>
          {busy && <Spinner data-icon="inline-start" />}
          {busy ? t("admin.keys.rotating") : t("admin.keys.rotateConfirm")}
        </Button>
      </DialogFooter>
    </>
  )
}

function RetireFlow({
  signingKey,
  current,
  onDone,
}: {
  signingKey: SigningKey
  current: SigningKey | undefined
  onDone: () => void
}) {
  const { t, fmt } = useI18n()
  const [busy, setBusy] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setFormError(null)
    try {
      await api.admin.retireSigningKey(signingKey.kid)
    } catch (error) {
      // Gone already: the list is stale, refreshing it is the answer.
      if (!hasCode(error, "not_found")) {
        setBusy(false)
        setFormError(errorMessage(error, t))
        return
      }
    }
    await refreshKeys()
    toast.success(t("admin.keys.retiredToast"))
    onDone()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>{t("admin.keys.retireTitle")}</DialogTitle>
        <DialogDescription>
          {t("admin.keys.retireDescription", { kid: signingKey.kid })}
        </DialogDescription>
      </DialogHeader>
      <Alert variant="destructive">
        <TriangleAlertIcon />
        <AlertTitle>{t("admin.keys.retireWarningTitle")}</AlertTitle>
        <AlertDescription>
          <p>{t("admin.keys.retireWarning")}</p>
          {current?.activatedAt && (
            <p>
              {t("admin.keys.currentSince", {
                date: fmt.dateTime(current.activatedAt),
                relative: fmt.relative(current.activatedAt),
              })}
            </p>
          )}
        </AlertDescription>
      </Alert>
      <FormAlert message={formError} />
      <DialogFooter>
        <Button variant="outline" onClick={onDone} disabled={busy}>
          {t("common.actions.cancel")}
        </Button>
        <Button
          variant="destructive"
          onClick={() => void run()}
          disabled={busy}
        >
          {busy && <Spinner data-icon="inline-start" />}
          {busy ? t("admin.keys.retiring") : t("admin.keys.retireConfirm")}
        </Button>
      </DialogFooter>
    </>
  )
}
