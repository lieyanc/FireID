import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { TriangleAlertIcon } from "lucide-react"

import { CopyButton } from "@/components/common/copy-button"
import { InfoList } from "@/components/common/info-list"
import { QueryError } from "@/components/common/query-state"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Spinner } from "@/components/ui/spinner"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { qk } from "@/lib/queries"
import type { App } from "@/lib/types"

/** forwardauth.LogoutPath: ends the session on the protected site. */
const LOGOUT_PATH = "/__fireid/logout"

/** What forward auth tells the app about the person (forwardauth.Forward). */
const HEADERS: { name: string; label: MessageKey }[] = [
  { name: "X-FireID-User", label: "admin.forwardAuth.header.user" },
  { name: "X-FireID-Email", label: "admin.forwardAuth.header.email" },
  { name: "X-FireID-Name", label: "admin.forwardAuth.header.name" },
  { name: "X-FireID-Groups", label: "admin.forwardAuth.header.groups" },
  { name: "X-FireID-Sub", label: "admin.forwardAuth.header.sub" },
]

function Section({
  title,
  titleId,
  action,
  children,
}: {
  title: string
  titleId: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <section aria-labelledby={titleId} className="grid gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id={titleId} className="text-sm font-medium">
          {title}
        </h3>
        {action}
      </div>
      {children}
    </section>
  )
}

/** A read-only nginx snippet; scrolls sideways rather than wrapping. */
function Snippet({
  title,
  copyLabel,
  value,
}: {
  title: string
  copyLabel: string
  value: string
}) {
  const id = React.useId()
  return (
    <Section
      title={title}
      titleId={id}
      action={<CopyButton value={value} label={copyLabel} size="sm" />}
    >
      {/* Focusable so the scrollable region can be scrolled by keyboard. */}
      <pre
        tabIndex={0}
        aria-labelledby={id}
        className="overflow-x-auto rounded-lg border bg-muted/50 p-3 font-mono text-xs leading-5 outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
      >
        <code>{value}</code>
      </pre>
    </Section>
  )
}

/**
 * How to protect a site that has no login of its own with this app, through
 * nginx auth_request: the hosts registered for it and the config to paste.
 */
export function ForwardAuth({ app }: { app: App }) {
  const { t } = useI18n()
  const hostsId = React.useId()
  const headersId = React.useId()
  const signOutId = React.useId()
  const query = useQuery({
    queryKey: qk.forwardAuth(app.slug),
    queryFn: () => api.admin.forwardAuth(app.slug),
  })

  let content: React.ReactNode
  if (query.isPending) {
    content = (
      <div className="flex justify-center py-4">
        <Spinner className="size-5 text-muted-foreground" />
      </div>
    )
  } else if (query.isError) {
    content = (
      <QueryError error={query.error} onRetry={() => void query.refetch()} />
    )
  } else {
    const setup = query.data
    const hosts = setup.hosts ?? []
    content = (
      <div className="grid gap-6">
        <Section title={t("admin.forwardAuth.hosts")} titleId={hostsId}>
          {hosts.length > 0 ? (
            <ul className="flex flex-col divide-y rounded-lg border">
              {hosts.map((host) => (
                <li key={host} className="p-3 font-mono text-xs break-all">
                  {host}
                </li>
              ))}
            </ul>
          ) : (
            <div className="grid gap-1.5 text-sm text-muted-foreground">
              <p>{t("admin.forwardAuth.noHosts")}</p>
              <p>{t("admin.forwardAuth.noHostsHint")}</p>
              <code className="w-fit rounded bg-muted px-1.5 py-0.5 font-mono text-xs break-all text-foreground">
                {`https://<site host>${setup.callbackPath}`}
              </code>
            </div>
          )}
        </Section>
        <Snippet
          title={t("admin.forwardAuth.server")}
          copyLabel={t("admin.forwardAuth.copyServer")}
          value={setup.serverSnippet}
        />
        <Snippet
          title={t("admin.forwardAuth.location")}
          copyLabel={t("admin.forwardAuth.copyLocation")}
          value={setup.locationSnippet}
        />
        <Alert>
          <TriangleAlertIcon />
          <AlertTitle>{t("admin.forwardAuth.warningTitle")}</AlertTitle>
          <AlertDescription>{t("admin.forwardAuth.warning")}</AlertDescription>
        </Alert>
        <Section title={t("admin.forwardAuth.headers")} titleId={headersId}>
          <InfoList
            rows={HEADERS.map((header) => ({
              label: (
                <code className="font-mono text-xs text-foreground">
                  {header.name}
                </code>
              ),
              value: t(header.label),
            }))}
          />
        </Section>
        <Section title={t("admin.forwardAuth.signOut")} titleId={signOutId}>
          <code className="w-fit rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
            {LOGOUT_PATH}
          </code>
          <p className="text-sm text-muted-foreground">
            {t("admin.forwardAuth.signOutHint")}
          </p>
        </Section>
      </div>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("admin.forwardAuth.title")}</CardTitle>
        <CardDescription>{t("admin.forwardAuth.description")}</CardDescription>
      </CardHeader>
      <CardContent>{content}</CardContent>
    </Card>
  )
}
