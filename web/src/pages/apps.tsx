import { useQuery } from "@tanstack/react-query"
import { AppWindowIcon, ClockIcon, ExternalLinkIcon } from "lucide-react"

import { PageSpinner, QueryError } from "@/components/common/query-state"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { AppLogo } from "@/features/apps/app-logo"
import { JoinButton, RequestAccessButton } from "@/features/apps/join-actions"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { qk } from "@/lib/queries"
import type { CatalogApp } from "@/lib/types"
import { httpUrl } from "@/lib/utils"

/** The signed-in person's applications: open, join or ask for each. */
export default function CatalogPage() {
  const { t } = useI18n()
  const query = useQuery({
    queryKey: qk.catalog,
    queryFn: async () => (await api.catalog.apps()).apps,
  })

  return (
    <>
      <div className="grid gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("apps.catalog.title")}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t("apps.catalog.description")}
        </p>
      </div>
      {query.isPending ? (
        <PageSpinner />
      ) : query.isError ? (
        <QueryError error={query.error} onRetry={() => void query.refetch()} />
      ) : query.data.length === 0 ? (
        <Empty className="border bg-card">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <AppWindowIcon />
            </EmptyMedia>
            <EmptyTitle>{t("apps.catalog.empty")}</EmptyTitle>
            <EmptyDescription>{t("apps.catalog.emptyHint")}</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {query.data.map((app) => (
            <CatalogCard key={app.slug} app={app} />
          ))}
        </div>
      )}
    </>
  )
}

function CatalogCard({ app }: { app: CatalogApp }) {
  const { t } = useI18n()
  const homepage = httpUrl(app.homepageUrl)
  return (
    <Card>
      <CardHeader className="flex flex-row items-start gap-3">
        <AppLogo url={app.logoUrl} />
        <div className="grid min-w-0 gap-1">
          <CardTitle className="break-words">{app.name}</CardTitle>
          {app.description && (
            <CardDescription className="line-clamp-3 break-words whitespace-pre-line">
              {app.description}
            </CardDescription>
          )}
        </div>
      </CardHeader>
      <CardFooter className="mt-auto">
        {app.state === "allowed" ? (
          homepage && (
            <Button variant="outline" asChild>
              <a
                href={homepage}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={t("apps.catalog.openLabel", { app: app.name })}
              >
                <ExternalLinkIcon data-icon="inline-start" />
                {t("apps.catalog.open")}
              </a>
            </Button>
          )
        ) : app.state === "pending" ? (
          <Badge variant="warning">
            <ClockIcon data-icon="inline-start" />
            {t("apps.catalog.pending")}
          </Badge>
        ) : app.join === "join" ? (
          <JoinButton slug={app.slug} name={app.name} />
        ) : app.join === "request" ? (
          <RequestAccessButton slug={app.slug} name={app.name} />
        ) : null}
      </CardFooter>
    </Card>
  )
}
