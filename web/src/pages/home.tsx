import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { InfoList } from "@/components/common/info-list"
import { TwoStepCard } from "@/features/account/two-step-card"
import { useI18n, type MessageKey } from "@/i18n"
import { useMe } from "@/lib/queries"
import type { Me, User } from "@/lib/types"
import { displayName, initials } from "@/lib/user"

const AMR_LABELS: Record<string, MessageKey> = {
  pwd: "account.session.amr.pwd",
  otp: "account.session.amr.otp",
  email: "account.session.amr.email",
}

const ACR_LABELS: Record<string, MessageKey> = {
  "loa:1": "account.session.acr.loa:1",
  "loa:2": "account.session.acr.loa:2",
}

/** The level of assurance, whether acr is bare or a URN ("urn:…:loa:2"). */
function acrLabel(acr: string) {
  const match = /(?:^|:)(loa:\d+)$/.exec(acr)
  return match ? ACR_LABELS[match[1]] : undefined
}

export default function HomePage() {
  const { t } = useI18n()
  const { data: me } = useMe()
  // The session gate renders this page only with a session.
  if (!me) return null

  return (
    <>
      <h1 className="text-2xl font-semibold tracking-tight">
        {t("account.title")}
      </h1>
      <ProfileCard user={me.user} />
      <div className="grid gap-6 md:grid-cols-2">
        <SessionCard me={me} />
        <TwoStepCard user={me.user} recoveryCodesLeft={me.recoveryCodesLeft} />
      </div>
    </>
  )
}

function ProfileCard({ user }: { user: User }) {
  const { t, fmt } = useI18n()
  return (
    <Card>
      <CardHeader className="flex flex-row items-center gap-4">
        <Avatar size="lg">
          <AvatarFallback className="font-medium">
            {initials(user)}
          </AvatarFallback>
        </Avatar>
        <div className="grid min-w-0 gap-1">
          <CardTitle className="flex flex-wrap items-center gap-2">
            <span className="truncate">{displayName(user)}</span>
            {user.superAdmin && (
              <Badge variant="secondary">
                {t("account.profile.superAdmin")}
              </Badge>
            )}
          </CardTitle>
          <CardDescription className="truncate">
            @{user.username}
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        <InfoList
          rows={[
            {
              label: t("account.profile.username"),
              value: user.username,
            },
            {
              label: t("account.profile.email"),
              value: user.email ? (
                <span className="inline-flex flex-wrap items-center gap-2">
                  {user.email}
                  <Badge variant={user.emailVerified ? "success" : "warning"}>
                    {user.emailVerified
                      ? t("account.profile.verified")
                      : t("account.profile.unverified")}
                  </Badge>
                </span>
              ) : (
                "–"
              ),
            },
            {
              label: t("account.profile.lastSignIn"),
              value: user.lastLoginAt
                ? fmt.dateTime(user.lastLoginAt)
                : t("common.states.never"),
            },
            {
              label: t("account.profile.memberSince"),
              value: fmt.date(user.createdAt),
            },
          ]}
        />
      </CardContent>
    </Card>
  )
}

function SessionCard({ me }: { me: Me }) {
  const { t, fmt } = useI18n()
  const acr = acrLabel(me.acr)
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("account.session.title")}</CardTitle>
        <CardDescription>{t("account.session.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <InfoList
          rows={[
            {
              label: t("account.session.methods"),
              value: (
                <span className="inline-flex flex-wrap gap-1.5">
                  {me.amr.length
                    ? me.amr.map((m) => (
                        <Badge key={m} variant="outline">
                          {AMR_LABELS[m] ? t(AMR_LABELS[m]) : m}
                        </Badge>
                      ))
                    : "–"}
                </span>
              ),
            },
            {
              label: t("account.session.level"),
              value: acr ? t(acr) : me.acr || "–",
            },
            {
              label: t("account.session.expires"),
              value: (
                <span title={fmt.dateTime(me.expiresAt)}>
                  {fmt.relative(me.expiresAt)}
                </span>
              ),
            },
          ]}
        />
      </CardContent>
    </Card>
  )
}
