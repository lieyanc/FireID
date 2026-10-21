import { Link, NavLink } from "react-router"

import { Brand } from "@/components/layout/brand"
import { Preferences } from "@/components/layout/preferences"
import { UserMenu } from "@/components/layout/user-menu"
import { cn } from "@/lib/utils"
import { useI18n } from "@/i18n"
import { useMe } from "@/lib/queries"
import type { User } from "@/lib/types"

/** Admin destinations in the header; hidden when the person has no access. */
function AppNav() {
  const { t } = useI18n()
  const { data: me } = useMe()
  const items = [
    {
      to: "/apps",
      label: t("admin.navigation.applications"),
      show: !!me?.permissions.manageApps,
    },
    {
      to: "/groups",
      label: t("admin.navigation.groups"),
      show: !!me?.permissions.superAdmin,
    },
  ].filter((item) => item.show)

  if (items.length === 0) return null
  return (
    <nav aria-label={t("shell.adminNav")} className="flex items-center gap-1">
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          className={({ isActive }) =>
            cn(
              "rounded-lg px-2.5 py-1.5 text-sm outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50",
              isActive ? "font-medium text-foreground" : "text-muted-foreground"
            )
          }
        >
          {item.label}
        </NavLink>
      ))}
    </nav>
  )
}

/** Header and centered content column for signed-in pages. */
export function AppLayout({
  user,
  children,
}: {
  user: User
  children: React.ReactNode
}) {
  return (
    <div className="flex min-h-svh flex-col bg-muted/40">
      <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <div className="mx-auto flex h-14 w-full max-w-4xl items-center gap-2 px-4">
          <Link
            to="/"
            className="rounded-lg outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
          >
            <Brand />
          </Link>
          <div className="ml-4 hidden sm:block">
            <AppNav />
          </div>
          <div className="ml-auto flex items-center gap-1">
            <Preferences />
            <UserMenu user={user} />
          </div>
        </div>
      </header>
      <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-6 px-4 py-6 md:py-8">
        {children}
      </main>
    </div>
  )
}
