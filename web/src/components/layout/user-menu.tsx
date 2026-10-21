import { useNavigate } from "react-router"
import { useQueryClient } from "@tanstack/react-query"
import { LogOutIcon } from "lucide-react"
import { toast } from "sonner"

import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { toastError } from "@/lib/errors"
import type { User } from "@/lib/types"
import { useVersion } from "@/lib/queries"
import { signedOut } from "@/lib/session"
import { displayName, initials } from "@/lib/user"

/** Account menu in the header. */
export function UserMenu({ user }: { user: User }) {
  const { t } = useI18n()
  const version = useVersion()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const signOut = async () => {
    try {
      await api.auth.logout()
    } catch (error) {
      toastError(error, t)
      return
    }
    await queryClient.cancelQueries()
    signedOut()
    toast.success(t("shell.user.signedOut"))
    navigate("/sign-in", { replace: true })
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="rounded-full"
          aria-label={t("shell.user.menu")}
        >
          <Avatar>
            <AvatarFallback className="text-xs font-medium">
              {initials(user)}
            </AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-56">
        <DropdownMenuLabel className="font-normal">
          <div className="grid text-sm leading-tight">
            <span className="truncate font-medium">{displayName(user)}</span>
            <span className="truncate text-xs text-muted-foreground">
              {user.email || user.username}
            </span>
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuGroup>
          <DropdownMenuItem
            variant="destructive"
            onSelect={() => void signOut()}
          >
            <LogOutIcon />
            {t("shell.user.signOut")}
          </DropdownMenuItem>
        </DropdownMenuGroup>
        {version.data && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuLabel className="font-mono text-xs font-normal text-muted-foreground">
              {t("common.appName")} {version.data.version}
            </DropdownMenuLabel>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
