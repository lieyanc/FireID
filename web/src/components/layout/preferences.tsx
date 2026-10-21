import {
  CheckIcon,
  LanguagesIcon,
  MonitorIcon,
  MoonIcon,
  SunIcon,
} from "lucide-react"

import { useTheme, type Theme } from "@/components/theme-provider"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { LANG_LABELS, LANGS, useI18n, type Lang } from "@/i18n"

export function LanguageSwitcher() {
  const { t, lang, setLang } = useI18n()
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              aria-label={t("shell.language")}
            >
              <LanguagesIcon />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>{t("shell.language")}</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>{t("shell.language")}</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={lang}
          onValueChange={(value) => setLang(value as Lang)}
        >
          {LANGS.map((l) => (
            <DropdownMenuRadioItem key={l} value={l}>
              {LANG_LABELS[l]}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

const THEME_ICONS = { light: SunIcon, dark: MoonIcon, system: MonitorIcon }

export function ThemeToggle() {
  const { t } = useI18n()
  const { theme, resolvedTheme, setTheme } = useTheme()
  const Icon = resolvedTheme === "dark" ? MoonIcon : SunIcon
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              aria-label={t("shell.theme.label")}
            >
              <Icon />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>{t("shell.theme.label")}</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>{t("shell.theme.label")}</DropdownMenuLabel>
        <DropdownMenuGroup>
          {(["light", "dark", "system"] as Theme[]).map((value) => {
            const ItemIcon = THEME_ICONS[value]
            return (
              <DropdownMenuItem key={value} onSelect={() => setTheme(value)}>
                <ItemIcon />
                {t(`shell.theme.${value}`)}
                {theme === value && <CheckIcon className="ml-auto" />}
              </DropdownMenuItem>
            )
          })}
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** Language and theme switches, shown on every screen. */
export function Preferences() {
  return (
    <div className="flex items-center gap-1">
      <LanguageSwitcher />
      <ThemeToggle />
    </div>
  )
}
