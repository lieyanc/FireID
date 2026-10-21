import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { CheckIcon, SearchIcon } from "lucide-react"

import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from "@/components/ui/field"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
} from "@/components/ui/input-group"
import { Spinner } from "@/components/ui/spinner"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import { errorMessage } from "@/lib/errors"
import { useMe } from "@/lib/queries"
import type { User } from "@/lib/types"
import { displayName, initials } from "@/lib/user"
import { cn } from "@/lib/utils"

const DEBOUNCE_MS = 300

function useDebounced<T>(value: T, delay: number) {
  const [debounced, setDebounced] = React.useState(value)
  React.useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(id)
  }, [value, delay])
  return debounced
}

/** One person, with avatar, name and login. */
export function UserRow({ user }: { user: User }) {
  return (
    <div className="flex min-w-0 items-center gap-3">
      <Avatar>
        <AvatarFallback className="text-xs font-medium">
          {initials(user)}
        </AvatarFallback>
      </Avatar>
      <div className="grid min-w-0 text-sm leading-tight">
        <span className="truncate font-medium">{displayName(user)}</span>
        <span className="truncate text-xs text-muted-foreground">
          {user.email ? `${user.username} · ${user.email}` : user.username}
        </span>
      </div>
    </div>
  )
}

/**
 * Debounced user search. Super admins get a prefix search; anyone else must
 * type an exact username or email (the server answers at most that account),
 * and the hint says so. Picking a result calls `onPick`; results whose ID is
 * in `selectedIds` are marked.
 */
export function UserSearch({
  onPick,
  selectedIds,
  autoFocus,
}: {
  onPick: (user: User) => void
  selectedIds?: ReadonlySet<number>
  autoFocus?: boolean
}) {
  const { t } = useI18n()
  const { data: me } = useMe()
  const superAdmin = !!me?.permissions.superAdmin
  const inputId = React.useId()
  const hintId = React.useId()
  const resultsId = React.useId()
  const [query, setQuery] = React.useState("")
  const q = useDebounced(query.trim(), DEBOUNCE_MS)

  const search = useQuery({
    queryKey: ["admin", "users", "search", q],
    queryFn: ({ signal }) => api.admin.searchUsers(q, signal),
    enabled: q !== "",
    staleTime: 30_000,
  })
  const users = q ? (search.data?.users ?? []) : []
  const settling = query.trim() !== q || (q !== "" && search.isFetching)

  return (
    <Field data-invalid={search.isError || undefined}>
      <FieldLabel htmlFor={inputId}>{t("admin.userSearch.label")}</FieldLabel>
      <InputGroup>
        <InputGroupAddon>
          <SearchIcon />
        </InputGroupAddon>
        <InputGroupInput
          id={inputId}
          type="search"
          autoFocus={autoFocus}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          placeholder={
            superAdmin
              ? t("admin.userSearch.placeholderPrefix")
              : t("admin.userSearch.placeholderExact")
          }
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-describedby={hintId}
          aria-controls={resultsId}
        />
        {settling && (
          <InputGroupAddon align="inline-end">
            <Spinner />
          </InputGroupAddon>
        )}
      </InputGroup>
      <FieldDescription id={hintId}>
        {superAdmin
          ? t("admin.userSearch.hintPrefix")
          : t("admin.userSearch.hintExact")}
      </FieldDescription>
      {search.isError && (
        <FieldError>{errorMessage(search.error, t)}</FieldError>
      )}
      <div id={resultsId} aria-live="polite">
        {q && !settling && !search.isError && users.length === 0 && (
          <p className="text-sm text-muted-foreground">
            {t("admin.userSearch.noResults")}
          </p>
        )}
        {users.length > 0 && (
          <ul
            aria-label={t("admin.userSearch.results")}
            className="flex max-h-64 flex-col divide-y overflow-y-auto rounded-lg border"
          >
            {users.map((user) => {
              const selected = selectedIds?.has(user.id) ?? false
              return (
                <li key={user.id}>
                  <button
                    type="button"
                    onClick={() => onPick(user)}
                    aria-pressed={selectedIds ? selected : undefined}
                    className={cn(
                      "flex w-full items-center gap-3 p-2.5 text-left outline-none hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:ring-inset",
                      selected && "bg-primary/5"
                    )}
                  >
                    <UserRow user={user} />
                    {selected && (
                      <CheckIcon
                        aria-hidden
                        className="ml-auto size-4 shrink-0 text-primary"
                      />
                    )}
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </Field>
  )
}
