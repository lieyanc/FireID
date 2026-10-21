import {
  QueryClient,
  queryOptions,
  useInfiniteQuery,
  useQuery,
} from "@tanstack/react-query"

import { api, isApiError } from "@/lib/api"
import type { AuditFilter, AuditPage } from "@/lib/types"

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      refetchOnWindowFocus: true,
      retry: (failureCount, error) => {
        if (isApiError(error) && error.status > 0 && error.status < 500) {
          return false
        }
        return failureCount < 2
      },
    },
    mutations: { retry: false },
  },
})

export const qk = {
  setup: ["setup"] as const,
  me: ["auth", "me"] as const,
  version: ["version"] as const,
  passkeys: ["account", "passkeys"] as const,
  sessions: ["account", "sessions"] as const,
  apps: ["admin", "apps"] as const,
  // Keys under an app's own are invalidated along with it, since TanStack
  // Query matches by prefix.
  app: (slug: string) => ["admin", "apps", slug] as const,
  appMembers: (slug: string) => ["admin", "apps", slug, "members"] as const,
  appGroups: (slug: string) => ["admin", "apps", slug, "groups"] as const,
  accessRequests: (slug: string) =>
    ["admin", "apps", slug, "access-requests"] as const,
  forwardAuth: (slug: string) =>
    ["admin", "apps", slug, "forward-auth"] as const,
  appAudit: (slug: string, filter: AuditFilter) =>
    ["admin", "apps", slug, "audit", filter] as const,
  audit: (filter: AuditFilter) => ["admin", "audit", filter] as const,
  signingKeys: ["admin", "signing-keys"] as const,
  groups: ["admin", "groups"] as const,
  group: (id: number) => ["admin", "groups", id] as const,
  groupMembers: (id: number) => ["admin", "groups", id, "members"] as const,
}

export const setupQuery = queryOptions({
  queryKey: qk.setup,
  queryFn: api.setup.state,
  staleTime: 60_000,
  retry: 1,
})

export function useSetupState() {
  return useQuery(setupQuery)
}

/** The current session, or null when signed out. */
export const meQuery = queryOptions({
  queryKey: qk.me,
  queryFn: async () => {
    try {
      return await api.auth.me()
    } catch (error) {
      if (isApiError(error) && error.code === "unauthenticated") return null
      throw error
    }
  },
  staleTime: 60_000,
  retry: 1,
})

export function useMe() {
  return useQuery(meQuery)
}

export function useVersion() {
  return useQuery({
    queryKey: qk.version,
    queryFn: api.version,
    staleTime: 5 * 60_000,
  })
}

/**
 * Pages of an audit log, newest first. Each page asks for the entries older
 * than the previous page's last one (nextBefore).
 */
export function useAuditLog(
  queryKey: readonly unknown[],
  fetchPage: (before?: number) => Promise<AuditPage>
) {
  return useInfiniteQuery({
    queryKey,
    queryFn: ({ pageParam }) => fetchPage(pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.nextBefore ?? undefined,
  })
}
