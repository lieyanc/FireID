import { QueryClient, queryOptions, useQuery } from "@tanstack/react-query"

import { api, isApiError } from "@/lib/api"

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
