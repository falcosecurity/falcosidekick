import { QueryClient } from "@tanstack/react-query"

import { ApiError } from "./api-error"

const MAX_RETRIES = 2

// A 4xx answer or an unavailable backend (503) will not change by asking again.
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= MAX_RETRIES) return false
  if (error instanceof ApiError) {
    return !((error.status >= 400 && error.status < 500) || error.status === 503)
  }
  return true
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        retry: shouldRetry,
        refetchOnWindowFocus: false,
      },
      mutations: {
        retry: 0,
      },
    },
  })
}
