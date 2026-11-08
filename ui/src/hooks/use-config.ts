import { useQuery } from "@tanstack/react-query"

import { api } from "@/lib/api-client"
import type { MaskedConfig, VersionInfo } from "@/lib/types"

export const CONFIG_QUERY_KEY = ["config"] as const
export const VERSION_QUERY_KEY = ["version"] as const

// The running configuration and the build do not change while the process runs.
const STATIC = { staleTime: Infinity, gcTime: Infinity, refetchInterval: false, refetchOnWindowFocus: false } as const

export function useConfig() {
  return useQuery<MaskedConfig>({
    queryKey: CONFIG_QUERY_KEY,
    queryFn: ({ signal }) => api.getConfig(signal),
    ...STATIC,
  })
}

export function useVersion() {
  return useQuery<VersionInfo>({
    queryKey: VERSION_QUERY_KEY,
    queryFn: ({ signal }) => api.getVersion(signal),
    ...STATIC,
  })
}
