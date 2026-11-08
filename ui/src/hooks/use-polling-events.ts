import { useQuery } from "@tanstack/react-query"
import { useEffect, useState } from "react"

import { api } from "@/lib/api-client"
import type { SearchQuery, SearchResult } from "@/lib/types"
import { useUIStore } from "@/stores/ui-store"

/**
 * Polling stand-in for the deferred 9e WebSocket stream. Same contract the
 * future useEventStream will expose. Honors the global refresh interval from
 * UIStore (0 = off) and pauses while the tab is hidden.
 */
export function usePollingEvents(query: SearchQuery) {
  const refreshIntervalMs = useUIStore((s) => s.refreshIntervalMs)
  const [tabHidden, setTabHidden] = useState(false)

  useEffect(() => {
    function onVisibility() {
      setTabHidden(document.visibilityState === "hidden")
    }
    onVisibility()
    document.addEventListener("visibilitychange", onVisibility)
    return () => document.removeEventListener("visibilitychange", onVisibility)
  }, [])

  return useQuery<SearchResult>({
    queryKey: ["events", "polling", query],
    queryFn: ({ signal }) => api.searchEvents(query, signal),
    refetchInterval: !refreshIntervalMs || tabHidden ? false : refreshIntervalMs,
    refetchIntervalInBackground: false,
  })
}
