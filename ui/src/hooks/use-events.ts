import { useQuery } from "@tanstack/react-query"

import { api } from "@/lib/api-client"
import type {
  Event,
  EventFilters,
  HistogramRequest,
  HistogramResult,
  SearchQuery,
  SearchResult,
} from "@/lib/types"
import { useUIStore } from "@/stores/ui-store"

function useGlobalInterval(): number | false {
  const ms = useUIStore((s) => s.refreshIntervalMs)
  return ms > 0 ? ms : false
}

export function useSearchEvents(query: SearchQuery) {
  const refetchInterval = useGlobalInterval()
  return useQuery<SearchResult>({
    queryKey: ["events", "search", query],
    queryFn: ({ signal }) => api.searchEvents(query, signal),
    placeholderData: (prev) => prev,
    refetchInterval,
  })
}

export function useEvent(uuid: string | null) {
  return useQuery<Event | null>({
    queryKey: ["events", "by-uuid", uuid],
    queryFn: ({ signal }) => (uuid ? api.getEvent(uuid, signal) : Promise.resolve(null)),
    enabled: !!uuid,
  })
}

export function useEventsCount(filters: EventFilters) {
  const refetchInterval = useGlobalInterval()
  return useQuery<number>({
    queryKey: ["events", "count", filters],
    queryFn: ({ signal }) => api.countEvents(filters, signal),
    refetchInterval,
  })
}

export function useEventsCountBy(
  groupby: "priority" | "rule" | "source" | "tags" | "hostname",
  filters: EventFilters,
) {
  const refetchInterval = useGlobalInterval()
  return useQuery<Record<string, number>>({
    queryKey: ["events", "count-by", groupby, filters],
    queryFn: ({ signal }) => api.countEventsBy(groupby, filters, signal),
    refetchInterval,
  })
}

export function useEventsHistogram(req: HistogramRequest) {
  const refetchInterval = useGlobalInterval()
  return useQuery<HistogramResult>({
    queryKey: ["events", "histogram", req],
    queryFn: ({ signal }) => api.getEventsHistogram(req, signal),
    refetchInterval,
    placeholderData: (prev) => prev,
  })
}
