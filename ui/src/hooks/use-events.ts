import { useQuery } from "@tanstack/react-query"

import { api } from "@/lib/api-client"
import type {
  Event,
  EventFilters,
  GroupBy,
  HistogramRequest,
  HistogramResult,
  SearchQuery,
  SearchResult,
} from "@/lib/types"

import { useUIStore } from "@/stores/ui-store"

import { useRefetchInterval } from "./use-refetch-interval"

// The event list refreshes on its own only when the page is set live: otherwise rows must not move
// while someone reads or selects them, and it changes with the query or on Refresh.
export function useSearchEvents(query: SearchQuery) {
  const interval = useRefetchInterval()
  const live = useUIStore((s) => s.eventsLive)
  return useQuery<SearchResult>({
    queryKey: ["events", "search", query],
    queryFn: ({ signal }) => api.searchEvents(query, signal),
    placeholderData: (prev) => prev,
    refetchInterval: live ? interval : false,
    refetchOnWindowFocus: live,
    staleTime: live ? 0 : Infinity,
  })
}

/** The newest stored event, refreshed with the rest of the live views. */
export function useLatestEvent() {
  const refetchInterval = useRefetchInterval()
  return useQuery<Event | null>({
    queryKey: ["events", "latest"],
    queryFn: async ({ signal }) => (await api.searchEvents({ limit: 1, sort_by: "timestamp", sort_desc: true }, signal)).events[0] ?? null,
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
  const refetchInterval = useRefetchInterval()
  return useQuery<number>({
    queryKey: ["events", "count", filters],
    queryFn: ({ signal }) => api.countEvents(filters, signal),
    refetchInterval,
  })
}

export function useEventsCountBy(groupby: GroupBy, filters: EventFilters) {
  const refetchInterval = useRefetchInterval()
  return useQuery<Record<string, number>>({
    queryKey: ["events", "count-by", groupby, filters],
    queryFn: ({ signal }) => api.countEventsBy(groupby, filters, signal),
    refetchInterval,
  })
}

export function useEventsHistogram(req: HistogramRequest) {
  const refetchInterval = useRefetchInterval()
  return useQuery<HistogramResult>({
    queryKey: ["events", "histogram", req],
    queryFn: ({ signal }) => api.getEventsHistogram(req, signal),
    refetchInterval,
    placeholderData: (prev) => prev,
  })
}
