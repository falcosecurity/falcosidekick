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

import { useRefetchInterval } from "./use-refetch-interval"

export function useSearchEvents(query: SearchQuery) {
  const refetchInterval = useRefetchInterval()
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
