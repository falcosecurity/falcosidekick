import { useQuery } from "@tanstack/react-query"
import { useEffect } from "react"

import { api } from "@/lib/api-client"
import type { OutputStatus, PipelineComposite } from "@/lib/types"
import { usePipelineStore } from "@/stores/pipeline-store"
import { useUIStore } from "@/stores/ui-store"

export function usePipelineComposite() {
  const setComposite = usePipelineStore((s) => s.setComposite)
  const refreshIntervalMs = useUIStore((s) => s.refreshIntervalMs)

  const query = useQuery<PipelineComposite>({
    queryKey: ["pipeline", "composite"],
    queryFn: ({ signal }) => api.getPipeline(signal),
    refetchInterval: refreshIntervalMs > 0 ? refreshIntervalMs : false,
  })

  useEffect(() => {
    setComposite(query.data ?? null)
  }, [query.data, setComposite])

  return query
}

export function usePipelineStatus() {
  const setStatus = usePipelineStore((s) => s.setStatus)
  const refreshIntervalMs = useUIStore((s) => s.refreshIntervalMs)

  const query = useQuery<OutputStatus[]>({
    queryKey: ["pipeline", "status"],
    queryFn: ({ signal }) => api.getPipelineStatus(signal),
    refetchInterval: refreshIntervalMs > 0 ? refreshIntervalMs : false,
  })

  useEffect(() => {
    if (query.data) setStatus(query.data)
  }, [query.data, setStatus])

  return query
}
