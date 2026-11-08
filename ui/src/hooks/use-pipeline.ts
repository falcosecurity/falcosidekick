import { useQuery } from "@tanstack/react-query"
import { useEffect } from "react"

import { api } from "@/lib/api-client"
import type { OutputConfigEntry, OutputStatus, PipelineComposite } from "@/lib/types"
import { usePipelineStore } from "@/stores/pipeline-store"

import { useRefetchInterval } from "./use-refetch-interval"

export function usePipelineComposite() {
  const setComposite = usePipelineStore((s) => s.setComposite)
  const refetchInterval = useRefetchInterval()

  const query = useQuery<PipelineComposite>({
    queryKey: ["pipeline", "composite"],
    queryFn: ({ signal }) => api.getPipeline(signal),
    refetchInterval,
  })

  useEffect(() => {
    setComposite(query.data ?? null)
  }, [query.data, setComposite])

  return query
}

export function usePipelineStatus() {
  const setStatus = usePipelineStore((s) => s.setStatus)
  const refetchInterval = useRefetchInterval()

  const query = useQuery<OutputStatus[]>({
    queryKey: ["pipeline", "status"],
    queryFn: ({ signal }) => api.getPipelineStatus(signal),
    refetchInterval,
  })

  useEffect(() => {
    if (query.data) setStatus(query.data)
  }, [query.data, setStatus])

  return query
}

export function useOutputs() {
  const refetchInterval = useRefetchInterval()
  return useQuery<OutputConfigEntry[]>({
    queryKey: ["pipeline", "outputs"],
    queryFn: ({ signal }) => api.getOutputs(signal),
    refetchInterval,
  })
}
