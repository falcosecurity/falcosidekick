import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { api } from "@/lib/api-client"
import type { OutputConfigEntry, OutputType, SecretsListing } from "@/lib/types"

// The catalog of output types does not change while the process runs.
export function useOutputTypes() {
  return useQuery<OutputType[]>({
    queryKey: ["pipeline", "output-types"],
    queryFn: ({ signal }) => api.getOutputTypes(signal),
    staleTime: Infinity,
  })
}

/** Names of the files under api.secret_dirs; read again each time a picker opens. */
export function useSecretFiles(enabled: boolean) {
  return useQuery<SecretsListing>({
    queryKey: ["secrets"],
    queryFn: ({ signal }) => api.getSecrets(signal),
    enabled,
    staleTime: 0,
  })
}

/** The stored output, read fresh before an edit so the version matches what is stored. */
export function useStoredOutput(name: string | null) {
  return useQuery<OutputConfigEntry | null>({
    queryKey: ["pipeline", "output", name],
    queryFn: ({ signal }) => api.getOutput(name!, signal),
    enabled: name !== null,
    staleTime: 0,
  })
}

export function useSaveOutput() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ name, version, config }: { name: string; version: number; config: Record<string, unknown> }) =>
      api.putOutput(name, version, config),
    onSettled: () => client.invalidateQueries({ queryKey: ["pipeline"] }),
  })
}

export function useDeleteOutput() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ name, version }: { name: string; version: number }) => api.deleteOutput(name, version),
    onSettled: () => client.invalidateQueries({ queryKey: ["pipeline"] }),
  })
}
