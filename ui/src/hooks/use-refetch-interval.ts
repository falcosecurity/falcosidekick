import { useUIStore } from "@/stores/ui-store"

export function useRefetchInterval(): number | false {
  const ms = useUIStore((s) => s.refreshIntervalMs)
  return ms > 0 ? ms : false
}
