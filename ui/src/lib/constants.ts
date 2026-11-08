import type { Priority } from "./types"

export const PRIORITY_LABEL_SHORT: Record<Priority, string> = {
  emergency: "EMRG",
  alert: "ALRT",
  critical: "CRIT",
  error: "ERR",
  warning: "WARN",
  notice: "NTC",
  informational: "INFO",
  debug: "DBG",
}

export type SincePreset = {
  label: string
  value: string
}

export const SINCE_PRESETS: readonly SincePreset[] = [
  { label: "Last 15m", value: "15m" },
  { label: "Last 1h", value: "1h" },
  { label: "Last 6h", value: "6h" },
  { label: "Last 24h", value: "24h" },
  { label: "Last 7d", value: "168h" },
] as const

export const DEFAULT_PAGE_SIZE = 50

export const PAGE_SIZES: readonly number[] = [25, 50, 100, 200, 500] as const
