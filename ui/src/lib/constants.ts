import type { Priority } from "./types"

/**
 * Semantic token names used by the priority badge. These map to OKLCH values
 * defined in `ui/styles/globals.css`. Change them there, not here.
 */
export const PRIORITY_TOKEN: Record<Priority, string> = {
  emergency: "priority-emergency",
  alert: "priority-alert",
  critical: "priority-critical",
  error: "priority-error",
  warning: "priority-warning",
  notice: "priority-notice",
  informational: "priority-info",
  debug: "priority-debug",
}

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
