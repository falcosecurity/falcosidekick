import { formatDistanceToNowStrict } from "date-fns"

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}

export function formatDurationMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "-"
  if (ms < 1000) return `${Math.round(ms)}ms`
  const seconds = ms / 1000
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 1)}s`
  const minutes = seconds / 60
  if (minutes < 60) return `${minutes.toFixed(1)}m`
  const hours = minutes / 60
  return `${hours.toFixed(1)}h`
}

export function formatTimeAgo(input: string | Date | number): string {
  try {
    return `${formatDistanceToNowStrict(new Date(input), { addSuffix: true })}`
  } catch {
    return "-"
  }
}

export function formatAbsoluteTime(input: string | Date | number): string {
  try {
    return new Date(input).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    })
  } catch {
    return "-"
  }
}

export function truncate(s: string, max: number): string {
  if (s.length <= max) return s
  return `${s.slice(0, max - 1)}…`
}
