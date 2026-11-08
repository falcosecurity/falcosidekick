import { formatDistanceStrict } from "date-fns"

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}

export function formatTimeAgo(input: string | Date | number, now: number | Date = Date.now()): string {
  const date = new Date(input)
  if (Number.isNaN(date.getTime())) return "-"
  return formatDistanceStrict(date, now, { addSuffix: true })
}

export function formatAbsoluteTime(input: string | Date | number): string {
  const date = new Date(input)
  if (Number.isNaN(date.getTime())) return "-"
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}

export function truncate(s: string, max: number): string {
  if (s.length <= max) return s
  return `${s.slice(0, max - 1)}…`
}
