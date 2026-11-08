import { formatDistanceStrict } from "date-fns"

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}

// Server and browser clocks drift by seconds; an instant that close reads as now, not as the future.
const CLOCK_SKEW_MS = 60_000

export function formatTimeAgo(input: string | Date | number, now: number | Date = Date.now()): string {
  const date = new Date(input)
  if (Number.isNaN(date.getTime())) return "-"
  const ahead = date.getTime() - new Date(now).getTime()
  if (ahead > 0 && ahead < CLOCK_SKEW_MS) return "just now"
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

const DURATION_UNITS: readonly [string, number][] = [
  ["h", 3_600_000_000_000],
  ["m", 60_000_000_000],
  ["s", 1_000_000_000],
  ["ms", 1_000_000],
  ["µs", 1_000],
  ["ns", 1],
]

// formatGoDuration renders a Go time.Duration (integer nanoseconds) the way Go's String does,
// without the trailing zero units: 30000000000 is "30s", 90000000000 is "1m30s".
export function formatGoDuration(ns: number): string {
  if (!Number.isFinite(ns)) return "-"
  if (ns === 0) return "0s"
  let rest = Math.abs(Math.trunc(ns))
  let out = ns < 0 ? "-" : ""
  for (const [unit, size] of DURATION_UNITS) {
    const count = Math.floor(rest / size)
    if (count > 0) {
      out += `${count}${unit}`
      rest -= count * size
    }
  }
  return out
}

export function truncate(s: string, max: number): string {
  if (s.length <= max) return s
  return `${s.slice(0, max - 1)}…`
}
