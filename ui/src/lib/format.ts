import { formatDistanceStrict } from "date-fns"

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}

// Server and browser clocks drift by seconds; an instant that close reads as now, not as the future.
const CLOCK_SKEW_MS = 60_000
// Under this, "0 seconds ago" or "3 seconds ago" reads worse than "just now".
const JUST_NOW_MS = 5_000

export function formatTimeAgo(input: string | Date | number, now: number | Date = Date.now()): string {
  const date = new Date(input)
  if (Number.isNaN(date.getTime())) return "-"
  const ahead = date.getTime() - new Date(now).getTime()
  if (ahead > 0 && ahead < CLOCK_SKEW_MS) return "just now"
  if (ahead <= 0 && ahead > -JUST_NOW_MS) return "just now"
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

const DURATION_UNITS: Record<string, number> = {
  h: 3_600_000_000_000,
  m: 60_000_000_000,
  s: 1_000_000_000,
  ms: 1_000_000,
  us: 1_000,
  "µs": 1_000,
  "μs": 1_000,
  ns: 1,
}

const DURATION_PART = /(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)/y

/**
 * Parses a Go duration string ("30s", "1m30s", "1.5s", "0") into nanoseconds, as time.ParseDuration
 * does; null when the text is not a duration.
 */
export function parseGoDuration(text: string): number | null {
  let rest = text.trim()
  let sign = 1
  if (rest.startsWith("-") || rest.startsWith("+")) {
    sign = rest.startsWith("-") ? -1 : 1
    rest = rest.slice(1)
  }
  if (rest === "0") return 0
  if (rest === "") return null
  let total = 0
  DURATION_PART.lastIndex = 0
  while (DURATION_PART.lastIndex < rest.length) {
    const match = DURATION_PART.exec(rest)
    if (!match) return null
    total += Number(match[1]) * DURATION_UNITS[match[2]!]!
  }
  return sign * total
}

/** Clock time of an instant: seconds for today, with the day otherwise. */
export function formatClock(input: string | Date | number, now: number | Date = Date.now()): string {
  const date = new Date(input)
  if (Number.isNaN(date.getTime())) return "-"
  const today = new Date(now).toDateString() === date.toDateString()
  const time = date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })
  return today ? time : `${date.toLocaleDateString(undefined, { day: "2-digit", month: "short" })} ${time}`
}

export function truncate(s: string, max: number): string {
  if (s.length <= max) return s
  return `${s.slice(0, max - 1)}…`
}
