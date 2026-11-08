import { describe, expect, test } from "bun:test"

import { formatAbsoluteTime, formatClock, formatGoDuration, formatNumber, formatTimeAgo, truncate } from "./format"

describe("formatGoDuration", () => {
  test.each([
    [0, "0s"],
    [30_000_000_000, "30s"],
    [90_000_000_000, "1m30s"],
    [3_600_000_000_000, "1h"],
    [5_400_000_000_000, "1h30m"],
    [1_500_000_000, "1s500ms"],
    [250_000, "250µs"],
    [-2_000_000_000, "-2s"],
    [Number.NaN, "-"],
  ])("%d ns is %s", (ns, text) => {
    expect(formatGoDuration(ns)).toBe(text)
  })
})

describe("formatNumber", () => {
  test("formats thousands using locale grouping", () => {
    expect(formatNumber(12_345)).toMatch(/12.345/)
  })

  test("formats zero", () => {
    expect(formatNumber(0)).toBe("0")
  })
})

describe("formatTimeAgo", () => {
  const now = Date.UTC(2026, 10, 8, 12, 0, 0)

  test("is relative to the clock it receives", () => {
    expect(formatTimeAgo(now - 30_000, now)).toBe("30 seconds ago")
    expect(formatTimeAgo("2026-11-08T11:15:00Z", now)).toBe("45 minutes ago")
    expect(formatTimeAgo(now + 2 * 3_600_000, now)).toBe("in 2 hours")
  })

  test("an instant a few seconds ahead, from clock skew, reads as just now", () => {
    expect(formatTimeAgo(now + 1_500, now)).toBe("just now")
    expect(formatTimeAgo(now + 59_000, now)).toBe("just now")
    expect(formatTimeAgo(now + 61_000, now)).toBe("in 1 minute")
  })

  test("the clock shows the time for today and adds the day otherwise", () => {
    const today = new Date(now - 60_000)
    expect(formatClock(today, now)).toBe(today.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }))
    const yesterday = new Date(now - 26 * 3_600_000)
    expect(formatClock(yesterday, now)).toContain(yesterday.toLocaleDateString(undefined, { day: "2-digit", month: "short" }))
    expect(formatClock("not a date", now)).toBe("-")
  })

  test("renders a dash for an unparsable instant", () => {
    expect(formatTimeAgo("not a date", now)).toBe("-")
    expect(formatAbsoluteTime("not a date")).toBe("-")
  })
})

describe("truncate", () => {
  test("passes through short strings", () => {
    expect(truncate("hello", 10)).toBe("hello")
  })

  test("adds ellipsis when over limit", () => {
    expect(truncate("abcdefgh", 5)).toBe("abcd…")
  })
})
