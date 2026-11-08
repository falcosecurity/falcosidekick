import { describe, expect, test } from "bun:test"

import { formatAbsoluteTime, formatNumber, formatTimeAgo, truncate } from "./format"

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
