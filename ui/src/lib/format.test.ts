import { describe, expect, test } from "bun:test"

import { formatDurationMs, formatNumber, truncate } from "./format"

describe("formatNumber", () => {
  test("formats thousands using locale grouping", () => {
    const result = formatNumber(12_345)
    expect(result).toMatch(/12.345/)
  })

  test("formats zero", () => {
    expect(formatNumber(0)).toBe("0")
  })
})

describe("formatDurationMs", () => {
  test("millisecond precision under 1s", () => {
    expect(formatDurationMs(742)).toBe("742ms")
  })

  test("seconds between 1s and 60s", () => {
    expect(formatDurationMs(1_500)).toBe("1.50s")
    expect(formatDurationMs(12_700)).toBe("12.7s")
  })

  test("minutes between 60s and 60m", () => {
    expect(formatDurationMs(90_000)).toBe("1.5m")
  })

  test("hours above 60m", () => {
    expect(formatDurationMs(3_700_000)).toBe("1.0h")
  })

  test("rejects invalid input", () => {
    expect(formatDurationMs(-1)).toBe("-")
    expect(formatDurationMs(Number.NaN)).toBe("-")
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
