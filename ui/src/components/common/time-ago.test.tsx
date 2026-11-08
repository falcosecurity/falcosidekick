import { afterEach, describe, expect, spyOn, test } from "bun:test"

import { CLOCK_TICK_MS } from "@/hooks/use-clock"
import { formatAbsoluteTime } from "@/lib/format"
import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { TimeAgo } from "./time-ago"

afterEach(cleanup)

describe("TimeAgo", () => {
  test("is keyboard reachable and names the absolute instant", () => {
    const value = new Date(Date.now() - 5 * 60_000).toISOString()
    renderWithProviders(<TimeAgo value={value} />)
    const time = screen.getByText(/5 minutes ago/).closest("time")!
    expect(time).toHaveAttribute("tabindex", "0")
    expect(time).toHaveAttribute("datetime", value)
    expect(time).toHaveTextContent(`5 minutes ago, ${formatAbsoluteTime(value)}`)
    expect(time.querySelector(".sr-only")).toHaveTextContent(formatAbsoluteTime(value))
  })

  test("renders a dash for an unparsable instant", () => {
    renderWithProviders(<TimeAgo value="never" />)
    expect(screen.getByText("-")).toBeInTheDocument()
    expect(document.querySelector("time")).toBeNull()
  })

  test("many instances share one clock interval", () => {
    const set = spyOn(globalThis, "setInterval")
    const clear = spyOn(globalThis, "clearInterval")
    try {
      const now = Date.now()
      const { unmount } = renderWithProviders(
        <>
          {Array.from({ length: 25 }, (_, i) => (
            <TimeAgo key={i} value={now - i * 60_000} />
          ))}
        </>,
      )
      const ticks = set.mock.calls.filter(([, ms]) => ms === CLOCK_TICK_MS)
      expect(ticks).toHaveLength(1)
      unmount()
      expect(clear).toHaveBeenCalledWith(ticks[0] ? set.mock.results[set.mock.calls.indexOf(ticks[0])]?.value : undefined)
    } finally {
      set.mockRestore()
      clear.mockRestore()
    }
  })
})
