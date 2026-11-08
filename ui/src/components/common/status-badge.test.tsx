import { afterEach, describe, expect, test } from "bun:test"

import { OUTPUT_HEALTHS } from "@/lib/types"
import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { StatusBadge } from "./status-badge"

afterEach(cleanup)

describe("StatusBadge", () => {
  test.each(OUTPUT_HEALTHS.map((s) => [s]))("renders %s as plain text without a live region", (status) => {
    renderWithProviders(<StatusBadge status={status} />)
    const badge = screen.getByText(status, { selector: "[data-status]" })
    expect(badge).toHaveAttribute("data-status", status)
    expect(badge).not.toHaveAttribute("role")
    expect(badge).not.toHaveAttribute("aria-live")
    expect(badge).toHaveTextContent(`status ${status}`)
    expect(screen.queryByRole("status")).toBeNull()
  })

  test("dashes the border of an output that is not running", () => {
    renderWithProviders(<StatusBadge status="failed" />)
    expect(screen.getByText("failed", { selector: "[data-status]" })).toHaveClass("border-dashed")
  })
})
