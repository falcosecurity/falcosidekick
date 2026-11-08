import { afterEach, describe, expect, test } from "bun:test"

import { PRIORITIES, PRIORITY_LABELS } from "@/lib/types"
import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { PriorityBadge } from "./priority-badge"

afterEach(cleanup)

describe("PriorityBadge", () => {
  test.each(PRIORITIES.map((p) => [p]))("renders each priority value: %s", (p) => {
    renderWithProviders(<PriorityBadge priority={p} short={false} />)
    const badge = screen.getByText(`priority ${p}`).parentElement!
    expect(badge).toHaveAttribute("data-variant", "priority")
    expect(badge).toHaveAttribute("data-priority", p)
    expect(screen.getByText(PRIORITY_LABELS[p])).toHaveAttribute("aria-hidden", "true")
    expect(badge).not.toHaveAttribute("role")
  })

  test("uses the short label by default and the full name for assistive technology", () => {
    renderWithProviders(<PriorityBadge priority="critical" />)
    expect(screen.getByText("CRIT")).toBeInTheDocument()
    expect(screen.getByText("priority critical")).toHaveClass("sr-only")
  })
})
