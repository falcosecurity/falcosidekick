import { describe, expect, test } from "bun:test"

import { PRIORITIES, PRIORITY_LABELS } from "@/lib/types"
import { renderWithProviders, screen } from "@/test/test-utils"

import { PriorityBadge } from "./priority-badge"

describe("PriorityBadge", () => {
  test.each(PRIORITIES.map((p) => [p]))("renders each priority value: %s", (p) => {
    const { unmount } = renderWithProviders(<PriorityBadge priority={p} short={false} />)
    expect(screen.getByLabelText(`priority ${p}`)).toHaveTextContent(PRIORITY_LABELS[p])
    unmount()
  })

  test("uses short label by default", () => {
    renderWithProviders(<PriorityBadge priority="critical" />)
    expect(screen.getByLabelText("priority critical")).toHaveTextContent("CRIT")
  })
})
