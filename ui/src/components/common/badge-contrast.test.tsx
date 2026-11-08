import { afterEach, describe, expect, test } from "bun:test"

import { rankedColor } from "@/lib/categorical-colors"
import { OUTPUT_HEALTHS, PRIORITIES } from "@/lib/types"
import { composite, contrast, oklchToRGB, themeColor, THEMES } from "@/test/contrast"
import { cleanup, render } from "@/test/test-utils"

import { SourceChip, TagChip } from "./chips"
import { PriorityBadge } from "./priority-badge"
import { StatusBadge } from "./status-badge"

const cases = [
  ...PRIORITIES.map((priority) => ({ name: `priority ${priority}`, badge: <PriorityBadge priority={priority} /> })),
  ...OUTPUT_HEALTHS.map((status) => ({ name: `status ${status}`, badge: <StatusBadge status={status} /> })),
  ...Array.from({ length: 10 }, (_, index) => ({
    name: `category ${index + 1}`,
    badge: <span className={rankedColor(index)}>Category</span>,
  })),
  { name: "source chip", badge: <SourceChip source="syscall" /> },
  { name: "tag chip", badge: <TagChip tag="mitre_execution" /> },
]

afterEach(cleanup)

test("contrast calculation matches sRGB reference colors", () => {
  expect(contrast([0, 0, 0], [1, 1, 1])).toBe(21)
  expect(contrast([119 / 255, 119 / 255, 119 / 255], [1, 1, 1])).toBeCloseTo(4.478, 3)
  const red = oklchToRGB("oklch(0.62795536 0.25768331 29.233885)")
  expect(red[0]).toBeCloseTo(1, 5)
  expect(red[1]).toBeCloseTo(0, 5)
  expect(red[2]).toBeCloseTo(0, 5)
})

for (const selector of THEMES) {
  describe(`${selector} badge text contrast`, () => {
    for (const surface of ["background", "card", "muted", "accent"]) {
      test.each(cases)(`$name meets 4.5:1 on ${surface}`, ({ badge, name }) => {
        const { container } = render(badge)
        const classes = container.firstElementChild!.className.split(" ")
        const foregroundClass = classes.find((value) => /^text-(priority|status|category|muted)-/.test(value))
        const backgroundClass = classes.find((value) => value.startsWith("bg-"))
        if (!foregroundClass || !backgroundClass) throw new Error(`Missing colors for ${name}`)
        const [backgroundToken, opacity = "100"] = backgroundClass.slice(3).split("/")
        const background = composite(themeColor(selector, backgroundToken!), themeColor(selector, surface), Number(opacity) / 100)
        const ratio = contrast(themeColor(selector, foregroundClass.slice(5)), background)
        expect(ratio, `${name} on ${selector} ${surface}`).toBeGreaterThanOrEqual(4.5)
      })
    }
  })
}
