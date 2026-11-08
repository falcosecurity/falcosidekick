import { afterEach, describe, expect, test } from "bun:test"

import { rankedColor } from "@/lib/categorical-colors"
import { PRIORITIES, type OutputStatusState } from "@/lib/types"
import { cleanup, render } from "@/test/test-utils"

import { PriorityBadge } from "./priority-badge"
import { StatusBadge } from "./status-badge"

const sheet = new CSSStyleSheet()
sheet.replaceSync(await Bun.file(new URL("../../../styles/globals.css", import.meta.url)).text())

type RGB = [number, number, number]

function themeStyle(selector: string): CSSStyleDeclaration {
  const rule = Array.from(sheet.cssRules).find(
    (rule): rule is CSSStyleRule => rule instanceof CSSStyleRule && rule.selectorText === selector,
  )
  if (!rule) throw new Error(`Missing theme ${selector}`)
  return rule.style
}

function srgb(value: number): number {
  const clipped = Math.max(0, Math.min(1, value))
  return clipped <= 0.0031308 ? clipped * 12.92 : 1.055 * clipped ** (1 / 2.4) - 0.055
}

// CSS Color 4 OKLCH -> linear sRGB, clipped to the sRGB display gamut.
function oklchToRGB(value: string): RGB {
  const match = /^oklch\(([\d.]+) ([\d.]+) ([\d.]+)\)$/.exec(value)
  if (!match) throw new Error(`Expected an opaque OKLCH token, received ${value}`)
  const lightness = Number(match[1])
  const chroma = Number(match[2])
  const hue = Number(match[3]) * Math.PI / 180
  const a = chroma * Math.cos(hue)
  const b = chroma * Math.sin(hue)
  const l = (lightness + 0.3963377774 * a + 0.2158037573 * b) ** 3
  const m = (lightness - 0.1055613458 * a - 0.0638541728 * b) ** 3
  const s = (lightness - 0.0894841775 * a - 1.291485548 * b) ** 3
  return [
    srgb(4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s),
    srgb(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s),
    srgb(-0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s),
  ]
}

function luminance(rgb: RGB): number {
  const linear = rgb.map((value) =>
    value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4,
  )
  return 0.2126 * linear[0]! + 0.7152 * linear[1]! + 0.0722 * linear[2]!
}

function contrast(a: RGB, b: RGB): number {
  const first = luminance(a)
  const second = luminance(b)
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05)
}

function composite(color: RGB, background: RGB, opacity: number): RGB {
  return [
    color[0] * opacity + background[0] * (1 - opacity),
    color[1] * opacity + background[1] * (1 - opacity),
    color[2] * opacity + background[2] * (1 - opacity),
  ]
}

const statuses: OutputStatusState[] = ["ok", "idle", "error", "degraded", "disabled", "unknown"]
const cases = [
  ...PRIORITIES.map((priority) => ({ name: `priority ${priority}`, badge: <PriorityBadge priority={priority} /> })),
  ...statuses.map((status) => ({ name: `status ${status}`, badge: <StatusBadge status={status} /> })),
  ...Array.from({ length: 10 }, (_, index) => ({
    name: `category ${index + 1}`,
    badge: <span className={rankedColor(index)}>Category</span>,
  })),
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

for (const selector of [":root", ".dark"]) {
  describe(`${selector} badge text contrast`, () => {
    const style = themeStyle(selector)
    const color = (name: string) => oklchToRGB(style.getPropertyValue(`--${name}`))

    for (const surface of ["background", "card", "muted", "accent"]) {
      test.each(cases)(`$name meets 4.5:1 on ${surface}`, ({ badge, name }) => {
        const { container } = render(badge)
        const classes = container.firstElementChild!.className.split(" ")
        const foregroundClass = classes.find((value) => /^text-(priority|status|category|muted)-/.test(value))
        const backgroundClass = classes.find((value) => value.startsWith("bg-"))
        if (!foregroundClass || !backgroundClass) throw new Error(`Missing colors for ${name}`)
        const [backgroundToken, opacity = "100"] = backgroundClass.slice(3).split("/")
        const background = composite(color(backgroundToken!), color(surface), Number(opacity) / 100)
        const ratio = contrast(color(foregroundClass.slice(5)), background)
        expect(ratio, `${name} on ${selector} ${surface}`).toBeGreaterThanOrEqual(4.5)
      })
    }
  })
}
