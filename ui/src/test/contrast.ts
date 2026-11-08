// WCAG contrast of the OKLCH tokens declared in styles/globals.css, for tests.

export type RGB = [number, number, number]

const sheet = new CSSStyleSheet()
sheet.replaceSync(await Bun.file(new URL("../../styles/globals.css", import.meta.url)).text())

export type ThemeSelector = ":root" | ".dark"

export const THEMES: readonly ThemeSelector[] = [":root", ".dark"] as const

export function themeStyle(selector: ThemeSelector): CSSStyleDeclaration {
  const rule = Array.from(sheet.cssRules).find(
    (rule): rule is CSSStyleRule => rule instanceof CSSStyleRule && rule.selectorText === selector,
  )
  if (!rule) throw new Error(`Missing theme ${selector}`)
  return rule.style
}

export function themeColor(selector: ThemeSelector, token: string): RGB {
  return oklchToRGB(themeStyle(selector).getPropertyValue(`--${token}`))
}

function srgb(value: number): number {
  const clipped = Math.max(0, Math.min(1, value))
  return clipped <= 0.0031308 ? clipped * 12.92 : 1.055 * clipped ** (1 / 2.4) - 0.055
}

// CSS Color 4 OKLCH -> sRGB, clipped to the display gamut.
export function oklchToRGB(value: string): RGB {
  const match = /^oklch\(([\d.]+) ([\d.]+) ([\d.]+)\)$/.exec(value.trim())
  if (!match) throw new Error(`Expected an opaque OKLCH token, received ${value}`)
  const lightness = Number(match[1])
  const chroma = Number(match[2])
  const hue = (Number(match[3]) * Math.PI) / 180
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

export function luminance(rgb: RGB): number {
  const linear = rgb.map((value) => (value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4))
  return 0.2126 * linear[0]! + 0.7152 * linear[1]! + 0.0722 * linear[2]!
}

export function contrast(a: RGB, b: RGB): number {
  const first = luminance(a)
  const second = luminance(b)
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05)
}

export function composite(color: RGB, background: RGB, opacity: number): RGB {
  return [
    color[0] * opacity + background[0] * (1 - opacity),
    color[1] * opacity + background[1] * (1 - opacity),
    color[2] * opacity + background[2] * (1 - opacity),
  ]
}
