import { describe, expect, test } from "bun:test"

import { fixtures } from "@/test/fixtures"

import { DRIVER_LOGOS } from "./driver-logos"
import { DRIVER_ICONS, DRIVER_NAMES, iconForDriver } from "./output-icons"

describe("driver icons", () => {
  test("cover exactly the drivers the backend catalog exposes", () => {
    const catalog = (fixtures.outputTypes.types ?? []).map((t) => t.name).sort()
    expect([...DRIVER_NAMES].sort()).toEqual(catalog)
  })

  test("every logo entry points at vendored Simple Icons path data and brand color", () => {
    for (const [driver, icon] of Object.entries(DRIVER_ICONS)) {
      if (icon.kind !== "logo") continue
      const logo = DRIVER_LOGOS[icon.logo]
      expect(logo.title.length, driver).toBeGreaterThan(0)
      expect(logo.color, driver).toMatch(/^#[0-9A-F]{6}$/)
      expect(logo.path, driver).toMatch(/^M[\d.\s-]/)
    }
  })

  test("marks from the vendors' kits are SVG assets", () => {
    const assets = Object.entries(DRIVER_ICONS)
      .filter(([, icon]) => icon.kind === "asset")
      .map(([driver]) => driver)
      .sort()
    expect(assets).toEqual(["awss3", "awssns", "awssqs", "cloudevents", "slack", "teams"])
    for (const driver of assets) {
      const icon = iconForDriver(driver)
      expect(icon.kind === "asset" && icon.src.endsWith(".svg"), driver).toBe(true)
    }
  })

  test("official marks are the driver's own, parent marks are flagged", () => {
    const parents = Object.entries(DRIVER_ICONS)
      .filter(([, icon]) => icon.kind === "logo" && !icon.official)
      .map(([driver]) => driver)
      .sort()
    expect(parents).toEqual(["alertmanager", "grafanaoncall", "loki", "policyreport", "talon"])
    expect(iconForDriver("alertmanager")).toEqual({ kind: "logo", logo: "prometheus", official: false })
    expect(iconForDriver("gcppubsub")).toEqual({ kind: "logo", logo: "googlepubsub", official: true })
  })

  test("drivers without a mark get a lucide icon and unknown names a generic plug", () => {
    for (const driver of ["smtp", "syslog", "webhook", "inmemory"]) {
      expect(iconForDriver(driver).kind, driver).toBe("icon")
    }
    expect(iconForDriver("Webhook")).toBe(iconForDriver("webhook"))
    expect(iconForDriver("custom-thing").kind).toBe("icon")
  })
})
