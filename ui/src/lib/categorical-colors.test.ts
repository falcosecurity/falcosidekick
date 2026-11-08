import { describe, expect, test } from "bun:test"

import { classesForSource, classesForTag, rankedColor } from "./categorical-colors"

describe("categorical colors", () => {
  test.each([
    ["network", 0], ["mitre_execution", 1], ["users", 2], ["filesystem", 3],
    ["shell", 4], ["container", 5], ["k8s", 6], ["logging", 7],
    ["process", 8], ["database", 9],
  ] as const)("preserves the semantic color for %s", (tag, index) => {
    expect(classesForTag(tag)).toBe(rankedColor(index))
    expect(classesForTag(tag.toUpperCase())).toBe(rankedColor(index))
  })

  test.each([
    ["syscall", 0], ["k8s_audit", 6], ["kubernetes", 6],
    ["docker", 5], ["cri", 5], ["plugin", 2],
  ] as const)("preserves the source override for %s", (source, index) => {
    expect(classesForSource(source)).toBe(rankedColor(index))
    expect(classesForSource(source.toUpperCase())).toBe(rankedColor(index))
  })

  test("maps unknown keys deterministically to the shared palette", () => {
    const palette = Array.from({ length: 10 }, (_, index) => rankedColor(index))
    for (const key of ["", "custom_source", "unrecognized-tag", "long_key_".repeat(50)]) {
      expect(palette).toContain(classesForTag(key))
      expect(classesForTag(key)).toBe(classesForTag(key.toUpperCase()))
      expect(classesForSource(key)).toBe(classesForTag(key))
    }
  })

  test.each(["constructor", "__proto__", "CONSTRUCTOR", "__PROTO__"])(
    "treats inherited property name %s as an ordinary source",
    (source) => {
      const palette = Array.from({ length: 10 }, (_, index) => rankedColor(index))
      expect(palette).toContain(classesForSource(source))
      expect(classesForSource(source)).toBe(classesForTag(source))
    },
  )

  test("wraps ranked colors without changing the chart or tint tokens", () => {
    for (let index = 0; index < 10; index++) {
      const classes = rankedColor(index)
      expect(classes).toContain(`text-category-${index + 1}-foreground`)
      expect(classes).toContain(`bg-category-${index + 1}/15`)
      expect(classes).toContain(`border-category-${index + 1}/30`)
      expect(rankedColor(index + 10)).toBe(classes)
    }
  })
})
