import { afterEach, describe, expect, test } from "bun:test"

import { cleanup, render, screen } from "@/test/test-utils"

import { Meter, meterPercent } from "./meter"

afterEach(cleanup)

describe("Meter", () => {
  test("exposes the meter role with its bounds and label", () => {
    render(<Meter value={80} max={100} label="Queue alerts" tone="warning" />)
    const meter = screen.getByRole("meter", { name: "Queue alerts" })
    expect(meter).toHaveAttribute("aria-valuemin", "0")
    expect(meter).toHaveAttribute("aria-valuemax", "100")
    expect(meter).toHaveAttribute("aria-valuenow", "80")
    expect(meter.firstElementChild).toHaveClass("bg-status-degraded")
    expect((meter.firstElementChild as HTMLElement).style.width).toBe("80%")
  })

  test.each([
    { value: 0, max: 100, width: "0%", now: "0" },
    { value: 0, max: 0, width: "0%", now: "0" },
    { value: 10, max: 0, width: "0%", now: "0" },
    { value: 75, max: 100, width: "75%", now: "75" },
    { value: 120, max: 100, width: "100%", now: "100" },
    { value: -3, max: 100, width: "0%", now: "0" },
  ])("clamps $value/$max to a valid meter", ({ value, max, width, now }) => {
    render(<Meter value={value} max={max} label="Queue" />)
    const meter = screen.getByRole("meter")
    expect(meter).toHaveAttribute("aria-valuenow", now)
    expect((meter.firstElementChild as HTMLElement).style.width).toBe(width)
    expect(meterPercent(value, max)).toBe(Number.parseFloat(width))
  })

  test("decorative meters carry no role and are hidden from assistive technology", () => {
    const { container } = render(<Meter decorative value={3} max={10} label="Rule" fillClassName="bg-category-1" />)
    const bar = container.firstElementChild!
    expect(bar).not.toHaveAttribute("role")
    expect(bar).toHaveAttribute("aria-hidden", "true")
    expect(bar).not.toHaveAttribute("aria-label")
    expect(bar.firstElementChild).toHaveClass("bg-category-1")
    expect(screen.queryByRole("meter")).toBeNull()
  })
})
