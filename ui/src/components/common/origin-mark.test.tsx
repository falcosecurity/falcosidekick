import { afterEach, describe, expect, test } from "bun:test"

import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { OriginMark } from "./origin-mark"

afterEach(cleanup)

describe("OriginMark", () => {
  test.each([
    [true, "File provisioned"],
    [false, "API provisioned"],
  ])("provisioned=%p reads %s to screen readers without being focusable", (provisioned, label) => {
    const { container } = renderWithProviders(
      <button type="button">
        out
        <OriginMark provisioned={provisioned} />
      </button>,
    )
    expect(screen.getByRole("button", { name: `out ${label}` })).toBeInTheDocument()
    expect(container.querySelectorAll("[tabindex]")).toHaveLength(0)
  })

  test("with the label shown, the text is visible once and the icon is decorative", () => {
    const { container } = renderWithProviders(<OriginMark provisioned showLabel />)
    expect(screen.getAllByText("File provisioned")).toHaveLength(1)
    expect(container.querySelector(".sr-only")).toBeNull()
    expect(container.querySelector("svg")).toHaveAttribute("aria-hidden", "true")
  })
})
