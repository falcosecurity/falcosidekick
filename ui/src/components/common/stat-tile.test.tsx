import { afterEach, describe, expect, test } from "bun:test"

import { cleanup, render, screen, within } from "@/test/test-utils"

import { StatTile, type StatTone } from "./stat-tile"

afterEach(cleanup)

describe("StatTile", () => {
  test("renders a term and a definition inside the parent list", () => {
    render(
      <dl>
        <StatTile label="Sent" value="1,204" />
      </dl>,
    )
    expect(screen.getByRole("term")).toHaveTextContent("Sent")
    expect(screen.getByRole("definition")).toHaveTextContent("1,204")
    expect(screen.getByRole("definition")).toHaveClass("[overflow-wrap:anywhere]", "tabular-nums")
  })

  test.each<[StatTone, string, string]>([
    ["ok", "border-l-status-ok", "text-status-ok-foreground"],
    ["error", "border-l-status-error", "text-status-error-foreground"],
    ["warning", "border-l-status-degraded", "text-status-degraded-foreground"],
    ["neutral", "border-l-border", "text-foreground"],
  ])("tone %s colors the border and the value", (tone, border, text) => {
    render(
      <dl>
        <StatTile label="Queue" value="3" tone={tone} />
      </dl>,
    )
    expect(screen.getByRole("term").parentElement).toHaveClass(border)
    expect(screen.getByRole("definition")).toHaveClass(text)
  })

  test("accepts children next to the value and custom classes", () => {
    render(
      <dl>
        <StatTile label="Queue" value="3/10" className="col-span-2" valueClassName="font-normal">
          <div data-testid="meter" />
        </StatTile>
      </dl>,
    )
    const definition = screen.getByRole("definition")
    expect(within(definition).getByTestId("meter")).toBeInTheDocument()
    expect(definition).toHaveClass("font-normal")
    expect(definition).not.toHaveClass("font-semibold")
    expect(screen.getByRole("term").parentElement).toHaveClass("col-span-2")
  })
})
