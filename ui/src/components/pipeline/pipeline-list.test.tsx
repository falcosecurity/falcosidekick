import { afterEach, describe, expect, mock, test } from "bun:test"

import type { PipelineComposite } from "@/lib/types"
import { statusNamed } from "@/test/fixtures"
import { cleanup, fireEvent, renderWithProviders, screen, within } from "@/test/test-utils"

import { PipelineList } from "./pipeline-list"

afterEach(cleanup)

const composite: PipelineComposite = {
  outputs: [
    { name: "webhook", config: {}, provisioned: true, version: 1, updated_at: "" },
    { name: "slack", config: {}, provisioned: false, version: 2, updated_at: "" },
  ],
  status: [],
  layout: { nodes: [], updated_at: "" },
}

describe("PipelineList", () => {
  test("lists Falco, Sidekick and every output with its status and origin, and selects on tap", () => {
    const onSelect = mock()
    renderWithProviders(
      <PipelineList composite={composite} statusByName={{ webhook: statusNamed("webhook") }} selection={{ kind: "sink", name: "slack" }} onSelect={onSelect} />,
    )
    const outputs = screen.getByRole("group", { name: "Outputs" })
    const webhook = within(outputs).getByRole("button", { name: /webhook/ })
    expect(webhook).toHaveTextContent("File provisioned")
    expect(within(webhook).getByText("error", { selector: "[data-status]" })).toBeInTheDocument()
    expect(within(outputs).getByRole("button", { name: /slack/ })).toHaveAttribute("aria-pressed", "true")
    fireEvent.click(screen.getByRole("button", { name: /Falco Sidekick/ }))
    expect(onSelect).toHaveBeenCalledWith({ kind: "core" })
    fireEvent.click(webhook)
    expect(onSelect).toHaveBeenCalledWith({ kind: "sink", name: "webhook" })
    expect(screen.queryByRole("button", { name: "Add output" })).toBeNull()
  })

  test("offers Add output when writes are allowed", () => {
    const onAdd = mock()
    renderWithProviders(<PipelineList composite={composite} statusByName={{}} selection={null} onSelect={mock()} onAdd={onAdd} />)
    fireEvent.click(screen.getByRole("button", { name: "Add output" }))
    expect(onAdd).toHaveBeenCalled()
  })
})
