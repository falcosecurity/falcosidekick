import { afterEach, describe, expect, test } from "bun:test"
import { useState } from "react"

import type { SchemaField } from "@/lib/types"
import { cleanup, fireEvent, renderWithProviders, screen } from "@/test/test-utils"

import { FieldControl } from "./field-control"
import type { FieldValue } from "./form-model"

afterEach(cleanup)

const footer: SchemaField = {
  name: "footer",
  type: "string",
  label: "Footer",
  required: false,
  description: "Text shown under the attachment. Empty shows no footer.",
  suggested: "https://github.com/falcosecurity/falcosidekick",
}

function Harness({ field, initial = "" }: { field: SchemaField; initial?: string }) {
  const [value, setValue] = useState<FieldValue>({ kind: "text", text: initial })
  return <FieldControl field={field} value={value} onChange={setValue} filesOnly={false} />
}

describe("FieldControl suggestions", () => {
  test("an empty field offers its suggestion, which fills the field and goes away", () => {
    renderWithProviders(<Harness field={footer} />)
    const input = screen.getByRole("textbox", { name: "Footer" })
    expect(input).toHaveValue("")
    fireEvent.click(screen.getByRole("button", { name: /Use the suggested Footer/ }))
    expect(input).toHaveValue(footer.suggested!)
    expect(screen.queryByRole("button", { name: /Use the suggested/ })).toBeNull()

    fireEvent.change(input, { target: { value: "" } })
    expect(screen.getByRole("button", { name: /Use the suggested Footer/ })).toBeInTheDocument()
  })

  test("a field with a value or without a suggestion offers nothing", () => {
    renderWithProviders(<Harness field={footer} initial="Security team" />)
    expect(screen.queryByRole("button", { name: /Use the suggested/ })).toBeNull()
    cleanup()
    renderWithProviders(<Harness field={{ ...footer, suggested: undefined }} />)
    expect(screen.queryByRole("button", { name: /Use the suggested/ })).toBeNull()
  })
})
