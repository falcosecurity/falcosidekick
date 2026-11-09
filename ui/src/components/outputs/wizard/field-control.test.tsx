import { afterEach, describe, expect, test } from "bun:test"
import userEvent from "@testing-library/user-event"
import { useState } from "react"

import type { SchemaField } from "@/lib/types"
import { fixtures } from "@/test/fixtures"
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

describe("FieldControl enums", () => {
  // The select cannot hold an empty option, so an enum listing "" would crash the wizard when opened.
  test("the Kafka SASL mechanism opens with Not set and each mechanism", async () => {
    const kafka = fixtures.outputTypes.types!.find((t) => t.name === "kafka")
    const sasl = kafka?.schema.fields?.find((f) => f.name === "auth.sasl")
    expect(sasl).toBeDefined()
    const user = userEvent.setup()
    renderWithProviders(<Harness field={sasl!} />)
    await user.click(screen.getByRole("combobox", { name: "SASL Mechanism" }))
    const options = screen.getAllByRole("option").map((o) => o.textContent)
    expect(options).toEqual(["Not set", ...sasl!.values!])
  })
})

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
