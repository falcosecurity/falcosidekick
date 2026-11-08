import { afterEach, describe, expect, mock, test } from "bun:test"
import userEvent from "@testing-library/user-event"

import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { MultiSelectFilter } from "./multi-select-filter"

afterEach(cleanup)

describe("MultiSelectFilter", () => {
  test.each(["Read Sensitive File", "Node-ABC", "MITRE_T1059"])(
    "preserves custom value case: %s",
    async (value) => {
      const user = userEvent.setup()
      const onChange = mock()
      renderWithProviders(
        <MultiSelectFilter label="Rule" options={[]} values={[]} onChange={onChange} allowCustom />,
      )

      await user.click(screen.getByRole("button", { name: "Rule" }))
      await user.type(screen.getByRole("combobox", { name: "Rule" }), `  ${value}  `)
      await user.keyboard("[Enter]")

      expect(onChange).toHaveBeenCalledWith([value])
    },
  )

  test("matches known options case-insensitively without altering their values", async () => {
    const user = userEvent.setup()
    const onChange = mock()
    renderWithProviders(
      <MultiSelectFilter
        label="Rule"
        options={[{ value: "Read Sensitive File", label: "Read Sensitive File" }]}
        values={[]}
        onChange={onChange}
      />,
    )

    await user.click(screen.getByRole("button", { name: "Rule" }))
    await user.type(screen.getByRole("combobox", { name: "Rule" }), "read SENSITIVE")
    await user.keyboard("[Enter]")

    expect(onChange).toHaveBeenCalledWith(["Read Sensitive File"])
  })

  test("allows a case-distinct custom value alongside a known value", async () => {
    const user = userEvent.setup()
    const onChange = mock()
    renderWithProviders(
      <MultiSelectFilter
        label="Tags"
        options={[{ value: "security", label: "security" }]}
        values={["security"]}
        onChange={onChange}
        allowCustom
      />,
    )

    await user.click(screen.getByRole("button", { name: "Tags" }))
    await user.type(screen.getByRole("combobox", { name: "Tags" }), "Security")
    await user.click(screen.getByRole("option", { name: "Security add custom" }))

    expect(onChange).toHaveBeenCalledWith(["security", "Security"])
  })

  test("does not offer an exact selected value again and can remove it", async () => {
    const user = userEvent.setup()
    const onChange = mock()
    renderWithProviders(
      <MultiSelectFilter
        label="Rule"
        options={[]}
        values={["Read Sensitive File"]}
        onChange={onChange}
        allowCustom
      />,
    )

    await user.click(screen.getByRole("button", { name: "Rule" }))
    await user.type(screen.getByRole("combobox", { name: "Rule" }), "Read Sensitive File")
    expect(screen.getAllByRole("option")).toHaveLength(1)
    expect(screen.queryByText("add custom")).not.toBeInTheDocument()
    await user.keyboard("[Enter]")
    expect(onChange).toHaveBeenCalledWith([])
  })

  test("shows an empty state and clears selected values", async () => {
    const user = userEvent.setup()
    const onChange = mock()
    renderWithProviders(
      <MultiSelectFilter
        label="Priority"
        options={[{ value: "warning", label: "Warning" }]}
        values={["warning"]}
        onChange={onChange}
      />,
    )

    await user.click(screen.getByRole("button", { name: "Priority" }))
    await user.type(screen.getByRole("combobox", { name: "Priority" }), "missing")
    expect(screen.getByText("No matches.")).toBeInTheDocument()
    expect(screen.queryByRole("option")).not.toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Clear" }))
    expect(onChange).toHaveBeenCalledWith([])
  })
})
