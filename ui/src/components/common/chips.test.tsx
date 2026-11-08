import { afterEach, describe, expect, test } from "bun:test"

import { classesForSource, classesForTag } from "@/lib/categorical-colors"
import { cleanup, render, screen } from "@/test/test-utils"

import { SourceChip, TagChip } from "./chips"

afterEach(cleanup)

describe("chips", () => {
  test("SourceChip is a Badge with the source variant and the categorical colors", () => {
    render(<SourceChip source="k8s_audit" />)
    const chip = screen.getByText("k8s_audit")
    expect(chip).toHaveAttribute("data-slot", "badge")
    expect(chip).toHaveAttribute("data-variant", "source")
    for (const cls of classesForSource("k8s_audit").split(" ")) expect(chip).toHaveClass(cls)
    expect(chip).toHaveClass("font-mono", "text-2xs")
    expect(chip).not.toHaveAttribute("role")
  })

  test("TagChip is a Badge with the tag variant and the categorical colors", () => {
    render(<TagChip tag="mitre_execution" />)
    const chip = screen.getByText("mitre_execution")
    expect(chip).toHaveAttribute("data-variant", "tag")
    for (const cls of classesForTag("mitre_execution").split(" ")) expect(chip).toHaveClass(cls)
    expect(chip).toHaveClass("text-2xs")
    expect(chip).not.toHaveClass("font-mono")
  })
})
