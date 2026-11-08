import { describe, expect, test } from "bun:test"

import type { SchemaField } from "@/lib/types"
import { fixtures } from "@/test/fixtures"

import { fieldHint, sectionsFor } from "./sections"

const field = (over: Partial<SchemaField>): SchemaField => ({ name: "x", type: "string", label: "X", required: false, ...over })

describe("fieldHint", () => {
  test("says what the field does, then its default or what a file field expects", () => {
    expect(fieldHint(field({ description: "Path the events are sent to.", default: "/" }))).toBe("Path the events are sent to. Default /.")
    expect(fieldHint(field({ description: "PEM file with the CAs.", file: true }))).toBe("PEM file with the CAs. Absolute path of a file.")
    expect(fieldHint(field({ default: 2 }))).toBe("Default 2.")
    expect(fieldHint(field({}))).toBeUndefined()
  })

  test("every field the API describes gets a hint", () => {
    for (const type of fixtures.outputTypes.types ?? []) {
      for (const f of type.schema.fields as SchemaField[]) {
        expect(fieldHint(f), `${type.name}: ${f.name}`).toStartWith(f.description ?? "")
        expect(f.description, `${type.name}: ${f.name}`).toBeTruthy()
      }
    }
  })
})

describe("sectionsFor", () => {
  test("offers batching only for the outputs whose schema has it", () => {
    const types = (fixtures.outputTypes.types ?? []) as { name: string; schema: { fields: SchemaField[] } }[]
    const groupsOf = (name: string) =>
      sectionsFor(types.find((t) => t.name === name)!.schema.fields)
        .find((s) => s.key === "delivery")!
        .groups!.map((g) => g.title)
    expect(groupsOf("loki")).toContain("Batching")
    expect(groupsOf("slack")).not.toContain("Batching")
  })
})
