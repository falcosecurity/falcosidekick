import { describe, expect, test } from "bun:test"

import type { OutputConfigEntry, SchemaField } from "@/lib/types"

import { buildPatch, countSet, fieldOfError, initialState, newRow, validate, type FormState, type MapRow } from "./form-model"

const ENTRY = [
  { name: "values", type: "string[]", label: "Values", required: false },
  { name: "secrets", type: "string[]", label: "Secrets", required: false, secret: true },
  { name: "files", type: "string[]", label: "Files", required: false, file: true },
] as SchemaField[]

const FIELDS: SchemaField[] = [
  { name: "host", type: "string", label: "Host", required: true },
  { name: "endpoint", type: "string", label: "Endpoint", required: false, default: "/" },
  { name: "method", type: "enum", label: "Method", required: false, values: ["POST", "PUT"] },
  { name: "password", type: "string", label: "Password", required: false, secret: true },
  { name: "headers", type: "map", label: "Headers", required: false, entry_fields: ENTRY },
  { name: "labels", type: "map", label: "Labels", required: false },
  { name: "tls.ca_file", type: "string", label: "CA file", required: false, file: true },
  { name: "tls.insecure_skip_verify", type: "bool", label: "Skip verify", required: false, default: false },
  { name: "runtime.workers", type: "int", label: "Workers", required: false, default: 2 },
  { name: "runtime.retry.multiplier", type: "float", label: "Multiplier", required: false, default: 2 },
  { name: "brokers", type: "string[]", label: "Brokers", required: false },
]

function stored(config: Record<string, unknown>, secretFields: Record<string, boolean> = {}): OutputConfigEntry {
  return { name: "webhook", config, secret_fields: secretFields, provisioned: false, version: 3, updated_at: "" }
}

function setText(state: FormState, name: string, text: string): FormState {
  return { ...state, [name]: { kind: "text", text } }
}

describe("initialState", () => {
  test("a new output starts empty, booleans unset", () => {
    const state = initialState(FIELDS)
    expect(state.host).toEqual({ kind: "text", text: "" })
    expect(state["tls.insecure_skip_verify"]).toEqual({ kind: "bool", value: null })
    expect(state.password).toEqual({ kind: "secret", secret: { mode: "none", file: "", value: "", stored: false } })
    expect(state.headers).toEqual({ kind: "map", rows: [] })
  })

  test("an edit reads nested values, keeps stored secrets and shows secret files", () => {
    const state = initialState(
      FIELDS,
      stored(
        {
          host: "https://h",
          tls: { insecure_skip_verify: true },
          runtime: { workers: 4 },
          brokers: ["a:9092", "b:9092"],
          headers: { "X-Key": {}, "X-Env": { values: ["prod"] } },
        },
        { "/password": true, "/headers/X-Key/secrets": true },
      ),
    )
    expect(state.host).toEqual({ kind: "text", text: "https://h" })
    expect(state["tls.insecure_skip_verify"]).toEqual({ kind: "bool", value: true })
    expect(state["runtime.workers"]).toEqual({ kind: "text", text: "4" })
    expect(state.brokers).toEqual({ kind: "text", text: "a:9092\nb:9092" })
    expect(state.password).toMatchObject({ secret: { mode: "keep", stored: true } })
    const rows = state.headers?.kind === "map" ? state.headers.rows : []
    expect(rows.map((r) => [r.key, r.kind, r.text, r.stored])).toEqual([
      ["X-Key", "secrets", "", true],
      ["X-Env", "values", "prod", true],
    ])
  })

  test("a secret stored as a file is shown as that file", () => {
    const state = initialState(FIELDS, stored({ password_file: "/etc/secrets/pw" }, { "/password": true }))
    expect(state.password).toMatchObject({ secret: { mode: "file", file: "/etc/secrets/pw", stored: true } })
  })
})

describe("validate", () => {
  const options = { filesOnly: true }
  test.each([
    ["host", "", "Required"],
    ["runtime.workers", "2.5", "Must be a whole number"],
    ["runtime.retry.multiplier", "x", "Must be a number"],
    ["method", "GET", "Must be one of POST, PUT"],
  ])("%s = %p: %s", (name, text, message) => {
    const state = setText(setText(initialState(FIELDS), "host", "https://h"), name, text)
    expect(validate(FIELDS, state, options)[name]).toBe(message)
  })

  test("a valid form has no errors", () => {
    expect(validate(FIELDS, setText(initialState(FIELDS), "host", "https://h"), options)).toEqual({})
  })

  test("secrets: inline values only where the database keeps them, files absolute", () => {
    const base = setText(initialState(FIELDS), "host", "https://h")
    const withSecret = (secret: object): FormState => ({
      ...base,
      password: { kind: "secret", secret: { mode: "value", file: "", value: "", stored: false, ...secret } },
    })
    expect(validate(FIELDS, withSecret({ value: "pw" }), { filesOnly: true }).password).toBe(
      "This database keeps only secret files: pick a file",
    )
    expect(validate(FIELDS, withSecret({ value: "pw" }), { filesOnly: false })).toEqual({})
    expect(validate(FIELDS, withSecret({ mode: "file", file: "secrets/pw" }), options).password).toBe("Must be an absolute path")
  })

  test("map entries need a name, unique plain keys and file paths for secrets on a persistent database", () => {
    const base = setText(initialState(FIELDS), "host", "https://h")
    expect(validate(FIELDS, { ...base, labels: { kind: "map", rows: [newRow({ key: "" })] } }, options).labels).toBe(
      "Every entry needs a name",
    )
    expect(
      validate(FIELDS, { ...base, labels: { kind: "map", rows: [newRow({ key: "a" }), newRow({ key: "a" })] } }, options).labels,
    ).toBe('"a" appears twice')
    expect(
      validate(FIELDS, { ...base, headers: { kind: "map", rows: [newRow({ key: "X", kind: "secrets", text: "t" })] } }, options)
        .headers,
    ).toBe('"X": this database keeps only secret files')
    expect(
      validate(FIELDS, { ...base, headers: { kind: "map", rows: [newRow({ key: "X", kind: "secrets", stored: true })] } }, options),
    ).toEqual({})
  })
})

describe("buildPatch", () => {
  test("a new output sends what is set, nested, typed, without empty fields", () => {
    let state = initialState(FIELDS)
    state = setText(state, "host", " https://h ")
    state = setText(state, "runtime.workers", "4")
    state = setText(state, "runtime.retry.multiplier", "1.5")
    state = setText(state, "brokers", "a:9092\n\n b:9092 ")
    state["tls.insecure_skip_verify"] = { kind: "bool", value: true }
    state.password = { kind: "secret", secret: { mode: "file", file: "/etc/secrets/pw", value: "", stored: false } }
    state.headers = {
      kind: "map",
      rows: [newRow({ key: "X-Env", text: "prod" }), newRow({ key: "X-Token", kind: "files", text: "/etc/secrets/t" })],
    }
    expect(buildPatch(FIELDS, state)).toEqual({
      host: "https://h",
      password_file: "/etc/secrets/pw",
      headers: { "X-Env": { values: ["prod"] }, "X-Token": { files: ["/etc/secrets/t"] } },
      tls: { insecure_skip_verify: true },
      runtime: { workers: 4, retry: { multiplier: 1.5 } },
      brokers: ["a:9092", "b:9092"],
    })
  })

  test("an edit sends only changes, null for cleared fields and removed entries, and keeps stored secrets", () => {
    const entry = stored(
      {
        host: "https://h",
        endpoint: "/v1",
        runtime: { workers: 4 },
        headers: { "X-Key": {}, "X-Env": { values: ["prod"] }, "X-Old": { values: ["1"] } },
        labels: { team: "sec" },
      },
      { "/password": true, "/headers/X-Key/secrets": true },
    )
    let state = initialState(FIELDS, entry)
    state = setText(state, "endpoint", "")
    state = setText(state, "runtime.workers", "4")
    const rows = state.headers?.kind === "map" ? state.headers.rows : []
    state.headers = {
      kind: "map",
      rows: rows.filter((r) => r.key !== "X-Old").map((r) => (r.key === "X-Env" ? { ...r, text: "staging", edited: true } : r)),
    }
    expect(buildPatch(FIELDS, state, entry)).toEqual({
      endpoint: null,
      headers: { "X-Env": { values: ["staging"] }, "X-Old": null },
    })
  })

  // The API removes entry secrets from config and flags them in secret_fields (see the output fixture).
  describe("entry secrets as the API returns them", () => {
    const withSecret = stored(
      { host: "https://h", headers: { "X-Api-Key": { values: ["public"] }, Authorization: {} } },
      { "/headers/X-Api-Key/secrets": true, "/headers/Authorization/secrets": true },
    )

    test("each key with a stored secret shows it as stored", () => {
      const rows = initialState(FIELDS, withSecret).headers
      expect(rows?.kind === "map" ? rows.rows.map((r) => [r.key, r.kind, r.stored]) : []).toEqual([
        ["X-Api-Key", "values", true],
        ["X-Api-Key", "secrets", true],
        ["Authorization", "secrets", true],
      ])
    })

    test("editing another field never names a stored secret", () => {
      const state = setText(initialState(FIELDS, withSecret), "host", "https://other")
      expect(buildPatch(FIELDS, state, withSecret)).toEqual({ host: "https://other" })
    })

    test("changing the public value of a key keeps its secret", () => {
      const state = initialState(FIELDS, withSecret)
      const map = state.headers as { kind: "map"; rows: MapRow[] }
      state.headers = { kind: "map", rows: map.rows.map((r) => (r.key === "X-Api-Key" && r.kind === "values" ? { ...r, text: "public2", edited: true } : r)) }
      expect(buildPatch(FIELDS, state, withSecret)).toEqual({ headers: { "X-Api-Key": { values: ["public2"] } } })
    })

    test("removing the stored secret clears only that secret, and removing every row clears the key", () => {
      const state = initialState(FIELDS, withSecret)
      const map = state.headers as { kind: "map"; rows: MapRow[] }
      state.headers = { kind: "map", rows: map.rows.filter((r) => r.kind !== "secrets") }
      expect(buildPatch(FIELDS, state, withSecret)).toEqual({ headers: { "X-Api-Key": { secrets: null }, Authorization: null } })
    })

    test("replacing a stored secret sends the new one", () => {
      const state = initialState(FIELDS, withSecret)
      const map = state.headers as { kind: "map"; rows: MapRow[] }
      state.headers = { kind: "map", rows: map.rows.map((r) => (r.key === "Authorization" ? { ...r, text: "Bearer new", edited: true } : r)) }
      expect(buildPatch(FIELDS, state, withSecret)).toEqual({ headers: { Authorization: { secrets: ["Bearer new"] } } })
    })

    test("keys with a slash or tilde use escaped pointers", () => {
      const entry = stored({ headers: { "a/b~c": {} } }, { "/headers/a~1b~0c/secrets": true })
      const rows = initialState(FIELDS, entry).headers
      expect(rows?.kind === "map" ? rows.rows.map((r) => [r.key, r.kind]) : []).toEqual([["a/b~c", "secrets"]])
      expect(buildPatch(FIELDS, initialState(FIELDS, entry), entry)).toEqual({})
    })
  })

  test("an edit replaces a stored secret with a file, or clears it", () => {
    const entry = stored({ host: "https://h" }, { "/password": true })
    const replace = initialState(FIELDS, entry)
    replace.password = { kind: "secret", secret: { mode: "file", file: "/etc/secrets/new", value: "", stored: true } }
    expect(buildPatch(FIELDS, replace, entry)).toEqual({ password_file: "/etc/secrets/new" })

    const clear = initialState(FIELDS, entry)
    clear.password = { kind: "secret", secret: { mode: "none", file: "", value: "", stored: true } }
    expect(buildPatch(FIELDS, clear, entry)).toEqual({ password: null, password_file: null })
  })

  test("a field the merge stored as null reads as unset and is not cleared again", () => {
    const entry = stored({ host: "https://h", runtime: { workers: null }, tls: { insecure_skip_verify: null }, headers: {} })
    const state = initialState(FIELDS, entry)
    expect(state["runtime.workers"]).toEqual({ kind: "text", text: "" })
    expect(buildPatch(FIELDS, state, entry)).toEqual({})
  })

  test("an unchanged edit sends an empty patch", () => {
    const entry = stored({ host: "https://h", tls: { insecure_skip_verify: false }, brokers: ["a"] }, { "/password": true })
    expect(buildPatch(FIELDS, initialState(FIELDS, entry), entry)).toEqual({})
  })
})

describe("fieldOfError", () => {
  test.each([
    ["password_file: must name a regular file of at most 1 MiB inside api.secret_dirs", "password"],
    ['headers["X-Key"].files[1]: must name a regular file', "headers"],
    ["tls.ca_file: must name a regular file", "tls.ca_file"],
    ["host: must be a valid URL", "host"],
    ["output \"webhook\": unknown problem", null],
  ])("%s -> %p", (message, field) => {
    expect(fieldOfError(FIELDS, message)).toBe(field)
  })
})

test("countSet counts the fields holding a value", () => {
  const state = setText(initialState(FIELDS), "host", "h")
  state["tls.insecure_skip_verify"] = { kind: "bool", value: false }
  expect(countSet(["host", "endpoint", "tls.insecure_skip_verify", "password"], state)).toBe(2)
})
