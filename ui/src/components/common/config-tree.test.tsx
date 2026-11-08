import { afterEach, describe, expect, test } from "bun:test"

import { cleanup, render, screen, within } from "@/test/test-utils"

import { ConfigTree } from "./config-tree"

afterEach(cleanup)

function definition(name: string) {
  return within(screen.getByText(name, { selector: "dt" }).parentElement!).getByRole("definition")
}

describe("ConfigTree", () => {
  test("stacks narrow config rows and reserves the remaining width in wide rows", () => {
    render(<ConfigTree data={{ headers: { "X-Api-Key": { values: ["public"] } } }} secretFields={{ "/headers/X-Api-Key/secrets": true }} />)
    for (const name of ["values", "secrets"]) {
      expect(definition(name).parentElement).toHaveClass("grid-cols-1", "@[14rem]/config:grid-cols-[minmax(0,min(40%,10rem))_minmax(0,1fr)]")
      expect(definition(name).parentElement?.parentElement).toHaveClass("@container/config")
      expect(definition(name)).toHaveClass("min-w-0")
    }
  })

  test.each([undefined, {}])("keeps the empty state without secret metadata (%j)", (secretFields) => {
    render(<ConfigTree data={{}} secretFields={secretFields} />)
    expect(screen.getByText("No configuration.")).toBeInTheDocument()
  })

  test("renders omitted top-level secrets even when no public config remains", () => {
    const data = Object.freeze({})
    const secretFields = Object.freeze({ "/password": true, "/bearer_token": false })
    const { container } = render(<ConfigTree data={data} secretFields={secretFields} />)

    expect(screen.getByRole("definition", { name: "password: secret configured" })).toHaveTextContent("Configured")
    expect(screen.getByRole("definition", { name: "bearer_token: secret not configured" })).toHaveTextContent("Not configured")
    expect(container.querySelectorAll('svg.lucide-lock[aria-hidden="true"]')).toHaveLength(2)
    expect(screen.queryByText("No configuration.")).not.toBeInTheDocument()
    expect(data).toEqual({})
    expect(secretFields).toEqual({ "/password": true, "/bearer_token": false })
  })

  test.each([
    {},
    { headers: {} },
    { headers: { "X-Api-Key": {} } },
  ])("renders metadata-only descendants of %j", (data) => {
    render(<ConfigTree data={data} secretFields={{ "/headers/X-Api-Key/secrets": true }} />)

    expect(screen.getByText("headers:")).toBeInTheDocument()
    expect(screen.getByText("X-Api-Key:")).toBeInTheDocument()
    expect(definition("secrets")).toHaveTextContent("Configured")
    expect(screen.queryByText("{}")).not.toBeInTheDocument()
    expect(screen.queryByText("No configuration.")).not.toBeInTheDocument()
  })

  test("preserves public header values, file paths and literal stars without mutating input", () => {
    const header = Object.freeze({
      values: Object.freeze(["security", "****"]),
      files: Object.freeze(["/run/secrets/client-key"]),
    })
    const data = Object.freeze({
      headers: Object.freeze({ "X-Api-Key": header }),
      note: "****",
      PaSsWoRd: "public exact-case sibling",
    })
    const before = JSON.stringify(data)
    const secretFields = Object.freeze({ "/headers/X-Api-Key/secrets": true, "/password": false })
    render(<ConfigTree data={data} secretFields={secretFields} />)

    expect(definition("values")).toHaveTextContent("[security, ****]")
    expect(definition("files")).toHaveTextContent("[/run/secrets/client-key]")
    expect(definition("note")).toHaveTextContent("****")
    expect(definition("PaSsWoRd")).toHaveTextContent("public exact-case sibling")
    expect(definition("secrets")).toHaveTextContent("Configured")
    expect(definition("password")).toHaveTextContent("Not configured")
    expect(JSON.stringify(data)).toBe(before)
    expect(Object.hasOwn(header, "secrets")).toBe(false)
    expect(secretFields).toEqual({ "/headers/X-Api-Key/secrets": true, "/password": false })
  })

  test.each([
    ["text", "hello", "hello"],
    ["stars", "****", "****"],
    ["empty", "", ""],
    ["zero", 0, "0"],
    ["enabled", true, "true"],
    ["disabled", false, "false"],
    ["nothing", null, "null"],
    ["list", [], "[]"],
    ["object", {}, "{}"],
    ["values", ["a", 0, true, false, null], "[a, 0, true, false, null]"],
  ] as const)("retains public %s display without inferring secrecy", (name, value, expected) => {
    const { container } = render(<ConfigTree data={{ [name]: value }} />)
    expect(definition(name).textContent).toBe(expected)
    expect(container.querySelector("svg")).toBeNull()
  })

  test("keeps object and nested arrays readable", () => {
    render(<ConfigTree data={{ targets: [{ host: "example.test", ports: [80, 443] }, ["nested"]] }} />)
    expect(screen.getByText("targets:")).toBeInTheDocument()
    expect(screen.getByText("[0]:")).toBeInTheDocument()
    expect(definition("host")).toHaveTextContent("example.test")
    expect(definition("ports")).toHaveTextContent("[80, 443]")
    expect(definition("[1]")).toHaveTextContent("[nested]")
  })

  test.each([
    ["X/Api-Key", "X~1Api-Key"],
    ["X~Api-Key", "X~0Api-Key"],
    ["X~1Api~0Key", "X~01Api~00Key"],
    ["X/Api~Key", "X~1Api~0Key"],
    ["X.Api.Key", "X.Api.Key"],
    ["X%2FKey", "X%2FKey"],
    ["", ""],
  ])("decodes pointer segment %s exactly once", (name, encoded) => {
    const data = { headers: { [name]: { values: ["public"] }, sibling: { secrets: "public sibling" } } }
    render(<ConfigTree data={data} secretFields={{ [`/headers/${encoded}/secrets`]: true }} />)
    const branch = screen.getByText(`${name}:`).parentElement!
    expect(within(branch).getByRole("definition", { name: "secrets: secret configured" })).toHaveTextContent("Configured")
    expect(within(branch).getByText("public")).toBeInTheDocument()
    expect(screen.getByText("public sibling")).toBeInTheDocument()
  })

  test("does not confuse escaped, dotted, or case-distinct paths", () => {
    render(<ConfigTree
      data={{
        "auth.password": "public dotted key",
        auth: { Password: "public case sibling" },
        "auth/password": "hidden escaped key",
      }}
      secretFields={{ "/auth/password": false, "/auth~1password": true }}
    />)
    expect(definition("auth.password")).toHaveTextContent("public dotted key")
    expect(definition("Password")).toHaveTextContent("public case sibling")
    expect(definition("password")).toHaveTextContent("Not configured")
    expect(definition("auth/password")).toHaveTextContent("Configured")
    expect(screen.queryByText("hidden escaped key")).not.toBeInTheDocument()
  })

  test("keeps identically named secret leaves independent across branches", () => {
    render(<ConfigTree data={{ headers: { "X-Key": {}, "X-Empty": {} } }} secretFields={{
      "/headers/X-Key/secrets": true, "/headers/X-Empty/secrets": false,
    }} />)
    const configured = screen.getByText("X-Key:").parentElement!
    const empty = screen.getByText("X-Empty:").parentElement!
    expect(within(configured).getByRole("definition", { name: "secrets: secret configured" }).textContent).toBe("Configured")
    expect(within(empty).getByRole("definition", { name: "secrets: secret not configured" }).textContent).toBe("Not configured")
  })

  test("handles prototype-sensitive public and metadata-only keys without prototype writes", () => {
    const prototype = Object.getOwnPropertyDescriptors(Object.prototype)
    const data: Record<string, unknown> = JSON.parse('{"__proto__":{"public":"visible"},"constructor":{"prototype":{"note":"also visible"}}}')
    const before = JSON.stringify(data)
    render(<ConfigTree data={data} secretFields={{
      "/__proto__/password": true,
      "/constructor/prototype/token": false,
      "/headers/__proto__/secrets": true,
      "/toString": false,
    }} />)

    expect(screen.getAllByText("__proto__:")).toHaveLength(2)
    expect(definition("public")).toHaveTextContent("visible")
    expect(definition("note")).toHaveTextContent("also visible")
    expect(definition("password")).toHaveTextContent("Configured")
    expect(definition("token")).toHaveTextContent("Not configured")
    expect(definition("secrets")).toHaveTextContent("Configured")
    expect(definition("toString")).toHaveTextContent("Not configured")
    expect(JSON.stringify(data)).toBe(before)
    expect(Object.getOwnPropertyDescriptors(Object.prototype)).toEqual(prototype)
  })

  test.each([
    { value: "unexpected credential" },
    { value: ["unexpected credential", "another credential"] },
    { value: { nested: "unexpected credential" } },
    { value: [] },
    { value: "" },
    { value: null },
    { value: false },
    { value: 0 },
  ])("secret metadata takes precedence over contradictory value %j", ({ value }) => {
    const data = Object.freeze({ configured: value, unconfigured: value })
    const before = JSON.stringify(data)
    render(<ConfigTree data={data} secretFields={{ "/configured": true, "/unconfigured": false }} />)
    expect(definition("configured").textContent).toBe("Configured")
    expect(definition("unconfigured").textContent).toBe("Not configured")
    expect(screen.getAllByRole("definition")).toHaveLength(2)
    expect(screen.queryByText(/unexpected credential/)).not.toBeInTheDocument()
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument()
    expect(JSON.stringify(data)).toBe(before)
  })

  test("a protected parent hides its descendants even with contradictory child metadata", () => {
    render(<ConfigTree data={{ auth: { password: "unexpected credential" } }} secretFields={{
      "/auth/password": true, "/auth": false,
    }} />)
    expect(definition("auth")).toHaveTextContent("Not configured")
    expect(screen.queryByText("password")).not.toBeInTheDocument()
    expect(screen.queryByText("unexpected credential")).not.toBeInTheDocument()
  })

  test("applies secret paths inside arrays without exposing protected elements", () => {
    render(<ConfigTree data={{
      tokens: ["public", "unexpected credential"],
      targets: [{ host: "example.test" }],
    }} secretFields={{ "/tokens/1": true, "/targets/0/password": false }} />)
    expect(screen.getByText("public")).toBeInTheDocument()
    expect(screen.getByRole("definition", { name: "[1]: secret configured" })).toHaveTextContent("Configured")
    expect(definition("host")).toHaveTextContent("example.test")
    expect(definition("password")).toHaveTextContent("Not configured")
    expect(screen.queryByText("unexpected credential")).not.toBeInTheDocument()
  })

  test("does not retain secret state after metadata changes", () => {
    const { rerender } = render(<ConfigTree data={{}} secretFields={{ "/password": true }} />)
    expect(definition("password")).toHaveTextContent("Configured")
    rerender(<ConfigTree data={{}} secretFields={{ "/password": false }} />)
    expect(definition("password")).toHaveTextContent("Not configured")
    rerender(<ConfigTree data={{ password: "****" }} />)
    expect(definition("password")).toHaveTextContent("****")
    expect(screen.queryByText("Not configured")).not.toBeInTheDocument()
  })
})
