import { afterEach, describe, expect, mock, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import type { InternalAxiosRequestConfig } from "axios"

import { setApiAdapterForTests } from "@/lib/api-client"
import { errorResponse, fixtureAdapter, fixtures, routeKey } from "@/test/fixtures"
import { act, cleanup, fireEvent, renderWithProviders, screen, waitFor, within } from "@/test/test-utils"

import { OutputWizard, type WizardTarget } from "./output-wizard"

afterEach(() => {
  cleanup()
  setApiAdapterForTests(null)
})

type Handler = (config: InternalAxiosRequestConfig) => unknown

/** The fixture routes, with overrides by "METHOD /path"; a handler may throw an axios error. */
function adapter(overrides: Record<string, Handler> = {}, calls: InternalAxiosRequestConfig[] = []) {
  const base = fixtureAdapter(calls)
  setApiAdapterForTests(async (config) => {
    const handler = overrides[routeKey(config)]
    if (!handler) return base(config)
    calls.push(config)
    return { data: handler(config), status: 200, statusText: "OK", headers: {}, config }
  })
  return calls
}

function body(config: InternalAxiosRequestConfig): { version: number; config: Record<string, unknown> } {
  return JSON.parse(String(config.data))
}

function open(target: WizardTarget, onSaved = mock()) {
  renderWithProviders(<OutputWizard target={target} onClose={mock()} onSaved={onSaved} />)
  return onSaved
}

async function pickDriver(name: RegExp) {
  fireEvent.click(await screen.findByRole("button", { name }))
  fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
}

describe("OutputWizard", () => {
  test("lists every driver of the catalog, configured ones disabled, and filters by name", async () => {
    adapter()
    open({ kind: "create" })
    const list = await screen.findByRole("list", { name: "Drivers" })
    expect(within(list).getAllByRole("button")).toHaveLength(fixtures.outputTypes.types!.length)
    for (const configured of [/^In-memory store/, /^Webhook/, /^Alertmanager/]) {
      expect(within(list).getByRole("button", { name: configured })).toBeDisabled()
    }
    expect(screen.getByRole("button", { name: /^Next/ })).toBeDisabled()
    expect(within(list).getByRole("button", { name: /^In-memory store/ })).toHaveTextContent("Event source")
    expect(within(list).getByRole("button", { name: /^Webhook/ })).not.toHaveTextContent("Event source")
    expect(screen.getByText(/the driver also stores events/)).toBeInTheDocument()
    fireEvent.change(screen.getByRole("textbox", { name: "Search drivers" }), { target: { value: "slack" } })
    expect(within(list).getAllByRole("button").map((b) => b.textContent)).toEqual(["SlackChat"])
  })

  test("creates an output: the required secret blocks Next, then a PUT with version 0 sends what was set", async () => {
    const calls = adapter({ "PUT /pipeline/outputs/discord": (c) => ({ name: "discord", config: body(c).config, version: 1, provisioned: false, updated_at: "" }) })
    const onSaved = open({ kind: "create" })
    await pickDriver(/^Discord/)

    fireEvent.click(await screen.findByRole("button", { name: /^Next/ }))
    await waitFor(() => expect(document.getElementById("field-secret_endpoint-error")).toHaveTextContent("Required"))
    expect(screen.getByRole("listitem", { current: "step" })).toHaveTextContent("Configure")

    // The fixture database is in memory, so an inline value is allowed and said to be lost on restart.
    fireEvent.click(screen.getByRole("radio", { name: "Value" }))
    fireEvent.change(document.getElementById("field-secret_endpoint")!, { target: { value: "/api/webhooks/1/token" } })
    expect(screen.getByText("Kept in memory only and lost on restart.")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))

    expect(await screen.findByText("Hidden value")).toBeInTheDocument()
    expect(screen.queryByText("/api/webhooks/1/token")).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Add output" }))

    await waitFor(() => expect(onSaved).toHaveBeenCalledWith("discord"))
    const put = calls.find((c) => routeKey(c) === "PUT /pipeline/outputs/discord")!
    expect(body(put)).toEqual({ version: 0, config: { secret_endpoint: "/api/webhooks/1/token" } })
  })

  test("on a persistent database a secret can only be a file", async () => {
    adapter({ "GET /config": () => fixtures.configPostgres })
    open({ kind: "create" })
    await pickDriver(/^Discord/)
    await screen.findByText("The database keeps only the path; Sidekick reads the file and follows its changes.")
    expect(screen.queryByRole("radio", { name: "Value" })).toBeNull()
    expect(screen.getByRole("button", { name: "Browse secret files" })).toBeInTheDocument()
  })

  test("a 400 that names a field brings back Configure with the message on that field", async () => {
    adapter({
      "PUT /pipeline/outputs/discord": (c) => {
        throw errorResponse(c, 400, { error: "secret_endpoint_file: must name a regular file of at most 1 MiB inside api.secret_dirs" })
      },
    })
    open({ kind: "create" })
    await pickDriver(/^Discord/)
    fireEvent.click(await screen.findByRole("radio", { name: "From a file" }))
    fireEvent.change(document.getElementById("field-secret_endpoint")!, { target: { value: "/tmp/elsewhere" } })
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
    fireEvent.click(await screen.findByRole("button", { name: "Add output" }))

    expect(await screen.findByText("must name a regular file of at most 1 MiB inside api.secret_dirs")).toBeInTheDocument()
    expect(screen.getByRole("listitem", { current: "step" })).toHaveTextContent("Configure")
    expect(document.getElementById("field-secret_endpoint")).toHaveAttribute("aria-invalid", "true")
  })

  test("an edit starts from the stored output, sends only the change with its version, and explains a 409", async () => {
    let conflict = true
    const calls = adapter({
      "PUT /pipeline/outputs/webhook": (c) => {
        if (conflict) throw errorResponse(c, 409, fixtures.errors.version_conflict.body)
        return { ...fixtures.output, version: 3 }
      },
    })
    const onSaved = open({ kind: "edit", name: "webhook" })
    expect(await screen.findByDisplayValue("http://127.0.0.1:2899")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: /Connection/ }))
    const endpoint = await screen.findByDisplayValue("/events")
    // The header keeps its public value and shows that it also holds a stored secret.
    expect(screen.getAllByDisplayValue("X-Api-Key")).toHaveLength(2)
    expect(screen.getByText("Stored, hidden")).toBeInTheDocument()
    fireEvent.change(endpoint, { target: { value: "/v2/events" } })
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
    expect(await screen.findByText("/v2/events")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }))

    expect(await screen.findByText("Changed by someone else")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled()
    const put = calls.find((c) => routeKey(c) === "PUT /pipeline/outputs/webhook")!
    expect(body(put)).toEqual({ version: fixtures.output.version, config: { endpoint: "/v2/events" } })

    conflict = false
    fireEvent.click(screen.getByRole("button", { name: /Reload/ }))
    expect(await screen.findByDisplayValue("/events")).toBeInTheDocument()
    fireEvent.change(screen.getByDisplayValue("/events"), { target: { value: "/v2/events" } })
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
    fireEvent.click(await screen.findByRole("button", { name: "Save changes" }))
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith("webhook"))
  })

  test("a newer copy read after the first edit does not change the version the edit is saved against", async () => {
    const calls = adapter({ "PUT /pipeline/outputs/webhook": () => ({ ...fixtures.output, version: 4 }) })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0, gcTime: 0 } } })
    renderWithProviders(<OutputWizard target={{ kind: "edit", name: "webhook" }} onClose={mock()} onSaved={mock()} />, { queryClient: client })
    fireEvent.click(await screen.findByRole("button", { name: /Connection/ }))
    fireEvent.change(await screen.findByDisplayValue("/events"), { target: { value: "/v2/events" } })
    // Someone else changed the host; the background read brings version 3.
    act(() => {
      client.setQueryData(["pipeline", "output", "webhook"], {
        ...fixtures.output,
        version: 3,
        config: { ...fixtures.output.config, host: "http://changed:1" },
      })
    })
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
    fireEvent.click(await screen.findByRole("button", { name: "Save changes" }))
    await waitFor(() => expect(calls.some((c) => routeKey(c) === "PUT /pipeline/outputs/webhook")).toBe(true))
    const put = calls.find((c) => routeKey(c) === "PUT /pipeline/outputs/webhook")!
    expect(body(put)).toEqual({ version: fixtures.output.version, config: { endpoint: "/v2/events" } })
  })
})
