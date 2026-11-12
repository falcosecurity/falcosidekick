import { afterEach, describe, expect, mock, spyOn, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import type { InternalAxiosRequestConfig } from "axios"
import { toast } from "sonner"

import { setApiAdapterForTests } from "@/lib/api-client"
import { errorResponse, fixtureAdapter, fixtures, routeKey, statusNamed } from "@/test/fixtures"
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

async function fillDiscordSecret() {
  fireEvent.click(await screen.findByRole("radio", { name: "Value" }))
  fireEvent.change(document.getElementById("field-secret_endpoint")!, { target: { value: "/api/webhooks/1/token" } })
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

  test("a number out of the schema range blocks Next on its field, focused, and nothing is sent", async () => {
    const calls = adapter()
    open({ kind: "create" })
    await pickDriver(/^Discord/)
    await fillDiscordSecret()
    fireEvent.click(screen.getByRole("button", { name: /Delivery/ }))
    fireEvent.change(await waitFor(() => document.getElementById("field-runtime-workers")!), { target: { value: "99999999999999999999" } })
    fireEvent.change(document.getElementById("field-runtime-retry-initial_interval")!, { target: { value: "30" } })
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))

    await waitFor(() => expect(document.getElementById("field-runtime-workers-error")).toHaveTextContent("must be an integer between 1 and 256"))
    expect(document.getElementById("field-runtime-retry-initial_interval-error")).toHaveTextContent("must be a duration such as 30s or 1m")
    expect(screen.getByRole("listitem", { current: "step" })).toHaveTextContent("Configure")
    await waitFor(() => expect(document.activeElement?.id).toBe("field-runtime-workers"))
    expect(calls.some((c) => c.method === "put")).toBe(false)
  })

  test("a 400 with fields puts each message on its field, focuses the first in form order and sums up the rest", async () => {
    adapter({
      "PUT /pipeline/outputs/discord": (c) => {
        throw errorResponse(c, 400, {
          error: "invalid configuration",
          phase: "validate",
          fields: [
            { path: "runtime.workers", message: "must be an integer between 1 and 256" },
            { path: "tls.ca_file", message: "must name a regular file" },
            { path: "runtime", message: "workers × batch_size must be at most 100000" },
          ],
        })
      },
    })
    open({ kind: "create" })
    await pickDriver(/^Discord/)
    await fillDiscordSecret()
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
    fireEvent.click(await screen.findByRole("button", { name: "Add output" }))

    await waitFor(() => expect(document.getElementById("field-tls-ca_file-error")).toHaveTextContent("must name a regular file"))
    expect(document.getElementById("field-runtime-workers-error")).toHaveTextContent("must be an integer between 1 and 256")
    expect(screen.getByRole("listitem", { current: "step" })).toHaveTextContent("Configure")
    // TLS comes before Delivery in the form, so its field takes the focus.
    await waitFor(() => expect(document.activeElement?.id).toBe("field-tls-ca_file"))
    const summary = screen.getByText("Not added").closest<HTMLElement>('[role="alert"]')!
    expect(summary).toHaveTextContent("The configuration was refused.")
    expect(summary).toHaveTextContent("runtime: workers × batch_size must be at most 100000")
    expect(summary).not.toHaveTextContent("invalid configuration")
  })

  test("a 400 naming no field stays on Review with the reason, without the server's wrapping", async () => {
    adapter({
      "PUT /pipeline/outputs/discord": (c) => {
        throw errorResponse(c, 400, { error: 'apply output: apply create: catalog: create "discord": discord: tls: unknown certificate authority' })
      },
    })
    open({ kind: "create" })
    await pickDriver(/^Discord/)
    await fillDiscordSecret()
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
    fireEvent.click(await screen.findByRole("button", { name: "Add output" }))

    const summary = (await screen.findByText("Not added")).closest<HTMLElement>('[role="alert"]')!
    expect(summary).toHaveTextContent("tls: unknown certificate authority")
    expect(summary).not.toHaveTextContent("apply output")
    expect(summary).not.toHaveTextContent("catalog")
    expect(screen.getByRole("listitem", { current: "step" })).toHaveTextContent("Review")
  })

  test("a save answered degraded warns with the reason instead of the success toast", async () => {
    const warning = spyOn(toast, "warning")
    const success = spyOn(toast, "success")
    adapter({ "PUT /pipeline/outputs/discord": () => ({ ...fixtures.outputPutDegraded, name: "discord" }) })
    const onSaved = open({ kind: "create" })
    await pickDriver(/^Discord/)
    await fillDiscordSecret()
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
    fireEvent.click(await screen.findByRole("button", { name: "Add output" }))

    await waitFor(() => expect(onSaved).toHaveBeenCalledWith("discord"))
    expect(warning).toHaveBeenCalledTimes(1)
    expect(warning.mock.calls[0]![0]).toBe("Saved. Destination not verified: alertmanager healthcheck: 1 of 1 hosts unreachable")
    expect(success).not.toHaveBeenCalled()
    warning.mockRestore()
    success.mockRestore()
  })

  test("a healthy save keeps the success toast", async () => {
    const warning = spyOn(toast, "warning")
    const success = spyOn(toast, "success")
    adapter({
      "PUT /pipeline/outputs/discord": (c) => ({
        name: "discord", config: body(c).config, version: 1, provisioned: false, updated_at: "",
        status: { ...statusNamed("inmemory"), name: "discord" },
      }),
    })
    const onSaved = open({ kind: "create" })
    await pickDriver(/^Discord/)
    await fillDiscordSecret()
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
    fireEvent.click(await screen.findByRole("button", { name: "Add output" }))
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith("discord"))
    expect(success).toHaveBeenCalledWith("Discord added to the pipeline")
    expect(warning).not.toHaveBeenCalled()
    warning.mockRestore()
    success.mockRestore()
  })

  test.each([
    { name: "validation", field: "secret_endpoint" },
    { name: "validation_range", field: "runtime.workers" },
    { name: "validation_type", field: "runtime.queue_size" },
    { name: "validation_duration", field: "runtime.retry.initial_interval" },
  ] as const)("the server's $name refusal lands on $field, focused, on Configure", async ({ name, field }) => {
    const refusal = fixtures.errors[name]
    const calls = adapter({
      "PUT /pipeline/outputs/slack": (c) => {
        throw errorResponse(c, refusal.status, refusal.body)
      },
    })
    open({ kind: "create" })
    await pickDriver(/^Slack/)
    fireEvent.click(await screen.findByRole("radio", { name: "Value" }))
    fireEvent.change(document.getElementById("field-secret_endpoint")!, { target: { value: "/services/T/B/x" } })
    fireEvent.click(screen.getByRole("button", { name: /^Next/ }))
    fireEvent.click(await screen.findByRole("button", { name: "Add output" }))

    const id = `field-${field.replace(/[^\w-]/g, "-")}`
    await waitFor(() => expect(document.getElementById(`${id}-error`)).toHaveTextContent(refusal.body.fields![0]!.message))
    expect(screen.getByRole("listitem", { current: "step" })).toHaveTextContent("Configure")
    await waitFor(() => expect(document.activeElement?.id).toBe(id))
    // Everything the server said is on the field: no summary, and no wrapped text anywhere.
    expect(screen.queryByText("Not added")).toBeNull()
    expect(screen.queryByText(/apply output/)).toBeNull()
    expect(calls.filter((c) => c.method === "put")).toHaveLength(1)
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
