import { afterEach, describe, expect, spyOn, test } from "bun:test"

import { api } from "@/lib/api-client"
import { ApiError } from "@/lib/api-error"
import type { OutputConfigEntry, OutputStatus, OutputType } from "@/lib/types"
import { fixtures, outputNamed, statusNamed } from "@/test/fixtures"
import { cleanup, fireEvent, renderWithProviders, screen, within } from "@/test/test-utils"

import { falcoSnippet, PipelineDetailPanel, problemOf } from "./detail-panel"

const entry: OutputConfigEntry = outputNamed("webhook")
const delivering: OutputStatus = { ...statusNamed("inmemory"), name: "webhook" }
const failing: OutputStatus = statusNamed("webhook")

const spies: Array<{ mockRestore: () => void }> = []

afterEach(() => {
  cleanup()
  for (const spy of spies.splice(0)) spy.mockRestore()
})

function mockCoreQueries() {
  const version = spyOn(api, "getVersion").mockResolvedValue(fixtures.version)
  const config = spyOn(api, "getConfig").mockResolvedValue({
    config: { ...fixtures.config.config, listen_address: "127.0.0.1", listen_port: 3801, log_level: "debug" },
  })
  const outputs = spyOn(api, "getOutputs").mockResolvedValue([entry])
  spies.push(version, config, outputs)
  return { version, config, outputs }
}

const memoryEntry: OutputConfigEntry = outputNamed("inmemory")

function metric(label: string) {
  return within(screen.getByText(label, { selector: "dt" }).parentElement!).getByRole("definition")
}

function statusBadge(state: string) {
  return screen.getByText(state, { selector: "[data-status]" })
}

function sink(name: string) {
  return { kind: "sink", name } as const
}

function mockOutputTypes() {
  spies.push(spyOn(api, "getOutputTypes").mockResolvedValue((fixtures.outputTypes.types ?? []) as OutputType[]))
}

describe("problemOf", () => {
  test.each([
    { error: "", warning: "", want: null },
    { error: "loki send: connection refused", warning: "", want: { main: "loki send: connection refused" } },
    {
      error: "loki send: connection refused",
      warning: "health check failed before start: loki send: connection refused",
      want: { main: "loki send: connection refused" },
    },
    {
      error: "loki send: 429 too many requests",
      warning: "health check failed before start: dial tcp: lookup loki: no such host",
      want: { main: "loki send: 429 too many requests", extra: "health check failed before start: dial tcp: lookup loki: no such host" },
    },
    { error: "", warning: "version 4 not applied: hosts: must be a valid URL", want: { main: "version 4 not applied: hosts: must be a valid URL" } },
  ])("error $error, warning $warning", ({ error, warning, want }) => {
    expect(problemOf({ ...delivering, last_error: error, last_warning: warning })).toEqual(want)
  })
})

describe("PipelineDetailPanel", () => {
  test("names the output by its driver, shows its origin and the real counters", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={delivering} />)
    expect(screen.getByRole("heading", { level: 2, name: "webhook" })).toBeInTheDocument()
    expect(screen.getByText("API provisioned")).toBeInTheDocument()
    expect(document.querySelector('[data-driver="webhook"]')).not.toBeNull()
    expect(metric("Sent")).toHaveTextContent("3")
    expect(metric("Rate")).toHaveTextContent("3 events/min")
    expect(metric("Circuit breaker")).toHaveTextContent("closed")
    expect(within(metric("Last delivery")).getByRole("time")).toBeInTheDocument()
    expect(metric("Queue")).toHaveTextContent("0 / 100")
    expect(screen.queryByRole("alert")).toBeNull()
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument()
  })

  test("a long error is cut to a few lines and can be shown whole", () => {
    const long = `loki send: ${"x".repeat(400)}`
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={{ ...failing, last_error: long }} />)
    expect(screen.getByText(long)).toHaveClass("line-clamp-4")
    fireEvent.click(screen.getByRole("button", { name: "Show the full error" }))
    expect(screen.getByText(long)).not.toHaveClass("line-clamp-4")
    expect(screen.getByRole("button", { name: "Show less" })).toBeInTheDocument()
  })

  test("the output the UI reads events from says so", async () => {
    spies.push(
      spyOn(api, "getConfig").mockResolvedValue({
        config: { ...fixtures.config.config, ui: { enabled: true, event_source: "inmemory" } },
      }),
    )
    spies.push(spyOn(api, "countEvents").mockResolvedValue(0))
    const { rerender } = renderWithProviders(<PipelineDetailPanel selection={sink("inmemory")} entry={memoryEntry} status={null} />)
    expect(await screen.findByText("The Events page and the dashboard read events from this output.")).toBeInTheDocument()
    rerender(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={delivering} />)
    expect(screen.queryByText("The Events page and the dashboard read events from this output.")).toBeNull()
  })

  test("a provisioned output says it is file provisioned", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("inmemory")} entry={memoryEntry} status={null} />)
    expect(screen.getByText("File provisioned")).toBeInTheDocument()
  })

  test("an output that never delivered shows one problem, never and its failures", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={failing} />)
    expect(statusBadge("error")).toBeInTheDocument()
    expect(metric("Failed")).toHaveTextContent("3")
    expect(metric("Failed")).toHaveClass("text-status-error-foreground")
    expect(metric("Last delivery")).toHaveTextContent("never")
    const problem = screen.getByRole("alert")
    expect(within(problem).getByText("Not delivering")).toBeInTheDocument()
    expect(within(problem).getByText(failing.last_error)).toHaveClass("[overflow-wrap:anywhere]")
  })

  test("an output that is not running says so for its circuit", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("alertmanager")} entry={outputNamed("alertmanager")} status={statusNamed("alertmanager")} />)
    expect(statusBadge("failed")).toBeInTheDocument()
    expect(metric("Circuit breaker")).toHaveTextContent("not running")
    expect(metric("Queue")).toHaveTextContent("0 / 0")
  })

  test("a degraded output that still delivers shows its warning as the problem, not an error", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={{
      ...delivering, status: "degraded",
      last_warning: "health check failed before start: connection refused",
    }} />)
    expect(statusBadge("degraded")).toBeInTheDocument()
    const problem = screen.getByRole("alert")
    expect(within(problem).getByText("Needs a look")).toBeInTheDocument()
    expect(within(problem).getByText("health check failed before start: connection refused")).toBeInTheDocument()
    expect(within(problem).queryByText("Not delivering")).toBeNull()
  })

  test("the configuration shows what is set by default, every field with its default on request", async () => {
    mockOutputTypes()
    renderWithProviders(<PipelineDetailPanel
      selection={sink("webhook")}
      entry={{ ...entry, secret_fields: { "/headers/X-Api-Key/secrets": false, "/password": true } }}
      status={delivering}
    />)
    const value = (label: string) => screen.getByText(label, { selector: "dt" }).nextElementSibling as HTMLElement
    expect(await screen.findByRole("heading", { level: 3, name: "Configuration" })).toBeInTheDocument()
    expect(value("Host (scheme, host and port)")).toHaveTextContent("http://127.0.0.1:2899")
    expect(value("Endpoint")).toHaveTextContent("/events")
    expect(value("Password (Basic Auth)")).toHaveTextContent("stored, hidden")
    expect(value("Custom HTTP Headers")).toHaveTextContent("X-Api-Key→public")
    expect(screen.queryByText("HTTP Method", { selector: "dt" })).toBeNull()
    // Each setting explains itself from the schema description.
    expect(screen.getByRole("button", { name: "About Endpoint" })).toBeInTheDocument()

    fireEvent.click(screen.getByRole("radio", { name: "All fields" }))
    expect(value("HTTP Method")).toHaveTextContent("POSTdefault")
    fireEvent.click(screen.getByRole("button", { name: /Delivery/ }))
    expect(value("Worker Count")).toHaveTextContent("2default")
    expect(value("Host (scheme, host and port)")).not.toHaveTextContent("default")
  })

  test("sections expand and collapse together and start over for another output", async () => {
    mockOutputTypes()
    const { rerender } = renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={delivering} />)
    await screen.findByRole("heading", { level: 3, name: "Configuration" })
    fireEvent.click(screen.getByRole("radio", { name: "All fields" }))
    const triggers = () => screen.getAllByRole("button", { expanded: true })
    fireEvent.click(screen.getByRole("button", { name: /Expand all/ }))
    expect(screen.queryAllByRole("button", { expanded: false })).toHaveLength(0)
    expect(triggers().length).toBeGreaterThan(2)
    fireEvent.click(screen.getByRole("button", { name: /Collapse all/ }))
    expect(screen.queryAllByRole("button", { expanded: true })).toHaveLength(0)

    rerender(<PipelineDetailPanel selection={sink("inmemory")} entry={memoryEntry} status={null} />)
    expect(await screen.findByRole("radio", { name: "Set", checked: true })).toBeInTheDocument()
  })

  test("an output type the catalog does not know falls back to the raw configuration", async () => {
    mockOutputTypes()
    renderWithProviders(<PipelineDetailPanel
      selection={sink("custom")}
      entry={{ ...entry, name: "custom", config: null, secret_fields: { "/enabled": true, "/credentials/token": false } }}
      status={null}
    />)
    expect(await screen.findByText("enabled", { selector: "dt" })).toBeInTheDocument()
    expect(metric("enabled")).toHaveTextContent("Configured")
    expect(screen.getByText("credentials:")).toBeInTheDocument()
    expect(metric("token")).toHaveTextContent("Not configured")
    expect(screen.queryByText("No configuration.")).not.toBeInTheDocument()
    expect(screen.queryByText("Health")).not.toBeInTheDocument()
  })

  test("selection and removed-output empty states remain distinct", () => {
    const { rerender } = renderWithProviders(<PipelineDetailPanel selection={null} entry={null} status={null} />)
    expect(screen.getByText("Select any node in the pipeline to see its details.")).toBeInTheDocument()
    rerender(<PipelineDetailPanel selection={sink("missing")} entry={null} status={null} />)
    expect(screen.getByText("Output not found.")).toBeInTheDocument()
  })

  test("health text uses the dedicated foreground tokens", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={{
      ...delivering, failed_total: 1, dropped_total: 2, queue_depth: 90,
      circuit_state: "open", last_error: "Connection refused",
    }} />)
    expect(metric("Sent")).toHaveClass("text-status-ok-foreground")
    expect(metric("Failed")).toHaveClass("text-status-error-foreground")
    expect(metric("Dropped")).toHaveClass("text-status-degraded-foreground")
    expect(within(metric("Circuit breaker")).getByText("open")).toHaveClass("text-status-degraded-foreground")
  })

  test("headings follow the card title", async () => {
    mockOutputTypes()
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={delivering} />)
    await screen.findByRole("heading", { level: 3, name: "Configuration" })
    expect(screen.getAllByRole("heading").map((h) => `${h.tagName}:${h.textContent}`).slice(0, 2)).toEqual(["H2:webhook", "H3:Configuration"])
  })

  test("Falco shows its recent activity and the settings that connect it, not the listener settings", async () => {
    mockCoreQueries()
    spies.push(
      spyOn(api, "searchEvents").mockResolvedValue({ events: [], total: 0, page: 1, limit: 1 }),
      spyOn(api, "countEventsBy").mockImplementation(async (groupBy): Promise<Record<string, number>> =>
        groupBy === "priority" ? { critical: 2, warning: 5 } : groupBy === "source" ? { syscall: 7, k8s_audit: 1 } : { "node-1": 7, "node-2": 1 },
      ),
    )
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "source" }} entry={null} status={null} />)
    expect(screen.getByRole("heading", { level: 2, name: "Falco" })).toBeInTheDocument()
    expect(await screen.findByText("none yet")).toBeInTheDocument()
    const byPriority = await screen.findByRole("list", { name: "Last hour by priority" })
    expect(within(byPriority).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["priority criticalCRIT 2", "priority warningWARN 5"])
    expect(metric("Last hour")).toHaveTextContent("7")
    expect(metric("Hosts")).toHaveTextContent("2")
    expect(within(screen.getByRole("list", { name: "Sources in the last 24 hours" })).getAllByRole("listitem")).toHaveLength(2)
    expect(await screen.findByText(/url: http:\/\/127\.0\.0\.1:3801\//)).toBeInTheDocument()
    expect(screen.queryByText(fixtures.version.commit)).not.toBeInTheDocument()
  })

  test("Falco activity that cannot be read says so instead of showing zero", async () => {
    mockCoreQueries()
    spies.push(
      spyOn(api, "searchEvents").mockRejectedValue(new ApiError(503, "event source not readable")),
      spyOn(api, "countEventsBy").mockResolvedValue({}),
    )
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "source" }} entry={null} status={null} />)
    expect(await screen.findByText("Activity unavailable")).toBeInTheDocument()
    expect(screen.queryByText("Last hour")).not.toBeInTheDocument()
  })

  test.each([
    { listen_address: "", tls: false, want: "http://<sidekick-host>:2801/" },
    { listen_address: "0.0.0.0", tls: true, want: "https://<sidekick-host>:2801/" },
    { listen_address: "10.0.0.5", tls: false, want: "http://10.0.0.5:2801/" },
    { listen_address: "fd00::1", tls: false, want: "http://[fd00::1]:2801/" },
  ])("the Falco snippet for $listen_address with TLS $tls points at $want", ({ listen_address, tls, want }) => {
    const snippet = falcoSnippet({ listen_address, listen_port: 2801, tls: { ...fixtures.config.config.tls!, enabled: tls } })
    expect(snippet).toContain(`url: ${want}`)
    expect(snippet).toContain("json_output: true")
  })

  test("core details remain loading until their queries resolve", () => {
    mockCoreQueries()
    spies.push(spyOn(api, "getPipelineStatus").mockImplementation(() => new Promise(() => {})))
    const { container } = renderWithProviders(<PipelineDetailPanel selection={{ kind: "core" }} entry={null} status={null} />)
    expect(container.querySelector('[aria-busy="true"]')).not.toBeNull()
    expect(screen.queryByText("Delivering")).not.toBeInTheDocument()
  })

  test("core query failures show the backend text instead of fallback values", async () => {
    mockCoreQueries()
    spies.push(spyOn(api, "getPipelineStatus").mockRejectedValue(new ApiError(503, fixtures.errors.database_not_configured.body.error)))
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "core" }} entry={null} status={null} />)
    expect(await screen.findByText("Unable to load pipeline details")).toBeInTheDocument()
    expect(screen.getByText("database not configured")).toBeInTheDocument()
    expect(screen.queryByText("Delivering")).not.toBeInTheDocument()
  })

  test("core details show live delivery and the outputs that need attention, not the build or settings", async () => {
    mockCoreQueries()
    spies.push(spyOn(api, "getPipelineStatus").mockResolvedValue([failing]))
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "core" }} entry={null} status={null} />)
    expect(await screen.findByText("Delivering")).toBeInTheDocument()
    expect(metric("Delivering")).toHaveTextContent("0 of 1")
    expect(metric("Failed")).toHaveTextContent(String(failing.failed_total))
    const attention = screen.getByRole("list")
    expect(within(attention).getByText("webhook")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /Version and settings/ })).toHaveAttribute("href", "/configuration")
    expect(screen.queryByText(fixtures.version.commit)).not.toBeInTheDocument()
    expect(screen.queryByText("127.0.0.1:3801")).not.toBeInTheDocument()
  })

  test("ring-buffer usage remains loading instead of showing a fabricated zero", () => {
    spies.push(spyOn(api, "countEvents").mockImplementation(() => new Promise(() => {})))
    const { container } = renderWithProviders(<PipelineDetailPanel selection={sink("inmemory")} entry={memoryEntry} status={null} />)
    expect(container.querySelector('[aria-busy="true"]')).not.toBeNull()
    expect(screen.queryByText("0 / 5,000")).not.toBeInTheDocument()
  })

  test("a ring-buffer query failure does not look like an empty buffer", async () => {
    spies.push(spyOn(api, "countEvents").mockRejectedValue(new ApiError(503, "event store not available")))
    renderWithProviders(<PipelineDetailPanel selection={sink("inmemory")} entry={memoryEntry} status={null} />)
    expect(await screen.findByText("Unable to load ring-buffer usage")).toBeInTheDocument()
    expect(screen.getByText("event store not available")).toBeInTheDocument()
    expect(screen.queryByText("0 / 5,000")).not.toBeInTheDocument()
  })

  test.each([0, 5000])("ring-buffer usage renders the measured count %s as a meter", async (count) => {
    spies.push(spyOn(api, "countEvents").mockResolvedValue(count))
    renderWithProviders(<PipelineDetailPanel selection={sink("inmemory")} entry={memoryEntry} status={null} />)
    expect(await screen.findByText(`${count === 0 ? "0" : "5,000"} / 5,000`)).toBeInTheDocument()
    const meter = screen.getByRole("meter", { name: "Events stored" })
    expect(meter).toHaveAttribute("aria-valuenow", String(count))
    expect(meter).toHaveAttribute("aria-valuemax", "5000")
    expect(screen.queryByText(/Oldest events are being overwritten/)).toBe(count === 5000
      ? screen.getByText(/Oldest events are being overwritten/)
      : null)
  })
})
