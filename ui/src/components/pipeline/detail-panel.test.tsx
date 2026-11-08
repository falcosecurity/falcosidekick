import { afterEach, describe, expect, spyOn, test } from "bun:test"

import { api } from "@/lib/api-client"
import { ApiError } from "@/lib/api-error"
import type { OutputConfigEntry, OutputStatus } from "@/lib/types"
import { fixtures, outputNamed, statusNamed } from "@/test/fixtures"
import { cleanup, renderWithProviders, screen, within } from "@/test/test-utils"

import { PipelineDetailPanel } from "./detail-panel"

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

describe("PipelineDetailPanel", () => {
  test("names the output by its driver, shows its origin and the real counters", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={delivering} />)
    expect(screen.getByRole("heading", { level: 2, name: "webhook" })).toBeInTheDocument()
    expect(screen.getByText("created through the API")).toBeInTheDocument()
    expect(document.querySelector('[data-driver="webhook"]')).not.toBeNull()
    expect(metric("Sent")).toHaveTextContent("3")
    expect(metric("Evt/min")).toHaveTextContent("3")
    expect(metric("Circuit")).toHaveTextContent("closed")
    expect(within(metric("Last success")).getByRole("time")).toBeInTheDocument()
    expect(screen.queryByText(/p99/)).toBeNull()
    expect(screen.getByRole("definition", { name: "secrets: secret configured" })).toHaveTextContent("Configured")
    expect(screen.getByText("public")).toBeInTheDocument()
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument()
    expect(screen.getByRole("meter", { name: "Queue webhook" })).toHaveAttribute("aria-valuemax", "100")
  })

  test("a provisioned output says it comes from the output files", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("inmemory")} entry={memoryEntry} status={null} />)
    expect(screen.getByText("from output files")).toBeInTheDocument()
  })

  test("an output that never delivered shows never, its error and a failed state", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={failing} />)
    expect(statusBadge("error")).toBeInTheDocument()
    expect(metric("Failed")).toHaveTextContent("3")
    expect(metric("Failed")).toHaveClass("text-status-error-foreground")
    expect(metric("Last success")).toHaveTextContent("never")
    expect(screen.getByText("Last error")).toHaveClass("text-status-error-foreground")
    expect(screen.getByText(failing.last_error)).toHaveClass("text-status-error-foreground", "[overflow-wrap:anywhere]")
    expect(screen.queryByText("Last warning")).toBeNull()
  })

  test("an output that is not running shows a dash for its circuit", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("alertmanager")} entry={outputNamed("alertmanager")} status={statusNamed("alertmanager")} />)
    expect(statusBadge("failed")).toBeInTheDocument()
    expect(metric("Circuit")).toHaveTextContent("-")
    expect(metric("Queue")).toHaveTextContent("0 / 0")
  })

  test("wires nested secret metadata alongside public output configuration", () => {
    const config = {
      url: "https://example.test/events",
      headers: { "X/Api~Key": { values: ["public"], files: ["/run/secrets/key"] } },
      note: "****",
    }
    renderWithProviders(<PipelineDetailPanel
      selection={sink("webhook")}
      entry={{ ...entry, config, secret_fields: { "/headers/X~1Api~0Key/secrets": false, "/password": true } }}
      status={delivering}
    />)
    const section = screen.getByText("Configuration (masked)").parentElement!
    expect(within(section).getByText("X/Api~Key:")).toBeInTheDocument()
    expect(within(section).getByRole("definition", { name: "secrets: secret not configured" })).toHaveTextContent("Not configured")
    expect(within(section).getByRole("definition", { name: "password: secret configured" })).toHaveTextContent("Configured")
    expect(within(section).getByText("https://example.test/events")).toBeInTheDocument()
    expect(within(section).getByText("/run/secrets/key")).toBeInTheDocument()
    expect(within(section).getByText("****")).toBeInTheDocument()
    expect(Object.hasOwn(config.headers["X/Api~Key"], "secrets")).toBe(false)
  })

  test("shows metadata-only configuration for an output without live status or config", () => {
    renderWithProviders(<PipelineDetailPanel
      selection={sink("custom")}
      entry={{ ...entry, name: "custom", config: null, secret_fields: { "/enabled": true, "/credentials/token": false } }}
      status={null}
    />)
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

  test("a degraded output that still delivers shows its warning wrapped by word, not an error", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={{
      ...delivering, status: "degraded",
      last_warning: "health check failed before start: connection refused",
    }} />)
    expect(statusBadge("degraded")).toBeInTheDocument()
    expect(screen.getByText("Last warning")).toHaveClass("text-status-degraded-foreground")
    const warning = screen.getByText("health check failed before start: connection refused")
    expect(warning).toHaveClass("text-status-degraded-foreground", "[overflow-wrap:anywhere]")
    expect(warning).not.toHaveClass("break-all")
    expect(screen.queryByText("Last error")).toBeNull()
  })

  test("health text uses the dedicated foreground tokens", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={{
      ...delivering, failed_total: 1, dropped_total: 2, queue_depth: 90,
      circuit_state: "open", last_error: "Connection refused",
    }} />)
    expect(metric("Sent")).toHaveClass("text-status-ok-foreground")
    expect(metric("Failed")).toHaveClass("text-status-error-foreground")
    expect(metric("Dropped")).toHaveClass("text-status-degraded-foreground")
    expect(metric("Queue")).toHaveClass("text-status-degraded-foreground")
    expect(metric("Circuit")).toHaveClass("text-status-degraded-foreground")
    expect(screen.getByText("Connection refused")).toHaveClass("text-status-error-foreground")
  })

  test("headings follow the card title", () => {
    renderWithProviders(<PipelineDetailPanel selection={sink("webhook")} entry={entry} status={delivering} />)
    expect(screen.getAllByRole("heading").map((h) => `${h.tagName}:${h.textContent}`)).toEqual([
      "H2:webhook", "H3:Health", "H3:Configuration (masked)",
    ])
  })

  test("source selection shows the ingestion endpoint without output controls", () => {
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "source" }} entry={null} status={null} />)
    expect(screen.getByRole("heading", { level: 2, name: "Falco" })).toBeInTheDocument()
    expect(screen.getAllByText("POST /")).toHaveLength(2)
    expect(screen.queryByText("Configuration (masked)")).not.toBeInTheDocument()
  })

  test("core details remain loading until their queries resolve", () => {
    const { version } = mockCoreQueries()
    version.mockImplementation(() => new Promise(() => {}))
    const { container } = renderWithProviders(<PipelineDetailPanel selection={{ kind: "core" }} entry={null} status={null} />)
    expect(container.querySelector('[aria-busy="true"]')).not.toBeNull()
    expect(screen.queryByText(":2801")).not.toBeInTheDocument()
    expect(screen.queryByText("Outputs")).not.toBeInTheDocument()
  })

  test("core query failures show the backend text instead of fallback runtime values", async () => {
    const { config } = mockCoreQueries()
    config.mockRejectedValue(new ApiError(503, fixtures.errors.database_not_configured.body.error))
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "core" }} entry={null} status={null} />)
    expect(await screen.findByText("Unable to load pipeline details")).toBeInTheDocument()
    expect(screen.getByText("database not configured")).toBeInTheDocument()
    expect(screen.queryByText(":2801")).not.toBeInTheDocument()
  })

  test("core details display the build as reported and the runtime configuration", async () => {
    mockCoreQueries()
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "core" }} entry={null} status={null} />)
    expect(await screen.findByText(fixtures.version.version)).toBeInTheDocument()
    expect(screen.getByText(fixtures.version.commit)).toBeInTheDocument()
    expect(screen.getByText(fixtures.version.go_version)).toBeInTheDocument()
    expect(screen.getByText("127.0.0.1:3801")).toBeInTheDocument()
    expect(screen.getByText("inmemory")).toBeInTheDocument()
    expect(screen.getByText("debug")).toBeInTheDocument()
    expect(screen.getByText("1", { selector: "dd" })).toBeInTheDocument()
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
