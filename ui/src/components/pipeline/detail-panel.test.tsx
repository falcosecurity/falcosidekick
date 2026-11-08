import { afterEach, describe, expect, spyOn, test } from "bun:test"

import { api } from "@/lib/api-client"
import type { OutputConfigEntry, OutputStatus } from "@/lib/types"
import { cleanup, renderWithProviders, screen, within } from "@/test/test-utils"

import { PipelineDetailPanel } from "./detail-panel"

const entry: OutputConfigEntry = {
  name: "alerts", type: "webhook", config: {}, secret_fields: { "/password": true },
  provisioned: true, version: 1, updated_at: "",
}
const status: OutputStatus = {
  name: "alerts", status: "ok", queue_depth: 3, queue_capacity: 100,
  sent_total: 42, failed_total: 0, dropped_total: 0,
  circuit_state: "closed", last_success: "", last_error: "",
}

const spies: Array<{ mockRestore: () => void }> = []

afterEach(() => {
  cleanup()
  for (const spy of spies.splice(0)) spy.mockRestore()
})

function mockCoreQueries() {
  const version = spyOn(api, "getVersion").mockResolvedValue({ version: "3.0.0-beta.1", commit: "abc123" })
  const config = spyOn(api, "getConfig").mockResolvedValue({
    config: { listen_address: "127.0.0.1", listen_port: 3801, log_level: "debug", database: { backend: "inmemory" } },
    version: 1, updated_at: "",
  })
  const outputs = spyOn(api, "getOutputs").mockResolvedValue([entry])
  spies.push(version, config, outputs)
  return { version, config, outputs }
}

const memoryEntry: OutputConfigEntry = { ...entry, name: "inmemory", type: "inmemory", config: { capacity: 100 } }

function metric(label: string) {
  return within(screen.getByText(label, { selector: "dt" }).parentElement!).getByRole("definition")
}

describe("PipelineDetailPanel", () => {
  test("does not fabricate a zero p99 latency when the backend omits the metric", () => {
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "sink", name: "alerts" }} entry={entry} status={status} />)
    expect(metric("p99 latency")).toHaveTextContent("Not available")
    expect(metric("Sent")).toHaveTextContent("42")
    expect(screen.getByRole("definition", { name: "password: secret configured" })).toHaveTextContent("Configured")
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument()
  })

  test("wires nested secret metadata alongside public output configuration", () => {
    const config = {
      url: "https://example.test/events",
      headers: { "X/Api~Key": { values: ["public"], files: ["/run/secrets/key"] } },
      note: "****",
    }
    renderWithProviders(<PipelineDetailPanel
      selection={{ kind: "sink", name: "alerts" }}
      entry={{ ...entry, config, secret_fields: { "/headers/X~1Api~0Key/secrets": false, "/password": true } }}
      status={status}
    />)
    const section = screen.getByText("Configuration (masked)").parentElement!
    expect(within(section).getByText("X/Api~Key:")).toBeInTheDocument()
    expect(within(section).getByRole("definition", { name: "secrets: secret not configured" })).toHaveTextContent("Not configured")
    expect(within(section).getByRole("definition", { name: "password: secret configured" })).toHaveTextContent("Configured")
    expect(within(section).getByText("https://example.test/events")).toBeInTheDocument()
    expect(within(section).getByText("public")).toBeInTheDocument()
    expect(within(section).getByText("/run/secrets/key")).toBeInTheDocument()
    expect(within(section).getByText("****")).toBeInTheDocument()
    expect(within(section).queryByRole("textbox")).not.toBeInTheDocument()
    expect(Object.hasOwn(config.headers["X/Api~Key"], "secrets")).toBe(false)
  })

  test("shows metadata-only configuration for an unknown output without live status", () => {
    renderWithProviders(<PipelineDetailPanel
      selection={{ kind: "sink", name: "custom" }}
      entry={{ ...entry, name: "custom", type: "unknown", config: {}, secret_fields: { "/enabled": true, "/credentials/token": false } }}
      status={null}
    />)
    expect(metric("enabled")).toHaveTextContent("Configured")
    expect(screen.getByText("credentials:")).toBeInTheDocument()
    expect(metric("token")).toHaveTextContent("Not configured")
    expect(screen.queryByText("No configuration.")).not.toBeInTheDocument()
    expect(screen.queryByText("Health")).not.toBeInTheDocument()
  })

  test.each([[0, "0ms"], [125, "125ms"], [1500, "1.50s"]] as const)("renders a supplied p99 measurement of %s ms", (latency, expected) => {
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "sink", name: "alerts" }} entry={entry} status={{ ...status, send_latency_p99_ms: latency }} />)
    expect(metric("p99 latency")).toHaveTextContent(expected)
  })

  test("selection and removed-output empty states remain distinct", () => {
    const { rerender } = renderWithProviders(<PipelineDetailPanel selection={null} entry={null} status={null} />)
    expect(screen.getByText("Select any node in the pipeline to see its details.")).toBeInTheDocument()
    rerender(<PipelineDetailPanel selection={{ kind: "sink", name: "missing" }} entry={null} status={null} />)
    expect(screen.getByText("Output not found.")).toBeInTheDocument()
    expect(screen.queryByText("p99 latency")).not.toBeInTheDocument()
  })

  test("missing status never fabricates health counters", () => {
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "sink", name: "alerts" }} entry={entry} status={null} />)
    expect(screen.queryByText("Health")).not.toBeInTheDocument()
    expect(screen.getByText("Configuration (masked)")).toBeInTheDocument()
  })

  test("an output failure is visible alongside its counters and masked configuration", () => {
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "sink", name: "alerts" }} entry={entry} status={{ ...status, status: "error", failed_total: 4, last_error: "Connection refused" }} />)
    expect(screen.getByLabelText("status error")).toBeInTheDocument()
    expect(metric("Failed")).toHaveTextContent("4")
    expect(screen.getByText("Connection refused")).toBeInTheDocument()
  })

  test("health text uses the dedicated foreground tokens", () => {
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "sink", name: "alerts" }} entry={entry} status={{
      ...status, failed_total: 1, dropped_total: 2, queue_depth: 90,
      circuit_state: "open", last_error: "Connection refused",
    }} />)
    expect(metric("Sent")).toHaveClass("text-status-ok-foreground")
    expect(metric("Failed")).toHaveClass("text-status-error-foreground")
    expect(metric("Dropped")).toHaveClass("text-status-degraded-foreground")
    expect(metric("Queue")).toHaveClass("text-status-degraded-foreground")
    expect(metric("Circuit")).toHaveClass("text-status-degraded-foreground")
    expect(screen.getByText("Last error")).toHaveClass("text-status-error-foreground")
    expect(screen.getByText("Connection refused")).toHaveClass("text-status-error-foreground")
  })

  test("source selection shows the ingestion endpoint without output controls", () => {
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "source" }} entry={null} status={null} />)
    expect(screen.getByText("Falco")).toBeInTheDocument()
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

  test("core query failures are explicit instead of displaying fallback runtime values", async () => {
    const { config } = mockCoreQueries()
    config.mockRejectedValue(new Error("Service unavailable"))
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "core" }} entry={null} status={null} />)
    expect(await screen.findByText("Unable to load pipeline details")).toBeInTheDocument()
    expect(screen.queryByText(":2801")).not.toBeInTheDocument()
  })

  test("core details display the resolved build and runtime configuration", async () => {
    mockCoreQueries()
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "core" }} entry={null} status={null} />)
    expect(await screen.findByText("3.0.0-beta.1")).toBeInTheDocument()
    expect(screen.getByText("abc123")).toBeInTheDocument()
    expect(screen.getByText("127.0.0.1:3801")).toBeInTheDocument()
    expect(screen.getByText("inmemory")).toBeInTheDocument()
    expect(screen.getByText("debug")).toBeInTheDocument()
    expect(screen.getByText("1", { selector: "dd" })).toBeInTheDocument()
  })

  test("ring-buffer usage remains loading instead of showing a fabricated zero", () => {
    spies.push(spyOn(api, "countEvents").mockImplementation(() => new Promise(() => {})))
    const { container } = renderWithProviders(<PipelineDetailPanel selection={{ kind: "sink", name: "inmemory" }} entry={memoryEntry} status={null} />)
    expect(container.querySelector('[aria-busy="true"]')).not.toBeNull()
    expect(screen.queryByText("0 / 100")).not.toBeInTheDocument()
  })

  test("a ring-buffer query failure does not look like an empty buffer", async () => {
    spies.push(spyOn(api, "countEvents").mockRejectedValue(new Error("Service unavailable")))
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "sink", name: "inmemory" }} entry={memoryEntry} status={null} />)
    expect(await screen.findByText("Unable to load ring-buffer usage")).toBeInTheDocument()
    expect(screen.queryByText("0 / 100")).not.toBeInTheDocument()
  })

  test.each([0, 100])("ring-buffer usage renders the measured count %s", async (count) => {
    spies.push(spyOn(api, "countEvents").mockResolvedValue(count))
    renderWithProviders(<PipelineDetailPanel selection={{ kind: "sink", name: "inmemory" }} entry={memoryEntry} status={null} />)
    expect(await screen.findByText(`${count} / 100`)).toBeInTheDocument()
    expect(screen.queryByText(/Oldest events are being overwritten/)).toBe(count === 100
      ? screen.getByText(/Oldest events are being overwritten/)
      : null)
  })
})
