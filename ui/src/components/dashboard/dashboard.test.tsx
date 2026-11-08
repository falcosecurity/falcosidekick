import { afterEach, describe, expect, test } from "bun:test"
import type { InternalAxiosRequestConfig } from "axios"

import { setApiAdapterForTests } from "@/lib/api-client"
import type { HistogramResult, OutputStatus } from "@/lib/types"
import { fixtureAdapter, fixtures, routeKey } from "@/test/fixtures"
import { cleanup, fireEvent, renderWithProviders, screen, waitFor, within } from "@/test/test-utils"

import { AttentionCard, byAttention, needsAttention, queueTone } from "./attention"
import { DeliveryCard } from "./delivery-card"
import { KpiCards } from "./kpi-cards"
import { SeverityCard } from "./severity-card"
import { TopCard } from "./top-card"

afterEach(() => {
  cleanup()
  setApiAdapterForTests(null)
})

const HOUR = 3_600_000
const T0 = Date.UTC(2026, 10, 8, 10)

function histogram(buckets: Record<string, number>[]): HistogramResult {
  return {
    group_by: "priority",
    bucket_ms: HOUR,
    from: T0,
    to: T0 + buckets.length * HOUR,
    buckets: buckets.map((by, i) => ({ t: T0 + i * HOUR, count: Object.values(by).reduce((a, b) => a + b, 0), by })),
  }
}

function status(name: string, change: Partial<OutputStatus> = {}): OutputStatus {
  return {
    name,
    status: "ok",
    circuit_state: "closed",
    last_success: "2026-11-08T11:00:00Z",
    last_error: "",
    last_warning: "",
    queue_depth: 0,
    queue_capacity: 100,
    sent_total: 10,
    dropped_total: 0,
    failed_total: 0,
    events_per_minute: 4,
    ...change,
  }
}

/** Fixture routes with overrides; histograms and counts answer by their query. */
function serve(overrides: Record<string, (config: InternalAxiosRequestConfig) => unknown>) {
  const calls: InternalAxiosRequestConfig[] = []
  const base = fixtureAdapter(calls)
  setApiAdapterForTests(async (config) => {
    const handler = overrides[routeKey(config)]
    if (!handler) return base(config)
    calls.push(config)
    return { data: handler(config), status: 200, statusText: "OK", headers: {}, config }
  })
  return calls
}

describe("attention rules", () => {
  test.each([
    { depth: 0, capacity: 100, tone: "neutral" },
    { depth: 10, capacity: 0, tone: "neutral" },
    { depth: 75, capacity: 100, tone: "neutral" },
    { depth: 76, capacity: 100, tone: "warning" },
    { depth: 120, capacity: 100, tone: "warning" },
  ])("queue $depth/$capacity is $tone", ({ depth, capacity, tone }) => {
    expect(queueTone(depth, capacity)).toBe(tone)
  })

  test("an output needs attention when it does not deliver or its queue fills up, and comes first", () => {
    const list = [status("b"), status("a", { status: "error" }), status("c", { queue_depth: 90 }), status("d", { status: "idle" })]
    expect(list.filter(needsAttention).map((s) => s.name)).toEqual(["a", "c"])
    expect(byAttention(list).map((s) => s.name)).toEqual(["a", "c", "b", "d"])
  })
})

describe("AttentionCard", () => {
  test("lists critical events and failing outputs with their errors, linking to where to act", async () => {
    serve({
      "GET /events/count/priority": () => ({ groups: { emergency: 1, critical: 2, warning: 9 } }),
      "GET /pipeline/status": () => ({ outputs: [status("webhook", { status: "error", last_error: "connection refused", queue_depth: 7 }), status("slack")] }),
    })
    renderWithProviders(<AttentionCard />)
    const critical = await screen.findByRole("link", { name: /3 critical or worse events in the last hour/ })
    expect(critical).toHaveAttribute("href", "/events?priority=emergency&priority=alert&priority=critical&since=1h")
    const webhook = screen.getByRole("link", { name: /webhook is not delivering/ })
    expect(webhook).toHaveTextContent("connection refused · 7 of 100 queued")
    expect(webhook).toHaveAttribute("href", "/pipeline")
    expect(screen.queryByRole("link", { name: /slack/ })).toBeNull()
    expect(screen.getByText("2")).toBeInTheDocument()
  })

  test("says all clear when nothing needs attention", async () => {
    serve({
      "GET /events/count/priority": () => ({ groups: { warning: 4 } }),
      "GET /pipeline/status": () => ({ outputs: [status("slack")] }),
    })
    renderWithProviders(<AttentionCard />)
    expect(await screen.findByText("All clear")).toBeInTheDocument()
  })
})

describe("KpiCards", () => {
  test("compares the last hour with the one before and counts healthy outputs", async () => {
    serve({
      "GET /events/histogram": () => histogram([{ critical: 2, notice: 8 }, { alert: 3, notice: 12 }]),
      "GET /events/count/priority": () => ({ groups: { notice: 40, warning: 2 } }),
      "GET /pipeline/status": () => ({ outputs: [status("a"), status("b", { status: "failed" })] }),
    })
    renderWithProviders(<KpiCards />)
    const card = (label: string) => screen.getByText(label).closest("[data-slot=card]") as HTMLElement
    await waitFor(() => expect(within(card("Events, last hour")).getByText("15")).toBeInTheDocument())
    expect(within(card("Events, last hour")).getByText("+50%")).toBeInTheDocument()
    expect(within(card("Events, last hour")).getByText("10 the hour before")).toBeInTheDocument()
    expect(within(card("Critical or worse, last hour")).getByText("3")).toBeInTheDocument()
    expect(within(card("Critical or worse, last hour")).getByText("+50%")).toBeInTheDocument()
    expect(within(card("Outputs delivering")).getByText("1 of 2")).toBeInTheDocument()
    expect(within(card("Outputs delivering")).getByText("1 need attention")).toBeInTheDocument()
    expect(within(card("Events, last 24 hours")).getByText("42")).toBeInTheDocument()
  })
})

describe("SeverityCard", () => {
  test("totals each severity tier over the window and switches windows", async () => {
    const calls = serve({
      "GET /events/histogram": () => histogram([{ emergency: 1, alert: 1, notice: 5 }, { critical: 2, error: 3, informational: 1, debug: 1 }]),
    })
    renderWithProviders(<SeverityCard />)
    expect(await screen.findByText("14")).toBeInTheDocument()
    const legend = (label: string) => screen.getByText(label).parentElement as HTMLElement
    expect(legend("Critical+")).toHaveTextContent("4")
    expect(legend("Error")).toHaveTextContent("3")
    expect(legend("Warning")).toHaveTextContent("0")
    expect(legend("Notice")).toHaveTextContent("5")
    expect(legend("Info & debug")).toHaveTextContent("2")
    fireEvent.click(screen.getByRole("radio", { name: "24h" }))
    const param = (c: InternalAxiosRequestConfig, key: string) => (c.params as URLSearchParams).get(key)
    await waitFor(() =>
      expect(calls.some((c) => param(c, "since") === "24h" && param(c, "group_by") === "priority" && param(c, "bucket_ms") === String(HOUR / 2))).toBe(true),
    )
  })
})

describe("DeliveryCard", () => {
  test("shows every output, the failing one first, with its counters", async () => {
    serve({})
    renderWithProviders(<DeliveryCard />)
    const rows = await screen.findAllByRole("row")
    const names = rows.slice(1).map((r) => within(r).getAllByRole("cell")[0]!.textContent)
    expect(names).toEqual(["alertmanager", "webhook", "inmemory"])
    expect(fixtures.pipelineStatus.outputs!.length).toBe(3)
  })
})

describe("TopCard", () => {
  test("ranks rules and switches to hosts", async () => {
    const calls = serve({
      "GET /events/count/rule": () => ({ groups: { "Write below etc": 2, "Terminal shell in container": 9 } }),
      "GET /events/count/hostname": () => ({ groups: { "node-1": 3 } }),
    })
    renderWithProviders(<TopCard />)
    const links = await screen.findAllByRole("link")
    expect(links.map((l) => l.textContent)).toEqual(["Terminal shell in container9", "Write below etc2"])
    expect(links[0]).toHaveAttribute("href", "/events?rule=Terminal%20shell%20in%20container&since=24h")
    fireEvent.click(screen.getByRole("radio", { name: "Hosts" }))
    expect(await screen.findByRole("link", { name: /node-1/ })).toHaveAttribute("href", "/events?hostname=node-1&since=24h")
    expect(screen.getByText("Top hosts")).toBeInTheDocument()
    expect(calls.some((c) => c.url === "/events/count/hostname")).toBe(true)
  })
})
