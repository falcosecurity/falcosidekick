import { afterEach, describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"

import { PRIORITIES, PRIORITY_LABELS } from "@/lib/types"
import { cleanup, renderWithProviders, screen, within } from "@/test/test-utils"

import { CounterCards } from "./counter-cards"

const clients: QueryClient[] = []
const queryKey = ["events", "count-by", "priority", { since: "24h" }]

function renderCounters(counts?: Record<string, number>, error?: Error) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { enabled: false, retry: false, gcTime: 0 } },
  })
  clients.push(queryClient)
  if (counts) queryClient.setQueryData(queryKey, counts)
  if (error) {
    queryClient.getQueryCache().build(queryClient, { queryKey }).setState({ status: "error", error })
  }
  return renderWithProviders(<CounterCards />, { queryClient })
}

afterEach(() => {
  cleanup()
  for (const client of clients.splice(0)) client.clear()
})

describe("CounterCards", () => {
  test("renders one labelled tile per priority with readable foregrounds and priority borders", () => {
    renderCounters(Object.fromEntries(PRIORITIES.map((priority, index) => [priority, index + 1])))
    const list = screen.getAllByRole("term")[0]!.closest("dl")!
    expect(within(list).getAllByRole("term").map((t) => t.textContent)).toEqual(PRIORITIES.map((p) => PRIORITY_LABELS[p]))
    for (const [index, priority] of PRIORITIES.entries()) {
      const token = priority === "informational" ? "info" : priority
      const value = screen.getByText(String(index + 1))
      expect(value).toHaveClass(`text-priority-${token}-foreground`)
      expect(value.parentElement).toHaveClass(`border-l-priority-${token}`)
    }
  })

  test("shows a loading skeleton for every priority", () => {
    renderCounters()
    expect(screen.getAllByRole("status")).toHaveLength(PRIORITIES.length)
    for (const skeleton of screen.getAllByRole("status")) {
      expect(skeleton).toHaveAttribute("aria-busy", "true")
    }
  })

  test("distinguishes failed requests from zero counts and names the cause", () => {
    renderCounters(undefined, new Error("event store not available"))
    expect(screen.getByText("Unable to load event counts: event store not available")).toBeInTheDocument()
    expect(screen.queryByText("0")).toBeNull()
  })

  test("renders zero for priorities absent from an empty response", () => {
    renderCounters({})
    expect(screen.getAllByText("0")).toHaveLength(PRIORITIES.length)
  })
})
