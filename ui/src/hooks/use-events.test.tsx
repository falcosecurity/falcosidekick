import { afterEach, describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import type { InternalAxiosRequestConfig } from "axios"

import { setApiAdapterForTests } from "@/lib/api-client"
import { useUIStore } from "@/stores/ui-store"
import { fixtureAdapter } from "@/test/fixtures"
import { cleanup, renderWithProviders, screen, waitFor } from "@/test/test-utils"

import { useSearchEvents } from "./use-events"

afterEach(() => {
  cleanup()
  setApiAdapterForTests(null)
  useUIStore.setState({ eventsLive: false })
})

function Probe({ rule }: { rule: string }) {
  const { data } = useSearchEvents({ rule: [rule], limit: 50 })
  return <p>{data ? `loaded ${rule}` : "loading"}</p>
}

const searches = (calls: InternalAxiosRequestConfig[], rule: string) =>
  calls.filter((c) => c.url === "/events/search" && JSON.stringify(c.params ?? c.data).includes(rule)).length

describe("useSearchEvents", () => {
  test("with Live off it never polls, yet filters visited again are read again", async () => {
    useUIStore.setState({ eventsLive: false })
    const calls: InternalAxiosRequestConfig[] = []
    setApiAdapterForTests(fixtureAdapter(calls))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 60_000 } } })
    const { rerender } = renderWithProviders(<Probe rule="A" />, { queryClient: client })
    await screen.findByText("loaded A")
    rerender(<Probe rule="B" />)
    await screen.findByText("loaded B")
    rerender(<Probe rule="A" />)
    await waitFor(() => expect(searches(calls, "A")).toBe(2))
    expect(searches(calls, "B")).toBe(1)

    const observers = client.getQueryCache().findAll({ queryKey: ["events", "search"] }).flatMap((q) => q.observers)
    expect(observers.every((o) => o.options.refetchInterval === false && o.options.refetchOnWindowFocus === false)).toBe(true)
  })

  test("with Live on it follows the refresh interval", async () => {
    useUIStore.setState({ eventsLive: true })
    setApiAdapterForTests(fixtureAdapter())
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    renderWithProviders(<Probe rule="A" />, { queryClient: client })
    await screen.findByText("loaded A")
    const observers = client.getQueryCache().findAll({ queryKey: ["events", "search"] }).flatMap((q) => q.observers)
    expect(observers.length).toBeGreaterThan(0)
    expect(observers.every((o) => typeof o.options.refetchInterval === "number" && o.options.refetchInterval > 0)).toBe(true)
    expect(observers.every((o) => o.options.refetchOnWindowFocus === true)).toBe(true)
  })
})
