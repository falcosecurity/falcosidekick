import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import userEvent from "@testing-library/user-event"

import { api } from "@/lib/api-client"
import type { Event, SearchResult } from "@/lib/types"
import {
  act,
  cleanup,
  fireEvent,
  renderWithProviders,
  screen,
  waitFor,
  within,
} from "@/test/test-utils"

import { EventsPage } from "./events"

const event: Event = {
  uuid: "events-page-1",
  rule: "Read Sensitive File",
  priority: "warning",
  source: "syscall",
  time: "2026-10-05T12:00:00Z",
  output: "A process read a sensitive file",
  output_fields: {},
}

const result: SearchResult = { events: [event], total: 1, page: 1, limit: 50 }
const empty: SearchResult = { ...result, events: [], total: 0 }
let search: ReturnType<typeof spyOn<typeof api, "searchEvents">>
let counts: ReturnType<typeof spyOn<typeof api, "countEventsBy">>

beforeEach(() => {
  search = spyOn(api, "searchEvents").mockResolvedValue(result)
  counts = spyOn(api, "countEventsBy").mockResolvedValue({})
})

afterEach(() => {
  cleanup()
  search.mockRestore()
  counts.mockRestore()
})

describe("EventsPage", () => {
  test("shows loading state until the request completes", async () => {
    const pending = Promise.withResolvers<SearchResult>()
    search.mockReturnValue(pending.promise)
    renderWithProviders(<EventsPage />)

    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true")
    expect(screen.getByRole("button", { name: "Refresh" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()

    await act(async () => pending.resolve(result))
    expect(await screen.findByRole("table")).toBeInTheDocument()
    expect(screen.queryByRole("status")).not.toBeInTheDocument()
  })

  test("shows empty results without a drawer or next page", async () => {
    search.mockResolvedValue(empty)
    renderWithProviders(<EventsPage />)

    expect(await screen.findByText("No events match")).toBeInTheDocument()
    expect(screen.getByText("0 events")).toBeInTheDocument()
    expect(screen.queryByRole("table")).not.toBeInTheDocument()
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  })

  test("shows request errors and recovers on retry", async () => {
    const user = userEvent.setup()
    search.mockRejectedValueOnce(new Error("Event store unavailable"))
    renderWithProviders(<EventsPage />)

    expect(await screen.findByText("Unable to load events")).toBeInTheDocument()
    expect(screen.getByText("Event store unavailable")).toBeInTheDocument()
    expect(screen.queryByText(/^Loading/) === null).toBe(true)
    await user.click(screen.getByRole("button", { name: "Retry" }))

    expect(await screen.findByRole("table")).toBeInTheDocument()
    expect(screen.queryByText("Unable to load events")).not.toBeInTheDocument()
  })

  test.each(["[Enter]", " "])("opens from a row with %s and returns focus on Escape", async (key) => {
    const user = userEvent.setup()
    renderWithProviders(<EventsPage />)
    const row = await screen.findByRole("row", { name: `Event ${event.rule} priority warning` })
    row.focus()
    await user.keyboard(key)

    const dialog = await screen.findByRole("dialog", { name: event.rule })
    await waitFor(() => expect(document.activeElement === within(dialog).getByRole("button", { name: "Close" })).toBe(true))
    await user.keyboard("[Escape]")

    await waitFor(() => expect(document.activeElement === row).toBe(true))
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
  })

  test("returns focus to the clicked row even if it did not have focus", async () => {
    const user = userEvent.setup()
    renderWithProviders(<EventsPage />)
    const row = await screen.findByRole("row", { name: `Event ${event.rule} priority warning` })
    screen.getByRole("button", { name: "Refresh" }).focus()
    fireEvent.click(row)
    await screen.findByRole("dialog")
    await user.keyboard("[Escape]")

    await waitFor(() => expect(document.activeElement === row).toBe(true))
  })

  test("restores focus to the results region when a refreshed result removes the opening row", async () => {
    const user = userEvent.setup()
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
    renderWithProviders(<EventsPage />, { queryClient: client })
    const row = await screen.findByRole("row", { name: `Event ${event.rule} priority warning` })
    await user.click(row)
    await screen.findByRole("dialog")
    act(() => { client.setQueriesData({ queryKey: ["events", "search"] }, empty) })
    await waitFor(() => expect(row.isConnected).toBe(false))
    await user.keyboard("[Escape]")

    await waitFor(() => {
      expect(document.activeElement === screen.getByRole("region", { name: "Event results" })).toBe(true)
    })
  })

  test("exposes sort direction and a keyboard focus indicator", async () => {
    const user = userEvent.setup()
    renderWithProviders(<EventsPage />, { initialEntries: ["/events?page=2&rule=Read+Sensitive+File"] })
    const table = await screen.findByRole("table")
    const rule = within(table).getByRole("button", { name: "Rule" })
    expect(rule).toHaveClass("focus-visible:outline-2", "focus-visible:outline-ring")
    expect(within(table).getByRole("columnheader", { name: "Time" })).toHaveAttribute("aria-sort", "descending")
    rule.focus()
    await user.keyboard("[Enter]")

    await waitFor(() => expect(search.mock.calls.at(-1)?.[0]).toMatchObject({
      page: 1, rule: ["Read Sensitive File"], sort_by: "rule", sort_desc: true,
    }))
    expect(within(table).getByRole("columnheader", { name: "Rule" })).toHaveAttribute("aria-sort", "descending")
    await user.keyboard("[Enter]")
    await waitFor(() => expect(search.mock.calls.at(-1)?.[0].sort_desc).toBe(false))
    expect(within(table).getByRole("columnheader", { name: "Rule" })).toHaveAttribute("aria-sort", "ascending")
  })

  test("sends custom filters with their original case when facet data is unavailable", async () => {
    const user = userEvent.setup()
    counts.mockRejectedValue(new Error("Facets unavailable"))
    search.mockResolvedValue(empty)
    renderWithProviders(<EventsPage />)
    await screen.findByText("No events match")
    await user.click(screen.getByRole("button", { name: "Rule" }))
    await user.type(screen.getByRole("combobox", { name: "Rule" }), "Read Sensitive File")
    await user.keyboard("[Enter]")

    await waitFor(() => expect(search.mock.calls.at(-1)?.[0].rule).toEqual(["Read Sensitive File"]))
  })

  test("does not announce the requested sort until the reordered results arrive", async () => {
    const user = userEvent.setup()
    const pending = Promise.withResolvers<SearchResult>()
    const olderEvent: Event = {
      ...event,
      uuid: "events-page-2",
      rule: "Write Sensitive File",
      time: "2026-10-05T11:00:00Z",
    }
    const initial: SearchResult = { ...result, events: [event, olderEvent], total: 2 }
    const sorted: SearchResult = { ...initial, events: [olderEvent, event] }
    search.mockResolvedValueOnce(initial).mockReturnValueOnce(pending.promise)
    renderWithProviders(<EventsPage />)
    const table = await screen.findByRole("table")
    expect(within(table).getByRole("columnheader", { name: "Time" })).toHaveAttribute("aria-sort", "descending")

    await user.click(within(table).getByRole("button", { name: "Rule" }))
    await waitFor(() => expect(search.mock.calls.at(-1)?.[0].sort_by).toBe("rule"))

    expect(within(table).getAllByRole("columnheader").some((head) => head.hasAttribute("aria-sort"))).toBe(false)
    expect(table).toHaveAttribute("aria-busy", "true")
    expect(within(table).getAllByRole("row", { name: /^Event / }).map((row) => row.getAttribute("aria-label"))).toEqual([
      `Event ${event.rule} priority warning`,
      `Event ${olderEvent.rule} priority warning`,
    ])

    await act(async () => pending.resolve(sorted))

    await waitFor(() => expect(table).toHaveAttribute("aria-busy", "false"))
    expect(within(table).getByRole("columnheader", { name: "Rule" })).toHaveAttribute("aria-sort", "descending")
    expect(within(table).getByRole("columnheader", { name: "Time" })).not.toHaveAttribute("aria-sort")
    expect(within(table).getAllByRole("row", { name: /^Event / }).map((row) => row.getAttribute("aria-label"))).toEqual([
      `Event ${olderEvent.rule} priority warning`,
      `Event ${event.rule} priority warning`,
    ])
  })

  test("replaces failed sort results with an error and restores sort semantics only after retry", async () => {
    const user = userEvent.setup()
    const pending = Promise.withResolvers<SearchResult>()
    search.mockResolvedValueOnce(result).mockReturnValueOnce(pending.promise)
    renderWithProviders(<EventsPage />)
    const table = await screen.findByRole("table")
    await user.click(within(table).getByRole("button", { name: "Rule" }))
    await waitFor(() => expect(search.mock.calls.at(-1)?.[0].sort_by).toBe("rule"))

    expect(within(table).getAllByRole("columnheader").some((head) => head.hasAttribute("aria-sort"))).toBe(false)
    expect(table).toHaveAttribute("aria-busy", "true")

    await act(async () => pending.reject(new Error("Sort request failed")))

    expect(await screen.findByText("Sort request failed")).toBeInTheDocument()
    expect(screen.queryByRole("table")).toBeNull()
    expect(screen.queryByRole("columnheader")).toBeNull()
    expect(screen.getByText("Events unavailable")).toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "Retry" }))
    const recovered = await screen.findByRole("table")
    await waitFor(() => expect(recovered).toHaveAttribute("aria-busy", "false"))
    expect(within(recovered).getByRole("columnheader", { name: "Rule" })).toHaveAttribute("aria-sort", "descending")
  })

  test("retains the established sort during a same-query background refresh", async () => {
    const user = userEvent.setup()
    const pending = Promise.withResolvers<SearchResult>()
    search.mockResolvedValueOnce(result).mockReturnValueOnce(pending.promise)
    renderWithProviders(<EventsPage />)
    const table = await screen.findByRole("table")
    await user.click(screen.getByRole("button", { name: "Refresh" }))

    await waitFor(() => expect(table).toHaveAttribute("aria-busy", "true"))
    expect(within(table).getByRole("columnheader", { name: "Time" })).toHaveAttribute("aria-sort", "descending")

    await act(async () => pending.resolve(result))
    await waitFor(() => expect(table).toHaveAttribute("aria-busy", "false"))
    expect(within(table).getByRole("columnheader", { name: "Time" })).toHaveAttribute("aria-sort", "descending")
  })
})
