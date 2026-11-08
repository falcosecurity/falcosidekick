import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import userEvent from "@testing-library/user-event"

import { api } from "@/lib/api-client"
import { ApiError } from "@/lib/api-error"
import type { Event, SearchResult } from "@/lib/types"
import { events, fixtures } from "@/test/fixtures"
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

const event: Event = events[0]!
const result: SearchResult = { ...fixtures.eventsSearch, events: [event], total: 1 }
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

function rowButton(rule = event.rule) {
  return screen.findByRole("button", { name: rule })
}

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

  test("shows the backend error text and recovers on retry", async () => {
    const user = userEvent.setup()
    const { status, body } = fixtures.errors.event_store_unavailable
    search.mockRejectedValueOnce(new ApiError(status, body.error))
    renderWithProviders(<EventsPage />)

    expect(await screen.findByText("Unable to load events")).toBeInTheDocument()
    expect(screen.getByText(body.error)).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Retry" }))

    expect(await screen.findByRole("table")).toBeInTheDocument()
    expect(screen.queryByText("Unable to load events")).not.toBeInTheDocument()
  })

  test("renders the full fixture page with one real button per row and no clickable rows", async () => {
    search.mockResolvedValue(fixtures.eventsSearch)
    renderWithProviders(<EventsPage />)
    const table = await screen.findByRole("table")
    const rows = within(table).getAllByRole("row").slice(1)
    expect(rows).toHaveLength(events.length)
    for (const [i, row] of rows.entries()) {
      expect(row).not.toHaveAttribute("tabindex")
      expect(row).not.toHaveAttribute("aria-label")
      const button = within(row).getByRole("button", { name: events[i]!.rule })
      expect(button).toHaveAttribute("title", events[i]!.rule)
      expect(within(row).getByText(`priority ${events[i]!.priority}`)).toHaveClass("sr-only")
      expect(within(row).getByText(events[i]!.source)).toHaveAttribute("data-variant", "source")
      expect(within(row).getByRole("time")).toHaveAttribute("tabindex", "0")
    }
    expect(within(table).getByRole("columnheader", { name: "Source" })).toHaveClass("hidden", "md:table-cell")
    expect(within(table).getByRole("columnheader", { name: "Hostname" })).toHaveClass("hidden", "lg:table-cell")
    expect(within(table).getByRole("columnheader", { name: "Tags" })).toHaveClass("hidden", "xl:table-cell")
    for (const name of ["Priority", "Time", "Rule"]) {
      expect(within(table).getByRole("columnheader", { name })).not.toHaveClass("hidden")
    }
    expect(screen.getByRole("combobox", { name: "Rows per page" })).toBeInTheDocument()
  })

  test.each(["[Enter]", " "])("opens from the row button with %s and returns focus on Escape", async (key) => {
    const user = userEvent.setup()
    renderWithProviders(<EventsPage />)
    const button = await rowButton()
    button.focus()
    await user.keyboard(key)

    const dialog = await screen.findByRole("dialog", { name: event.rule })
    await waitFor(() => expect(document.activeElement === within(dialog).getByRole("button", { name: "Close" })).toBe(true))
    await user.keyboard("[Escape]")

    await waitFor(() => expect(document.activeElement === button).toBe(true))
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
  })

  test("returns focus to the clicked button even if it did not have focus", async () => {
    const user = userEvent.setup()
    renderWithProviders(<EventsPage />)
    const button = await rowButton()
    screen.getByRole("button", { name: "Refresh" }).focus()
    fireEvent.click(button)
    await screen.findByRole("dialog")
    await user.keyboard("[Escape]")

    await waitFor(() => expect(document.activeElement === button).toBe(true))
  })

  test("restores focus to the results region when a refreshed result removes the opening row", async () => {
    const user = userEvent.setup()
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
    renderWithProviders(<EventsPage />, { queryClient: client })
    const button = await rowButton()
    await user.click(button)
    await screen.findByRole("dialog")
    act(() => { client.setQueriesData({ queryKey: ["events", "search"] }, empty) })
    await waitFor(() => expect(button.isConnected).toBe(false))
    await user.keyboard("[Escape]")

    await waitFor(() => {
      expect(document.activeElement === screen.getByRole("region", { name: "Event results" })).toBe(true)
    })
  })

  test("exposes sort direction and a keyboard focus indicator", async () => {
    const user = userEvent.setup()
    renderWithProviders(<EventsPage />, { initialEntries: ["/events?page=2&rule=Terminal+shell+in+container"] })
    const table = await screen.findByRole("table")
    const rule = within(table).getByRole("button", { name: "Rule" })
    expect(rule).toHaveClass("focus-visible:outline-2", "focus-visible:outline-ring")
    expect(within(table).getByRole("columnheader", { name: "Time" })).toHaveAttribute("aria-sort", "descending")
    rule.focus()
    await user.keyboard("[Enter]")

    await waitFor(() => expect(search.mock.calls.at(-1)?.[0]).toMatchObject({
      page: 1, rule: ["Terminal shell in container"], sort_by: "rule", sort_desc: true,
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
    const olderEvent: Event = events[1]!
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
    const ruleButtons = () => within(table).getAllByRole("button").map((b) => b.textContent).filter((t) => [event.rule, olderEvent.rule].includes(t ?? ""))
    expect(ruleButtons()).toEqual([event.rule, olderEvent.rule])

    await act(async () => pending.resolve(sorted))

    await waitFor(() => expect(table).toHaveAttribute("aria-busy", "false"))
    expect(within(table).getByRole("columnheader", { name: "Rule" })).toHaveAttribute("aria-sort", "descending")
    expect(within(table).getByRole("columnheader", { name: "Time" })).not.toHaveAttribute("aria-sort")
    expect(ruleButtons()).toEqual([olderEvent.rule, event.rule])
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
