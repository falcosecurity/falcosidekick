import { afterEach, describe, expect, mock, test } from "bun:test"
import { useLocation } from "react-router"

import { setApiAdapterForTests } from "@/lib/api-client"
import { fixtureAdapter, fixtures, routeKey } from "@/test/fixtures"
import { cleanup, fireEvent, renderWithProviders, screen, waitFor } from "@/test/test-utils"

import { EventDetailDrawer } from "./event-detail-drawer"
import { EventsPagination, pageWindow } from "./events-pagination"
import { PriorityQuickFilter } from "./priority-quick-filter"

afterEach(() => {
  cleanup()
  setApiAdapterForTests(null)
})

function Location() {
  const location = useLocation()
  return <output aria-label="location">{location.pathname + location.search}</output>
}

describe("pageWindow", () => {
  const cases: [number, number, (number | "gap")[]][] = [
    [1, 1, [1]],
    [1, 3, [1, 2, 3]],
    [1, 31, [1, 2, "gap", 31]],
    [5, 31, [1, "gap", 4, 5, 6, "gap", 31]],
    [31, 31, [1, "gap", 30, 31]],
    [2, 4, [1, 2, 3, 4]],
  ]
  test.each(cases)("page %i of %i", (page, total, want) => {
    expect(pageWindow(page, total)).toEqual(want)
  })
})

describe("EventsPagination", () => {
  test("pages are links that keep the filters and stay in the app", () => {
    renderWithProviders(
      <>
        <EventsPagination page={2} totalPages={5} limit={50} summary="Showing 51-100 of 230" />
        <Location />
      </>,
      { initialEntries: ["/events?rule=Write%20below%20etc&page=2"] },
    )
    const next = screen.getByRole("link", { name: "Go to next page" })
    expect(next).toHaveAttribute("href", "?rule=Write+below+etc&page=3")
    expect(screen.getByRole("link", { name: "1" })).toHaveAttribute("href", "?rule=Write+below+etc")
    expect(screen.getByRole("link", { name: "2" })).toHaveAttribute("aria-current", "page")
    fireEvent.click(next)
    expect(screen.getByRole("status", { name: "location" })).toHaveTextContent("/events?rule=Write+below+etc&page=3")
  })

  test("the first page cannot go back and the last cannot go on", () => {
    renderWithProviders(<EventsPagination page={1} totalPages={1} limit={50} summary="3 events" />)
    expect(screen.getByRole("link", { name: "Go to previous page" })).toHaveAttribute("aria-disabled", "true")
    expect(screen.getByRole("link", { name: "Go to next page" })).toHaveAttribute("aria-disabled", "true")
  })
})

describe("PriorityQuickFilter", () => {
  test("counts each priority with the other filters and filters on click", async () => {
    const calls: string[] = []
    const base = fixtureAdapter()
    setApiAdapterForTests(async (config) => {
      if (routeKey(config) === "GET /events/count/priority") {
        calls.push(String(config.params))
        return { data: { groups: { critical: 4, warning: 9 } }, status: 200, statusText: "OK", headers: {}, config }
      }
      return base(config)
    })
    renderWithProviders(
      <>
        <PriorityQuickFilter />
        <Location />
      </>,
      { initialEntries: ["/events?priority=warning&rule=X&page=3"] },
    )
    const critical = await screen.findByRole("button", { name: "Critical: 4", pressed: false })
    expect(screen.getByRole("button", { name: "Warning: 9", pressed: true })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Debug: 0" })).toBeDisabled()
    expect(calls[0]).not.toContain("priority")
    expect(calls[0]).toContain("rule=X")
    fireEvent.click(critical)
    await waitFor(() => expect(screen.getByRole("status", { name: "location" })).toHaveTextContent("priority=warning%2Ccritical&rule=X"))
    expect(screen.getByRole("status", { name: "location" })).not.toHaveTextContent("page=")
  })
})

describe("EventDetailDrawer", () => {
  test("links to the events of the same rule and host", () => {
    setApiAdapterForTests(fixtureAdapter())
    const onClose = mock()
    renderWithProviders(<EventDetailDrawer event={fixtures.event} open onClose={onClose} />)
    expect(screen.getByRole("link", { name: /Events of this rule/ })).toHaveAttribute(
      "href",
      `/events?rule=${encodeURIComponent(fixtures.event.rule)}`,
    )
    const host = screen.getByRole("link", { name: /Events of this host/ })
    expect(host).toHaveAttribute("href", `/events?hostname=${encodeURIComponent(fixtures.event.hostname!)}`)
    fireEvent.click(host)
    expect(onClose).toHaveBeenCalled()
  })
})
