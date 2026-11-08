import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import userEvent from "@testing-library/user-event"

import { AUTH_UNAVAILABLE_MESSAGE } from "@/lib/auth"
import { useUIStore } from "@/stores/ui-store"
import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { TopBar } from "./top-bar"

let originalStore: ReturnType<typeof useUIStore.getState>

beforeEach(() => {
  originalStore = useUIStore.getState()
  useUIStore.setState({ sidebarCollapsed: true, sidebarOpen: false, refreshIntervalMs: 0 })
})

afterEach(() => {
  cleanup()
  useUIStore.setState(originalStore, true)
})

describe("TopBar", () => {
  test("is a landmark with one row and a truncating title", () => {
    renderWithProviders(<TopBar />, { initialEntries: ["/pipeline"] })
    const header = screen.getByRole("banner")
    expect(header.firstElementChild).toHaveClass("flex", "h-14", "items-center")
    expect(screen.getByText("Pipeline")).toHaveClass("min-w-0", "flex-1", "truncate")
    const controls = screen.getByRole("button", { name: "Switch to dark theme" }).parentElement!
    expect(controls).toHaveClass("shrink-0")
    expect(controls).toContainElement(screen.getByRole("button", { name: "Refresh all data now" }))
    expect(controls).toContainElement(screen.getByRole("combobox", { name: "Auto-refresh interval" }))
    expect(controls).toContainElement(screen.getByLabelText(AUTH_UNAVAILABLE_MESSAGE))
  })

  test("falls back to the product name on unknown routes", () => {
    renderWithProviders(<TopBar />, { initialEntries: ["/nowhere"] })
    expect(screen.getByText("Falcosidekick")).toBeInTheDocument()
  })

  test("opens the navigation sheet below md and toggles the rail at lg", async () => {
    renderWithProviders(<TopBar />)
    const user = userEvent.setup()
    const opener = screen.getByRole("button", { name: "Open navigation" })
    expect(opener).toHaveClass("md:hidden")
    await user.click(opener)
    expect(useUIStore.getState().sidebarOpen).toBe(true)

    const collapse = screen.getByRole("button", { name: "Collapse navigation sidebar" })
    expect(collapse).toHaveClass("hidden", "lg:inline-flex")
    expect(collapse).toHaveAttribute("aria-pressed", "true")
    await user.click(collapse)
    expect(useUIStore.getState().sidebarCollapsed).toBe(false)
    expect(collapse).toHaveAttribute("aria-pressed", "false")
  })

  test("the grouped refresh command still invalidates queries", async () => {
    const queryClient = new QueryClient()
    const invalidate = spyOn(queryClient, "invalidateQueries")
    try {
      renderWithProviders(<TopBar />, { queryClient })
      await userEvent.setup().click(screen.getByRole("button", { name: "Refresh all data now" }))
      expect(invalidate).toHaveBeenCalledTimes(1)
    } finally {
      invalidate.mockRestore()
    }
  })
})
