import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import userEvent from "@testing-library/user-event"

import { useUIStore } from "@/stores/ui-store"
import { contrast, themeColor, THEMES } from "@/test/contrast"
import { act, cleanup, renderWithProviders, screen, waitFor, within } from "@/test/test-utils"

import { NAV_ITEMS, NavSidebar } from "./nav-sidebar"

type Viewport = { width: number; height?: number }

function setViewport({ width, height = 800 }: Viewport) {
  window.happyDOM.setViewport({ width, height })
}

let originalStore: ReturnType<typeof useUIStore.getState>

beforeEach(() => {
  originalStore = useUIStore.getState()
  useUIStore.setState({ sidebarCollapsed: false, sidebarOpen: false })
})

afterEach(() => {
  cleanup()
  setViewport({ width: 1024 })
  useUIStore.setState(originalStore, true)
})

describe("NavSidebar", () => {
  test("renders every page link expanded at lg and above", () => {
    setViewport({ width: 1280 })
    renderWithProviders(<NavSidebar />, { initialEntries: ["/events"] })
    const aside = screen.getByRole("complementary")
    expect(aside).toHaveClass("w-60")
    expect(aside).toHaveAttribute("data-collapsed", "false")
    const nav = within(aside).getByRole("navigation", { name: "Primary" })
    for (const item of NAV_ITEMS) {
      const link = within(nav).getByRole("link", { name: item.label })
      expect(link).toHaveAttribute("href", item.to)
      expect(link.querySelector("span")).not.toHaveClass("sr-only")
    }
    expect(within(nav).getByRole("link", { name: "Events" })).toHaveAttribute("aria-current", "page")
    expect(screen.queryByText(/⌘K/)).toBeNull()
  })

  test("honors the collapsed preference at lg with labels for assistive technology", () => {
    setViewport({ width: 1280 })
    useUIStore.setState({ sidebarCollapsed: true })
    renderWithProviders(<NavSidebar />)
    const aside = screen.getByRole("complementary")
    expect(aside).toHaveClass("w-14")
    for (const item of NAV_ITEMS) {
      const link = screen.getByRole("link", { name: item.label })
      expect(link.querySelector("span")).toHaveClass("sr-only")
    }
  })

  test("is an icon rail between md and lg whatever the preference", () => {
    setViewport({ width: 900 })
    renderWithProviders(<NavSidebar />)
    const aside = screen.getByRole("complementary")
    expect(aside).toHaveClass("w-14")
    expect(aside).toHaveAttribute("data-collapsed", "true")
    expect(screen.getByRole("link", { name: "Pipeline" }).querySelector("span")).toHaveClass("sr-only")
  })

  test("becomes a sheet below md that closes after navigating", async () => {
    setViewport({ width: 375 })
    renderWithProviders(<NavSidebar />)
    expect(screen.queryByRole("complementary")).toBeNull()
    expect(screen.queryByRole("dialog")).toBeNull()

    act(() => useUIStore.getState().setSidebarOpen(true))
    const dialog = await screen.findByRole("dialog", { name: "Navigation" })
    expect(within(dialog).getByRole("navigation", { name: "Primary" })).toBeInTheDocument()

    await userEvent.setup().click(within(dialog).getByRole("link", { name: "Pipeline" }))
    await waitFor(() => expect(useUIStore.getState().sidebarOpen).toBe(false))
  })

  test("reacts to viewport changes without a remount", async () => {
    setViewport({ width: 1280 })
    renderWithProviders(<NavSidebar />)
    expect(screen.getByRole("complementary")).toHaveClass("w-60")
    act(() => setViewport({ width: 900 }))
    await waitFor(() => expect(screen.getByRole("complementary")).toHaveClass("w-14"))
    act(() => setViewport({ width: 500 }))
    await waitFor(() => expect(screen.queryByRole("complementary")).toBeNull())
  })
})

describe("active navigation contrast", () => {
  test.each([...THEMES])("%s active item text meets 4.5:1 on the accent background", (theme) => {
    const ratio = contrast(themeColor(theme, "sidebar-primary"), themeColor(theme, "sidebar-accent"))
    expect(ratio).toBeGreaterThanOrEqual(4.5)
  })

  test.each([...THEMES])("%s resting item text meets 4.5:1 on the sidebar", (theme) => {
    const ratio = contrast(themeColor(theme, "sidebar-foreground"), themeColor(theme, "sidebar"))
    expect(ratio).toBeGreaterThanOrEqual(4.5)
  })
})
