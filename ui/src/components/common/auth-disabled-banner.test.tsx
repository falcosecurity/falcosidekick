import { afterEach, describe, expect, test } from "bun:test"

import { AUTH_UNAVAILABLE_MESSAGE } from "@/lib/auth"
import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { AuthDisabledBanner } from "./auth-disabled-banner"

afterEach(cleanup)

describe("AuthDisabledBanner", () => {
  test("always states that authentication is not available, as a compact pill", () => {
    renderWithProviders(<AuthDisabledBanner compact />)
    const pill = screen.getByLabelText(AUTH_UNAVAILABLE_MESSAGE)
    expect(pill).toHaveTextContent("Auth off")
    expect(pill).toHaveClass("text-status-degraded-foreground", "bg-status-degraded/10", "border-status-degraded/30")
    expect(pill.querySelector("span:not([aria-hidden])")).toHaveClass("hidden", "sm:inline")
    expect(pill).not.toHaveAttribute("role")
  })

  test("always states that authentication is not available, as a banner without a live region", () => {
    renderWithProviders(<AuthDisabledBanner />)
    const banner = screen.getByText(AUTH_UNAVAILABLE_MESSAGE)
    expect(banner).toHaveClass("text-status-degraded-foreground")
    expect(screen.queryByRole("status")).toBeNull()
  })
})
