import { afterEach, describe, expect, test } from "bun:test"

import { setApiAdapterForTests } from "@/lib/api-client"
import { AUTH_UNAVAILABLE_MESSAGE } from "@/lib/auth"
import { formatAbsoluteTime } from "@/lib/format"
import { errorResponse, fixtureAdapter, fixtures } from "@/test/fixtures"
import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { SettingsPage } from "./settings"

afterEach(() => {
  cleanup()
  setApiAdapterForTests(null)
})

function definition(term: string): HTMLElement {
  return screen.getByText(term, { selector: "dt" }).nextElementSibling as HTMLElement
}

describe("SettingsPage", () => {
  test("shows the build exactly as the backend reports it and a fixed authentication state", async () => {
    setApiAdapterForTests(fixtureAdapter())
    renderWithProviders(<SettingsPage />)
    expect(await screen.findByText(fixtures.version.version)).toBeInTheDocument()
    expect(definition("Commit")).toHaveTextContent(fixtures.version.commit)
    expect(definition("Built")).toHaveTextContent(formatAbsoluteTime(fixtures.version.build_date))
    expect(definition("Go")).toHaveTextContent(fixtures.version.go_version)
    expect(definition("Authentication")).toHaveTextContent(AUTH_UNAVAILABLE_MESSAGE)
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Settings")
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual(["Deployment", "Auto-refresh"])
  })

  test("shows the backend error text when the build cannot be read", async () => {
    setApiAdapterForTests(async (config) => {
      throw errorResponse(config, 503, fixtures.errors.database_not_configured.body)
    })
    renderWithProviders(<SettingsPage />)
    expect(await screen.findByText("Unable to load build information")).toBeInTheDocument()
    expect(screen.getByText(fixtures.errors.database_not_configured.body.error)).toBeInTheDocument()
  })
})
