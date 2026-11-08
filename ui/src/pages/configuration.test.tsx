import { afterEach, describe, expect, test } from "bun:test"

import { setApiAdapterForTests } from "@/lib/api-client"
import { AUTH_UNAVAILABLE_MESSAGE } from "@/lib/auth"
import { formatAbsoluteTime } from "@/lib/format"
import { errorResponse, fixtureAdapter, fixtures } from "@/test/fixtures"
import { cleanup, renderWithProviders, screen, within } from "@/test/test-utils"

import { ConfigurationPage } from "./configuration"

afterEach(() => {
  cleanup()
  setApiAdapterForTests(null)
})

function section(title: string): HTMLElement {
  const heading = screen.getByRole("heading", { level: 2, name: title })
  return heading.closest("[data-slot=card]") as HTMLElement
}

function value(title: string, term: string): HTMLElement {
  return within(section(title)).getByText(term, { selector: "dt" }).nextElementSibling as HTMLElement
}

describe("ConfigurationPage", () => {
  test("shows every section of the default configuration, read-only", async () => {
    setApiAdapterForTests(fixtureAdapter())
    renderWithProviders(<ConfigurationPage />)
    expect(await screen.findByText(fixtures.version.version)).toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Configuration")
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual([
      "Build", "Listeners", "Database", "API", "Outputs", "Logs and metrics", "UI",
    ])
    expect(value("Build", "Built")).toHaveTextContent(formatAbsoluteTime(fixtures.version.build_date))
    expect(value("Listeners", "Ingestion")).toHaveTextContent("0.0.0.0:2801")
    expect(value("Listeners", "Ingestion TLS")).toHaveTextContent("Disabled")
    expect(value("Listeners", "Management")).toHaveTextContent("127.0.0.1:2802")
    expect(value("Database", "Backend")).toHaveTextContent("inmemory")
    expect(within(section("Database")).getByText(/lost on restart/)).toBeInTheDocument()
    expect(within(section("Database")).queryByText("Connect timeout")).toBeNull()
    expect(value("API", "Writes")).toHaveTextContent("Read-only")
    expect(value("API", "Secret directories")).toHaveTextContent("None")
    expect(value("API", "Authentication")).toHaveTextContent(AUTH_UNAVAILABLE_MESSAGE)
    expect(value("Outputs", "File outputs")).toHaveTextContent("Read-only from the UI and the API")
    expect(value("Outputs", "File change poll")).toHaveTextContent("every 30s")
    expect(value("Outputs", "Drain on reload")).toHaveTextContent("up to 10s")
    expect(value("Logs and metrics", "Label values")).toHaveTextContent("up to 1000 per label")
    expect(value("UI", "UI")).toHaveTextContent("Disabled")
    expect(screen.queryByRole("textbox")).toBeNull()
  })

  test("shows postgres settings with the password masked and listener TLS files", async () => {
    setApiAdapterForTests(async (config) => {
      if (config.url === "/config") {
        return { data: fixtures.configPostgres, status: 200, statusText: "OK", headers: {}, config }
      }
      return fixtureAdapter()(config)
    })
    renderWithProviders(<ConfigurationPage />)
    expect(await screen.findByText("postgres.falco.svc:5432")).toBeInTheDocument()
    expect(value("Database", "Password")).toHaveTextContent("Set inline (masked)")
    expect(document.body).not.toHaveTextContent("****")
    expect(value("Database", "SSL mode")).toHaveTextContent("verify-full")
    expect(value("Database", "CA file")).toHaveTextContent("/etc/falcosidekick/secrets/postgres-tls/ca.crt")
    expect(value("Database", "Instance sync")).toHaveTextContent("every 10s")
    expect(value("Database", "Connect timeout")).toHaveTextContent("30s")
    expect(value("Listeners", "Ingestion TLS")).toHaveTextContent("Enabled")
    expect(value("Listeners", "Certificate")).toHaveTextContent("/etc/falcosidekick/certs/tls.crt")
    expect(within(section("Listeners")).queryByText("Client CA")).toBeNull()
    expect(value("API", "Writes")).toHaveTextContent("Allowed")
    expect(value("API", "Secret directories")).toHaveTextContent("/etc/falcosidekick/secrets")
    expect(value("Logs and metrics", "Metric labels")).toHaveTextContent("cluster")
  })

  test("shows the backend error text when the configuration cannot be read", async () => {
    setApiAdapterForTests(async (config) => {
      throw errorResponse(config, 503, fixtures.errors.database_not_configured.body)
    })
    renderWithProviders(<ConfigurationPage />)
    expect(await screen.findByText("Unable to load the configuration")).toBeInTheDocument()
    expect(screen.getByText(fixtures.errors.database_not_configured.body.error)).toBeInTheDocument()
  })
})
