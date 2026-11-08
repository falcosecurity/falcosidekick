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
  return screen.getByRole("heading", { level: 2, name: title }).closest("[data-slot=card]") as HTMLElement
}

function row(title: string, label: string): HTMLElement {
  return within(section(title)).getByRole("group", { name: label })
}

function value(title: string, label: string): HTMLElement {
  return row(title, label).querySelector("[data-value]") as HTMLElement
}

describe("ConfigurationPage", () => {
  test("shows the build and every section of the default configuration, read-only", async () => {
    setApiAdapterForTests(fixtureAdapter())
    renderWithProviders(<ConfigurationPage />)
    expect(await screen.findByText(fixtures.version.version)).toBeInTheDocument()
    expect(screen.getByText(formatAbsoluteTime(fixtures.version.build_date))).toBeInTheDocument()
    expect(screen.getByRole("button", { name: `Copy ${fixtures.version.commit}` })).toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Configuration")
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual([
      "Listeners", "Database", "API and access", "Reload", "Logs and metrics", "UI",
    ])
    expect(screen.getAllByRole("link").map((a) => a.getAttribute("href"))).toEqual([
      "#listeners", "#database", "#api", "#reload", "#observability", "#ui",
    ])
    expect(value("Listeners", "Ingestion")).toHaveTextContent(/^:2801$/)
    expect(row("Listeners", "Ingestion")).toHaveTextContent(/Every interface, IPv4 and IPv6/)
    expect(value("Listeners", "Shutdown delay")).toHaveTextContent("5s")
    expect(value("Listeners", "Ingestion TLS")).toHaveTextContent("Disabled")
    expect(value("Listeners", "Management")).toHaveTextContent("127.0.0.1:2802")
    expect(value("Database", "Backend")).toHaveTextContent("inmemory")
    expect(row("Database", "Backend")).toHaveTextContent(/lost on restart/)
    expect(within(section("Database")).queryByRole("group", { name: "Connect timeout" })).toBeNull()
    expect(value("API and access", "Writes")).toHaveTextContent("Read-only")
    expect(value("API and access", "File outputs")).toHaveTextContent("Read-only")
    expect(value("API and access", "Secret directories")).toHaveTextContent("None")
    expect(row("API and access", "Authentication")).toHaveTextContent(AUTH_UNAVAILABLE_MESSAGE)
    expect(value("API and access", "Authentication")).toHaveTextContent("Not available")
    expect(value("Reload", "File change poll")).toHaveTextContent("every 30s")
    expect(value("Reload", "Drain on reload")).toHaveTextContent("10s")
    expect(value("Logs and metrics", "Label values")).toHaveTextContent("up to 1000")
    expect(value("UI", "UI")).toHaveTextContent("Disabled")
    expect(screen.queryByRole("textbox")).toBeNull()
  })

  test("shows postgres settings with the password hidden and listener TLS files", async () => {
    setApiAdapterForTests(async (config) => {
      if (config.url === "/config") {
        return { data: fixtures.configPostgres, status: 200, statusText: "OK", headers: {}, config }
      }
      return fixtureAdapter()(config)
    })
    renderWithProviders(<ConfigurationPage />)
    expect(await screen.findByText("postgres.falco.svc:5432")).toBeInTheDocument()
    expect(value("Database", "Password")).toHaveTextContent("Set inline, hidden")
    expect(document.body).not.toHaveTextContent("****")
    expect(value("Database", "SSL mode")).toHaveTextContent("verify-full")
    expect(value("Database", "CA file")).toHaveTextContent("/etc/falcosidekick/secrets/postgres-tls/ca.crt")
    expect(value("Database", "Instance sync")).toHaveTextContent("every 10s")
    expect(value("Database", "Connect timeout")).toHaveTextContent("30s")
    expect(value("Listeners", "Ingestion TLS")).toHaveTextContent("Enabled")
    expect(value("Listeners", "Certificate")).toHaveTextContent("/etc/falcosidekick/certs/tls.crt")
    expect(within(section("Listeners")).queryByRole("group", { name: "Client CA" })).toBeNull()
    expect(value("API and access", "Writes")).toHaveTextContent("Allowed")
    expect(value("API and access", "Secret directories")).toHaveTextContent("/etc/falcosidekick/secrets")
    expect(value("Logs and metrics", "Extra metric labels")).toHaveTextContent("cluster")
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
