import { afterEach, describe, expect, test } from "bun:test"

import { cleanup, render } from "@/test/test-utils"

import { PageHeader } from "./page-header"

afterEach(cleanup)

describe("PageHeader", () => {
  test("names the browser tab after the page and restores the app name when it leaves", () => {
    const { rerender, unmount } = render(<PageHeader title="Events" />)
    expect(document.title).toBe("Events · Falcosidekick")
    rerender(<PageHeader title="Pipeline" />)
    expect(document.title).toBe("Pipeline · Falcosidekick")
    unmount()
    expect(document.title).toBe("Falcosidekick")
  })
})
