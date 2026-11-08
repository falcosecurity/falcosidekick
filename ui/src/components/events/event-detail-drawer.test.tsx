import { afterEach, describe, expect, spyOn, test } from "bun:test"
import userEvent from "@testing-library/user-event"
import { useState } from "react"
import { toast } from "sonner"

import type { Event } from "@/lib/types"
import { fixtures } from "@/test/fixtures"
import { cleanup, renderWithProviders, screen, waitFor, within } from "@/test/test-utils"

import { EventDetailDrawer } from "./event-detail-drawer"

const event: Event = fixtures.event
const bare: Event = { ...event, uuid: "event-detail-2", tags: undefined, hostname: undefined }

afterEach(cleanup)

function DrawerHarness() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button onClick={() => setOpen(true)}>Inspect event</button>
      <EventDetailDrawer event={event} open={open} onClose={() => setOpen(false)} />
    </>
  )
}

describe("EventDetailDrawer", () => {
  test.each(["[Escape]", "[Enter]"])("restores focus after closing with %s", async (key) => {
    const user = userEvent.setup()
    renderWithProviders(<DrawerHarness />)
    const opener = screen.getByRole("button", { name: "Inspect event" })
    opener.focus()
    await user.keyboard("[Enter]")

    const dialog = await screen.findByRole("dialog", { name: event.rule })
    expect(dialog).toHaveAccessibleDescription(event.output)
    await waitFor(() => expect(document.activeElement === within(dialog).getByRole("button", { name: "Close" })).toBe(true))
    await user.keyboard(key)

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    await waitFor(() => expect(document.activeElement === opener).toBe(true))
  })

  test("renders the backend event with source and tag chips in a labelled list", async () => {
    renderWithProviders(<EventDetailDrawer event={event} open onClose={() => {}} />)
    const dialog = await screen.findByRole("dialog", { name: event.rule })
    const meta = dialog.querySelector("dl")!
    expect(within(meta).getAllByRole("term").map((t) => t.textContent)).toEqual(["Time", "Source", "Hostname", "Tags"])
    expect(within(dialog).getByText(event.source)).toHaveAttribute("data-variant", "source")
    for (const tag of event.tags ?? []) {
      expect(within(dialog).getByText(tag)).toHaveAttribute("data-variant", "tag")
    }
    expect(within(dialog).getByText(event.hostname!)).toBeInTheDocument()
    expect(within(dialog).getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual([
      "Rendered output", "Output fields",
    ])
    expect(within(dialog).getByText("proc.name")).toBeInTheDocument()
    expect(within(dialog).getByText("bash")).toBeInTheDocument()
  })

  test("renders output fields without requiring optional hostname or tags", async () => {
    renderWithProviders(<EventDetailDrawer event={bare} open onClose={() => {}} />)
    const dialog = await screen.findByRole("dialog", { name: event.rule })
    expect(within(dialog.querySelector("dl")!).getAllByRole("term").map((t) => t.textContent)).toEqual(["Time", "Source"])
    expect(within(dialog).queryByText("Hostname")).not.toBeInTheDocument()
    expect(within(dialog).queryByText("Tags")).not.toBeInTheDocument()
  })

  test("does not render a dialog without a selected event", () => {
    renderWithProviders(<EventDetailDrawer event={null} open={false} onClose={() => {}} />)
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
  })

  test.each(["UUID", "JSON"])("copies %s and reports success", async (label) => {
    const user = userEvent.setup()
    const write = spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined)
    const notify = spyOn(toast, "success").mockReturnValue(0)
    try {
      renderWithProviders(<EventDetailDrawer event={event} open onClose={() => {}} />)
      await user.click(screen.getByRole("button", { name: label }))

      expect(write).toHaveBeenCalledWith(label === "UUID" ? event.uuid : JSON.stringify(event, null, 2))
      expect(notify).toHaveBeenCalledWith(label === "UUID" ? "UUID copied" : "Event JSON copied")
    } finally {
      write.mockRestore()
      notify.mockRestore()
    }
  })

  test("reports clipboard failure without claiming success", async () => {
    const user = userEvent.setup()
    const write = spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("Permission denied"))
    const success = spyOn(toast, "success").mockReturnValue(0)
    const failure = spyOn(toast, "error").mockReturnValue(0)
    try {
      renderWithProviders(<EventDetailDrawer event={event} open onClose={() => {}} />)
      await user.click(screen.getByRole("button", { name: "UUID" }))

      expect(failure).toHaveBeenCalledWith("Unable to copy")
      expect(success).not.toHaveBeenCalled()
    } finally {
      write.mockRestore()
      success.mockRestore()
      failure.mockRestore()
    }
  })
})
