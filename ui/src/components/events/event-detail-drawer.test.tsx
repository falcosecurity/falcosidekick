import { afterEach, describe, expect, spyOn, test } from "bun:test"
import userEvent from "@testing-library/user-event"
import { useState } from "react"
import { toast } from "sonner"

import type { Event } from "@/lib/types"
import { cleanup, renderWithProviders, screen, waitFor, within } from "@/test/test-utils"

import { EventDetailDrawer } from "./event-detail-drawer"

const event: Event = {
  uuid: "event-detail-1",
  rule: "Read Sensitive File",
  priority: "warning",
  source: "syscall",
  time: "2026-10-05T12:00:00Z",
  output: "A process read a sensitive file",
  output_fields: { "proc.name": "cat", count: 2, nested: { enabled: true } },
}

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

  test("renders output fields without requiring optional hostname or tags", async () => {
    renderWithProviders(<EventDetailDrawer event={event} open onClose={() => {}} />)
    const dialog = await screen.findByRole("dialog", { name: event.rule })

    expect(within(dialog).getByText("proc.name")).toBeInTheDocument()
    expect(within(dialog).getByText("cat")).toBeInTheDocument()
    expect(within(dialog).getByText("nested:")).toBeInTheDocument()
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
