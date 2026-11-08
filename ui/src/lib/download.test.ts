import { afterEach, describe, expect, spyOn, test } from "bun:test"

import { downloadJSON } from "./download"

const spies: Array<{ mockRestore: () => void }> = []

afterEach(() => {
  for (const spy of spies.splice(0)) spy.mockRestore()
})

describe("downloadJSON", () => {
  test("keeps the object URL alive after the click, so the browser can read it, then frees it", () => {
    const timers: Array<() => void> = []
    const create = spyOn(URL, "createObjectURL").mockReturnValue("blob:events")
    const revoke = spyOn(URL, "revokeObjectURL").mockImplementation(() => {})
    const click = spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {})
    const timeout = spyOn(globalThis, "setTimeout").mockImplementation(((fn: () => void) => {
      timers.push(fn)
      return 0
    }) as unknown as typeof setTimeout)
    spies.push(create, revoke, click, timeout)

    downloadJSON("events.json", [{ rule: "a" }])
    expect(click).toHaveBeenCalledTimes(1)
    expect(revoke).not.toHaveBeenCalled()
    for (const fn of timers) fn()
    expect(revoke).toHaveBeenCalledWith("blob:events")
  })
})
