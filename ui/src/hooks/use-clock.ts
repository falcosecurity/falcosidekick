import { useSyncExternalStore } from "react"

export const CLOCK_TICK_MS = 30_000

const listeners = new Set<() => void>()
let now = Date.now()
let timer: ReturnType<typeof setInterval> | null = null

function tick() {
  now = Date.now()
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void): () => void {
  if (listeners.size === 0) {
    now = Date.now()
    timer = setInterval(tick, CLOCK_TICK_MS)
  }
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
    if (listeners.size === 0 && timer !== null) {
      clearInterval(timer)
      timer = null
    }
  }
}

function snapshot(): number {
  return now
}

/** Current time, shared by every subscriber and refreshed once per tick. */
export function useNow(): number {
  return useSyncExternalStore(subscribe, snapshot, snapshot)
}
