import { useCallback, useSyncExternalStore } from "react"

// Tailwind breakpoints used by the shell.
export const MEDIA_MD = "(min-width: 48rem)"
export const MEDIA_LG = "(min-width: 64rem)"

function mediaList(query: string): MediaQueryList | null {
  return typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia(query)
    : null
}

export function useMediaQuery(query: string): boolean {
  // Stable per query, so the store subscribes once instead of on every render.
  const subscribe = useCallback(
    (onChange: () => void) => {
      const list = mediaList(query)
      if (!list) return () => {}
      list.addEventListener("change", onChange)
      window.addEventListener("resize", onChange)
      return () => {
        list.removeEventListener("change", onChange)
        window.removeEventListener("resize", onChange)
      }
    },
    [query],
  )
  return useSyncExternalStore(subscribe, () => mediaList(query)?.matches ?? true, () => true)
}
