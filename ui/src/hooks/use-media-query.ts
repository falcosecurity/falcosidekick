import { useSyncExternalStore } from "react"

// Tailwind breakpoints used by the shell.
export const MEDIA_MD = "(min-width: 48rem)"
export const MEDIA_LG = "(min-width: 64rem)"

function mediaList(query: string): MediaQueryList | null {
  return typeof window !== "undefined" && typeof window.matchMedia === "function"
    ? window.matchMedia(query)
    : null
}

export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const list = mediaList(query)
      if (!list) return () => {}
      list.addEventListener("change", onChange)
      window.addEventListener("resize", onChange)
      return () => {
        list.removeEventListener("change", onChange)
        window.removeEventListener("resize", onChange)
      }
    },
    () => mediaList(query)?.matches ?? true,
    () => true,
  )
}
