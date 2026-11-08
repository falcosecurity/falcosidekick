import { useRef } from "react"

/**
 * Returns focus to the element that had it when an overlay opened, for overlays opened from code
 * rather than from a Radix Trigger. Spread the handlers on the Content of a Dialog, AlertDialog or
 * Sheet. If the opener is gone, Radix's own fallback applies.
 */
export function useReturnFocus() {
  const opener = useRef<HTMLElement | null>(null)
  return {
    onOpenAutoFocus: () => {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    },
    onCloseAutoFocus: (event: Event) => {
      if (opener.current?.isConnected) {
        event.preventDefault()
        opener.current.focus()
      }
      opener.current = null
    },
  }
}
