import { create } from "zustand"
import { createJSONStorage, persist } from "zustand/middleware"

export type ThemeMode = "system" | "light" | "dark"

// Global auto-refresh cadence presets. 0 means "off" (manual only).
export const REFRESH_OPTIONS: Array<{ label: string; value: number }> = [
  { label: "Off", value: 0 },
  { label: "5s", value: 5_000 },
  { label: "10s", value: 10_000 },
  { label: "15s", value: 15_000 },
  { label: "30s", value: 30_000 },
  { label: "1m", value: 60_000 },
  { label: "2m", value: 120_000 },
  { label: "5m", value: 300_000 },
]

const DEFAULT_REFRESH_MS = 15_000

interface UIState {
  /** Icon rail instead of the full sidebar at `lg` and above; between `md` and `lg` the rail is forced. */
  sidebarCollapsed: boolean
  /** The navigation sheet below `md`; never persisted. */
  sidebarOpen: boolean
  refreshIntervalMs: number
  /** The events list follows the refresh interval; off by default so rows stay still while selecting. */
  eventsLive: boolean
  toggleSidebar: () => void
  setSidebarOpen: (open: boolean) => void
  setRefreshIntervalMs: (value: number) => void
  setEventsLive: (live: boolean) => void
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      sidebarOpen: false,
      refreshIntervalMs: DEFAULT_REFRESH_MS,
      eventsLive: false,

      toggleSidebar() {
        set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed }))
      },
      setSidebarOpen(open) {
        set({ sidebarOpen: open })
      },
      setRefreshIntervalMs(value) {
        if (value === 0 || (value >= 1000 && value <= 600_000)) {
          set({ refreshIntervalMs: value })
        }
      },
      setEventsLive(live) {
        set({ eventsLive: live })
      },
    }),
    {
      name: "falcosidekick-ui",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
        refreshIntervalMs: state.refreshIntervalMs,
        eventsLive: state.eventsLive,
      }),
    },
  ),
)
