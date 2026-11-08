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
  sidebarCollapsed: boolean
  refreshIntervalMs: number
  authEnabled: boolean | null
  toggleSidebar: () => void
  setRefreshIntervalMs: (value: number) => void
  setAuthEnabled: (value: boolean | null) => void
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      refreshIntervalMs: DEFAULT_REFRESH_MS,
      authEnabled: null,

      toggleSidebar() {
        set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed }))
      },
      setRefreshIntervalMs(value) {
        if (value === 0 || (value >= 1000 && value <= 600_000)) {
          set({ refreshIntervalMs: value })
        }
      },
      setAuthEnabled(value) {
        set({ authEnabled: value })
      },
    }),
    {
      name: "falcosidekick-ui",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
        refreshIntervalMs: state.refreshIntervalMs,
      }),
    },
  ),
)
