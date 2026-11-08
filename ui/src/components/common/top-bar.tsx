import { PanelLeft } from "lucide-react"
import { useLocation } from "react-router"

import { AuthDisabledBanner } from "@/components/common/auth-disabled-banner"
import { NAV_ITEMS } from "@/components/common/nav-sidebar"
import { RefreshIntervalSelector } from "@/components/common/refresh-interval"
import { ThemeToggle } from "@/components/common/theme-toggle"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { useUIStore } from "@/stores/ui-store"

export function TopBar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed)
  const toggleSidebar = useUIStore((s) => s.toggleSidebar)
  const setSidebarOpen = useUIStore((s) => s.setSidebarOpen)
  const location = useLocation()
  const label = NAV_ITEMS.find((item) => item.to === location.pathname)?.label ?? "Falcosidekick"

  return (
    <header className="sticky top-0 z-20 border-b border-border/60 bg-background/90 backdrop-blur">
      <div className="flex h-14 items-center gap-2 px-3 sm:px-4">
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          onClick={() => setSidebarOpen(true)}
          aria-label="Open navigation"
        >
          <PanelLeft className="size-4" aria-hidden />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="hidden lg:inline-flex"
          onClick={toggleSidebar}
          aria-pressed={collapsed}
          aria-label="Collapse navigation sidebar"
        >
          <PanelLeft className="size-4" aria-hidden />
        </Button>
        <div className="min-w-0 flex-1 truncate text-sm font-medium text-muted-foreground">{label}</div>
        <div className="flex shrink-0 items-center gap-1 sm:gap-2">
          <RefreshIntervalSelector />
          <Separator orientation="vertical" className="mx-1 hidden h-5 sm:block" />
          <AuthDisabledBanner compact />
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
