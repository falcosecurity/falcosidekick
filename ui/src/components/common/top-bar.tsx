import { PanelLeft } from "lucide-react"
import { useLocation } from "react-router"

import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { AuthDisabledBanner } from "@/components/common/auth-disabled-banner"
import { RefreshIntervalSelector } from "@/components/common/refresh-interval"
import { ThemeToggle } from "@/components/common/theme-toggle"
import { useUIStore } from "@/stores/ui-store"

const ROUTE_LABEL: Record<string, string> = {
  "/": "Dashboard",
  "/events": "Events",
  "/pipeline": "Pipeline",
  "/settings": "Settings",
  "/login": "Sign in",
};

export function TopBar() {
  const toggleSidebar = useUIStore((s) => s.toggleSidebar)
  const location = useLocation()
  const label = ROUTE_LABEL[location.pathname] ?? "Falcosidekick"

  return (
    <div className="sticky top-0 z-20 border-b border-border/60 bg-background/90 backdrop-blur">
      <div className="grid h-24 grid-cols-[auto_minmax(0,1fr)] grid-rows-2 items-center gap-x-2 px-2 py-2 sm:h-14 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:grid-rows-1 sm:px-4 sm:py-0">
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          aria-label="Toggle navigation sidebar"
        >
          <PanelLeft className="size-4" aria-hidden />
        </Button>
        <div className="min-w-0 truncate text-sm font-medium text-muted-foreground">
          {label}
        </div>
        <div className="col-span-2 flex min-w-0 items-center justify-end gap-1 sm:col-span-1 sm:gap-2">
          <RefreshIntervalSelector />
          <Separator orientation="vertical" className="mx-1 h-5" />
          <AuthDisabledBanner compact />
          <ThemeToggle />
        </div>
      </div>
    </div>
  );
}
