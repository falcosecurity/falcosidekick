import { Activity, LayoutDashboard, Network, SlidersHorizontal } from "lucide-react"
import { NavLink } from "react-router"

import logoIcon from "@/assets/logo-icon.svg"
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { MEDIA_LG, MEDIA_MD, useMediaQuery } from "@/hooks/use-media-query"
import { useReturnFocus } from "@/hooks/use-return-focus"
import { cn } from "@/lib/utils"
import { useUIStore } from "@/stores/ui-store"

interface NavItem {
  to: string
  label: string
  icon: typeof LayoutDashboard
}

export const NAV_ITEMS: readonly NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/events", label: "Events", icon: Activity },
  { to: "/pipeline", label: "Pipeline", icon: Network },
  { to: "/configuration", label: "Configuration", icon: SlidersHorizontal },
] as const

const LINK_CLASS =
  "group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-sidebar-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring focus-visible:ring-offset-1 focus-visible:ring-offset-sidebar aria-[current=page]:bg-sidebar-accent aria-[current=page]:text-sidebar-primary aria-[current=page]:shadow-[inset_2px_0_0_var(--sidebar-primary)]"

function SidebarNav({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  return (
    <>
      <div className="flex h-14 items-center gap-2 border-b border-sidebar-border px-3">
        <img src={logoIcon} alt="" aria-hidden className="size-8 shrink-0" />
        {!collapsed && (
          <div className="flex flex-col leading-tight">
            <span className="text-sm font-semibold">Falco Sidekick</span>
            <span className="text-2xs uppercase tracking-wider text-muted-foreground">v3</span>
          </div>
        )}
      </div>

      <nav className="flex-1 px-2 py-3" aria-label="Primary">
        <ul className="flex flex-col gap-0.5">
          {NAV_ITEMS.map((item) => {
            const link = (
              <NavLink
                to={item.to}
                end={item.to === "/"}
                onClick={onNavigate}
                className={cn(LINK_CLASS, collapsed && "justify-center px-0")}
              >
                <item.icon className="size-4 shrink-0" aria-hidden />
                <span className={cn(collapsed && "sr-only")}>{item.label}</span>
              </NavLink>
            )
            return (
              <li key={item.to}>
                {collapsed ? (
                  <Tooltip>
                    <TooltipTrigger asChild>{link}</TooltipTrigger>
                    <TooltipContent side="right">{item.label}</TooltipContent>
                  </Tooltip>
                ) : (
                  link
                )}
              </li>
            )
          })}
        </ul>
      </nav>
    </>
  )
}

export function NavSidebar() {
  const isDesktop = useMediaQuery(MEDIA_MD)
  const isWide = useMediaQuery(MEDIA_LG)
  const collapsedPreference = useUIStore((s) => s.sidebarCollapsed)
  const open = useUIStore((s) => s.sidebarOpen)
  const setOpen = useUIStore((s) => s.setSidebarOpen)
  const returnFocus = useReturnFocus()

  if (!isDesktop) {
    return (
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent {...returnFocus} side="left" className="flex w-64 flex-col gap-0 bg-sidebar p-0 text-sidebar-foreground" aria-label="Navigation">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SheetDescription className="sr-only">Pages of this Falco Sidekick instance.</SheetDescription>
          <SidebarNav collapsed={false} onNavigate={() => setOpen(false)} />
        </SheetContent>
      </Sheet>
    )
  }

  const collapsed = !isWide || collapsedPreference
  return (
    <aside
      data-collapsed={collapsed}
      className={cn(
        "flex h-full shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-[width] duration-150",
        collapsed ? "w-14" : "w-60",
      )}
    >
      <SidebarNav collapsed={collapsed} />
    </aside>
  )
}
