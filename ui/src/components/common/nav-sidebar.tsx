import { Activity, LayoutDashboard, Network, Settings } from "lucide-react"
import { NavLink } from "react-router"

import logoIcon from "@/assets/logo-icon.svg"
import { cn } from "@/lib/utils"
import { useUIStore } from "@/stores/ui-store"

interface NavItem {
  to: string
  label: string
  icon: typeof LayoutDashboard
}

const ITEMS: readonly NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/events", label: "Events", icon: Activity },
  { to: "/pipeline", label: "Pipeline", icon: Network },
  { to: "/settings", label: "Settings", icon: Settings },
] as const

export function NavSidebar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed)

  return (
    <aside
      className={cn(
        "flex h-full shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-[width] duration-150",
        collapsed ? "w-14" : "w-60",
      )}
      aria-label="Primary navigation"
    >
      <div className="flex h-14 items-center gap-2 border-b border-sidebar-border px-3">
        <img src={logoIcon} alt="" aria-hidden className="size-8 shrink-0" />
        {!collapsed && (
          <div className="flex flex-col leading-tight">
            <span className="text-sm font-semibold">Falco Sidekick</span>
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">v3</span>
          </div>
        )}
      </div>

      <nav className="flex-1 px-2 py-3">
        <ul className="flex flex-col gap-0.5">
          {ITEMS.map((item) => (
            <li key={item.to}>
              <NavLink
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  cn(
                    "group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                    "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring focus-visible:ring-offset-1 focus-visible:ring-offset-sidebar",
                    isActive &&
                      "bg-sidebar-accent text-sidebar-primary border-l-2 border-sidebar-primary -ml-0.5 pl-[10px]",
                  )
                }
                aria-label={item.label}
              >
                <item.icon className="size-4 shrink-0" aria-hidden />
                {!collapsed && <span>{item.label}</span>}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      <div className="border-t border-sidebar-border p-3 text-[11px] text-muted-foreground">
        {!collapsed && "Press ⌘K to search"}
      </div>
    </aside>
  )
}
