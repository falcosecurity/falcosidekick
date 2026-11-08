import { useEffect, type ReactNode } from "react"

import { cn } from "@/lib/utils"

const APP_TITLE = "Falcosidekick"

interface PageHeaderProps {
  title: string
  description?: string
  actions?: ReactNode
  className?: string
}

/** The page heading; it also names the browser tab, so history and screen readers tell the pages apart. */
export function PageHeader({ title, description, actions, className }: PageHeaderProps) {
  useEffect(() => {
    document.title = `${title} · ${APP_TITLE}`
    return () => {
      document.title = APP_TITLE
    }
  }, [title])
  return (
    <header className={cn("flex flex-col gap-2 border-b border-border/60 pb-4 md:flex-row md:items-end md:justify-between", className)}>
      <div className="flex min-w-0 flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">{title}</h1>
        {description && <p className="text-sm text-muted-foreground [overflow-wrap:anywhere]">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2 md:shrink-0 md:flex-nowrap">{actions}</div>}
    </header>
  )
}
