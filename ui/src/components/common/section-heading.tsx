import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

interface SectionHeadingProps {
  level?: 2 | 3
  className?: string
  children: ReactNode
}

export function SectionHeading({ level = 3, className, children }: SectionHeadingProps) {
  const Tag = level === 2 ? "h2" : "h3"
  return (
    <Tag className={cn("text-xs font-semibold uppercase tracking-wider text-muted-foreground", className)}>
      {children}
    </Tag>
  )
}
