import { createElement } from "react"

import { iconForOutputType } from "@/lib/output-icons"
import { cn } from "@/lib/utils"

type Variant = "brand" | "neutral"
type Size = "sm" | "md" | "lg"

interface OutputTypeIconProps {
  type?: string
  name?: string
  variant?: Variant
  size?: Size
  className?: string
}

const CONTAINER_SIZE: Record<Size, string> = {
  sm: "size-8",
  md: "size-10",
  lg: "size-12",
}

const ICON_SIZE: Record<Size, string> = {
  sm: "size-4",
  md: "size-5",
  lg: "size-6",
}

const VARIANT_CLASS: Record<Variant, string> = {
  brand: "bg-brand/15 text-brand",
  neutral: "bg-muted text-muted-foreground",
}

export function OutputTypeIcon({
  type,
  name,
  variant = "neutral",
  size = "md",
  className,
}: OutputTypeIconProps) {
  return (
    <span
      className={cn(
        "flex shrink-0 items-center justify-center rounded-md",
        CONTAINER_SIZE[size],
        VARIANT_CLASS[variant],
        className,
      )}
    >
      {createElement(iconForOutputType(type, name), {
        className: ICON_SIZE[size],
        "aria-hidden": true,
      })}
    </span>
  )
}
