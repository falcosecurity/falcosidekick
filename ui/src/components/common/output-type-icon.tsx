import { createElement } from "react"

import { DRIVER_LOGOS } from "@/lib/driver-logos"
import { iconForDriver } from "@/lib/output-icons"
import { cn } from "@/lib/utils"

type Size = "sm" | "md" | "lg"

interface OutputTypeIconProps {
  driver: string
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

// Brand marks keep their original colors, some of them near black, so every driver sits on the
// same light plate in both themes.
const PLATE = "bg-white text-neutral-700 ring-1 ring-black/10"

export function OutputTypeIcon({ driver, size = "md", className }: OutputTypeIconProps) {
  const icon = iconForDriver(driver)
  return (
    <span
      data-driver={driver}
      className={cn("flex shrink-0 items-center justify-center rounded-md", CONTAINER_SIZE[size], PLATE, className)}
    >
      {icon.kind === "logo" && (
        <svg viewBox="0 0 24 24" className={ICON_SIZE[size]} fill={DRIVER_LOGOS[icon.logo].color} aria-hidden>
          <path d={DRIVER_LOGOS[icon.logo].path} />
        </svg>
      )}
      {icon.kind === "asset" && <img src={icon.src} alt="" className={ICON_SIZE[size]} aria-hidden />}
      {icon.kind === "icon" && createElement(icon.icon, { className: ICON_SIZE[size], "aria-hidden": true })}
    </span>
  )
}
