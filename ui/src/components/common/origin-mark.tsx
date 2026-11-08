import { Cloud, FileText } from "lucide-react"

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

const ORIGIN_COLOR = "text-muted-foreground"

function originOf(provisioned: boolean) {
  return provisioned
    ? { Icon: FileText, label: "File provisioned" }
    : { Icon: Cloud, label: "API provisioned" }
}

// OriginMark tells where an output comes from. With showLabel the label is visible; without it the
// mark is an icon with a tooltip for hover and sr-only text, and it is not focusable because it
// sits inside buttons.
export function OriginMark({
  provisioned,
  showLabel = false,
  className,
}: {
  provisioned: boolean
  showLabel?: boolean
  className?: string
}) {
  const { Icon, label } = originOf(provisioned)
  if (showLabel) {
    return (
      <span className={cn("inline-flex items-center gap-1.5", className)}>
        <Icon className={cn("size-3.5 shrink-0", ORIGIN_COLOR)} aria-hidden />
        {label}
      </span>
    )
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={cn("shrink-0", ORIGIN_COLOR, className)}>
          <Icon className="size-3.5" aria-hidden />
          <span className="sr-only">{label}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}
