import { Copy, FileCode2, X } from "lucide-react"
import { useRef } from "react"
import { toast } from "sonner"

import { ConfigTree } from "@/components/common/config-tree"
import { PriorityBadge } from "@/components/common/priority-badge"
import { TimeAgo } from "@/components/common/time-ago"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { formatAbsoluteTime } from "@/lib/format"
import type { Event } from "@/lib/types"

interface EventDetailDrawerProps {
  event: Event | null
  open: boolean
  onClose: () => void
  onCloseAutoFocus?: React.ComponentProps<typeof SheetContent>["onCloseAutoFocus"]
}

export function EventDetailDrawer({ event, open, onClose, onCloseAutoFocus }: EventDetailDrawerProps) {
  const closeButton = useRef<HTMLButtonElement>(null)
  const opener = useRef<HTMLElement | null>(null)

  async function copyText(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text)
      toast.success(`${label} copied`)
    } catch {
      toast.error("Unable to copy")
    }
  }

  return (
    <Sheet open={open} onOpenChange={(v) => !v && onClose()}>
      <SheetContent
        side="right"
        className="flex w-full flex-col gap-0 p-0 sm:max-w-xl"
        showCloseButton={false}
        onOpenAutoFocus={(e) => {
          opener.current = document.activeElement instanceof HTMLElement
            ? document.activeElement
            : null
          e.preventDefault()
          closeButton.current?.focus()
        }}
        onCloseAutoFocus={(e) => {
          if (onCloseAutoFocus) {
            onCloseAutoFocus(e)
          } else if (opener.current?.isConnected) {
            e.preventDefault()
            opener.current.focus()
          }
        }}
      >
        <SheetClose asChild>
          <Button
            ref={closeButton}
            variant="ghost"
            size="icon-sm"
            className="absolute top-4 right-4"
            aria-label="Close"
          >
            <X aria-hidden />
          </Button>
        </SheetClose>
        {event && (
          <>
            <SheetHeader className="gap-3 border-b pt-6 pr-14 pb-4 pl-6">
              <div className="flex items-start gap-3">
                <PriorityBadge priority={event.priority} className="mt-0.5" />
                <SheetTitle className="flex-1 text-base leading-snug">{event.rule}</SheetTitle>
              </div>
              <SheetDescription className="sr-only">{event.output}</SheetDescription>
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono">{event.uuid}</code>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-6 px-2"
                  onClick={() => copyText(event.uuid, "UUID")}
                >
                  <Copy className="mr-1 size-3" aria-hidden /> UUID
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-6 px-2"
                  onClick={() => copyText(JSON.stringify(event, null, 2), "Event JSON")}
                >
                  <FileCode2 className="mr-1 size-3" aria-hidden /> JSON
                </Button>
              </div>
            </SheetHeader>

            <ScrollArea className="flex-1">
              <div className="flex flex-col gap-6 px-6 py-5">
                <section className="grid grid-cols-2 gap-3">
                  <MetaTile label="Time">
                    <div className="text-sm">{formatAbsoluteTime(event.time)}</div>
                    <div className="text-xs text-muted-foreground">
                      <TimeAgo value={event.time} />
                    </div>
                  </MetaTile>
                  <MetaTile label="Source">
                    <Badge variant="outline" className="font-mono text-xs">
                      {event.source}
                    </Badge>
                  </MetaTile>
                  {event.hostname && (
                    <MetaTile label="Hostname">
                      <code className="font-mono text-xs">{event.hostname}</code>
                    </MetaTile>
                  )}
                  {event.tags && event.tags.length > 0 && (
                    <MetaTile label="Tags">
                      <div className="flex flex-wrap gap-1">
                        {event.tags.map((t) => (
                          <Badge key={t} variant="secondary" className="text-[10px] font-normal">
                            {t}
                          </Badge>
                        ))}
                      </div>
                    </MetaTile>
                  )}
                </section>

                <section className="flex flex-col gap-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Rendered output
                  </h3>
                  <blockquote className="border-l-2 border-brand/60 bg-muted/40 px-3 py-2 text-sm leading-relaxed">
                    {event.output}
                  </blockquote>
                </section>

                <Separator />

                <section className="flex flex-col gap-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Output fields
                  </h3>
                  <ConfigTree data={event.output_fields} />
                </section>
              </div>
            </ScrollArea>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}

function MetaTile({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border bg-card/50 p-3">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mt-1">{children}</div>
    </div>
  )
}
