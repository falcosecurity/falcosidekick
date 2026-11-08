import { Maximize2 } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useGroupRef } from "react-resizable-panels"

import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import {
  PipelineCanvas,
  type PipelineCanvasHandle,
  type PipelineSelection,
} from "@/components/pipeline/canvas"
import { PipelineDetailPanel } from "@/components/pipeline/detail-panel"
import { Button } from "@/components/ui/button"
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable"
import { usePipelineComposite, usePipelineStatus } from "@/hooks/use-pipeline"
import { cn } from "@/lib/utils"
import { usePipelineStore } from "@/stores/pipeline-store"

export function PipelinePage() {
  usePipelineStatus()
  const { data: composite, isPending, isError, error } = usePipelineComposite()
  const statusByName = usePipelineStore((s) => s.statusByName)
  const [selection, setSelection] = useState<PipelineSelection>(null)
  const canvasRef = useRef<PipelineCanvasHandle>(null)
  const groupRef = useGroupRef()
  const containerRef = useRef<HTMLDivElement>(null)
  const [orientation, setOrientation] = useState<"horizontal" | "vertical">("vertical")
  const stacked = orientation === "vertical"
  const panelsReady = !isPending && !isError && composite != null

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    let active = true
    const observer = new ResizeObserver(([entry]) => {
      if (!active || !entry || entry.contentRect.width <= 0) return
      setOrientation(entry.contentRect.width >= 900 ? "horizontal" : "vertical")
    })
    observer.observe(container)
    return () => {
      active = false
      observer.disconnect()
    }
  }, [])

  useEffect(() => {
    if (panelsReady) {
      groupRef.current?.setLayout({
        "pipeline-canvas-panel": stacked ? 50 : 70,
        "pipeline-detail-panel": stacked ? 50 : 30,
      })
    }
  }, [groupRef, panelsReady, stacked])

  const handleSelect = useCallback((sel: PipelineSelection) => {
    setSelection((prev) => {
      if (sel && prev && sel.kind === prev.kind) {
        if (sel.kind === "sink" && prev.kind === "sink" && sel.name === prev.name) {
          return null
        }
        if (sel.kind !== "sink") {
          return null
        }
      }
      return sel
    })
  }, [])

  const selectedEntry = useMemo(() => {
    if (!composite || selection?.kind !== "sink") return null
    return composite.outputs.find((o) => o.name === selection.name) ?? null
  }, [composite, selection])

  const selectedStatus = useMemo(() => {
    if (selection?.kind !== "sink") return null
    return statusByName[selection.name] ?? null
  }, [statusByName, selection])

  return (
    <div ref={containerRef} className="flex h-full min-h-0 min-w-0 flex-col gap-4 overflow-y-auto">
      <PageHeader
        title="Pipeline"
        description="Read-only view of the event pipeline. Click any node to inspect it; drag to rearrange."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => canvasRef.current?.resetPositions()}
            disabled={!composite}
          >
            <Maximize2 className="mr-1 size-3.5" aria-hidden />
            Reset layout
          </Button>
        }
      />

      {isPending ? (
        <LoadingSkeleton lines={8} />
      ) : isError ? (
        <EmptyState
          title="Unable to load pipeline"
          description={error instanceof Error ? error.message : "Unknown error"}
        />
      ) : !composite ? (
        <EmptyState title="Pipeline is empty" />
      ) : (
        <ResizablePanelGroup
          groupRef={groupRef}
          orientation={orientation}
          className={cn("flex-1 rounded-lg", stacked ? "min-h-[800px]" : "min-h-0")}
          id="pipeline-layout"
        >
          <ResizablePanel id="pipeline-canvas-panel" defaultSize={stacked ? "50%" : "70%"} minSize={stacked ? "300px" : "320px"}>
            <div className={cn("relative h-full min-h-0 min-w-0", stacked ? "pb-2" : "pr-2")}>
              <PipelineCanvas
                ref={canvasRef}
                composite={composite}
                statusByName={statusByName}
                selection={selection}
                onSelect={handleSelect}
              />
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel id="pipeline-detail-panel" defaultSize={stacked ? "50%" : "30%"} minSize={stacked ? "440px" : "280px"}>
            <div className={cn("h-full min-h-0 min-w-0", stacked ? "pt-2" : "pl-2")}>
              <PipelineDetailPanel
                selection={selection}
                entry={selectedEntry}
                status={selectedStatus}
              />
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      )}
    </div>
  )
}

export default PipelinePage
