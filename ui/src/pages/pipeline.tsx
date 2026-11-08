import { Maximize2, Plus } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useGroupRef } from "react-resizable-panels"

import { EmptyState } from "@/components/common/empty-state"
import { ErrorState } from "@/components/common/error-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import { DeleteOutputDialog } from "@/components/outputs/delete-output-dialog"
import { OutputWizard, type WizardTarget } from "@/components/outputs/wizard/output-wizard"
import {
  PipelineCanvas,
  type PipelineCanvasHandle,
  type PipelineSelection,
} from "@/components/pipeline/canvas"
import { PipelineDetailPanel, type OutputActions } from "@/components/pipeline/detail-panel"
import { PipelineList } from "@/components/pipeline/pipeline-list"
import { Button } from "@/components/ui/button"
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable"
import { ScrollArea } from "@/components/ui/scroll-area"
import { useConfig } from "@/hooks/use-config"
import { MEDIA_MD, useMediaQuery } from "@/hooks/use-media-query"
import { usePipelineComposite, usePipelineStatus } from "@/hooks/use-pipeline"
import { errorMessage } from "@/lib/api-error"
import type { OutputConfigEntry } from "@/lib/types"
import { cn } from "@/lib/utils"
import { usePipelineStore } from "@/stores/pipeline-store"

export function PipelinePage() {
  usePipelineStatus()
  const { data: composite, isPending, isError, error } = usePipelineComposite()
  const config = useConfig()
  const statusByName = usePipelineStore((s) => s.statusByName)
  const [selection, setSelection] = useState<PipelineSelection>(null)
  const [wizard, setWizardTarget] = useState<WizardTarget | null>(null)
  // A new session per opening resets the wizard; closing keeps it mounted so the sheet animates out
  // and returns focus to its opener.
  const [wizardSession, setWizardSession] = useState(0)
  const setWizard = useCallback((target: WizardTarget | null) => {
    if (target) setWizardSession((n) => n + 1)
    setWizardTarget(target)
  }, [])
  const [removing, setRemoving] = useState<OutputConfigEntry | null>(null)
  const writes = config.data?.config.api.allow_writes === true
  const fileOutputsWritable = config.data?.config.provisioning.allow_ui_updates === true
  const openCreate = useCallback(() => setWizard({ kind: "create" }), [setWizard])
  const canvasRef = useRef<PipelineCanvasHandle>(null)
  const wide = useMediaQuery(MEDIA_MD)
  const groupRef = useGroupRef()
  const containerRef = useRef<HTMLDivElement>(null)
  const [orientation, setOrientation] = useState<"horizontal" | "vertical">("vertical")
  const stacked = orientation === "vertical"
  // The canvas waits for the configuration so the "Add output" node is laid out with the rest, once.
  const loading = isPending || config.isPending
  const panelsReady = !loading && !isError && composite != null

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

  // The API refuses changes to outputs from the output files unless provisioning.allow_ui_updates.
  const actions = useMemo<OutputActions | undefined>(() => {
    if (!writes || !selectedEntry || (selectedEntry.provisioned && !fileOutputsWritable)) return undefined
    return {
      onEdit: () => setWizard({ kind: "edit", name: selectedEntry.name }),
      onDelete: () => setRemoving(selectedEntry),
    }
  }, [writes, fileOutputsWritable, selectedEntry, setWizard])

  return (
    <div ref={containerRef} className="flex h-full min-h-0 min-w-0 flex-col gap-4 overflow-y-auto">
      <PageHeader
        title="Pipeline"
        description={[
          wide ? "Click a node to inspect it; drag to rearrange." : "Tap an entry to inspect it.",
          config.isSuccess && !writes ? "Changes are disabled (api.allow_writes)." : "",
        ]
          .filter(Boolean)
          .join(" ")}
        actions={
          <>
            {wide && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => canvasRef.current?.resetPositions()}
                disabled={!composite}
              >
                <Maximize2 className="size-3.5" aria-hidden />
                Reset layout
              </Button>
            )}
            {writes && (
              <Button size="sm" onClick={openCreate}>
                <Plus className="size-3.5" aria-hidden />
                Add output
              </Button>
            )}
          </>
        }
      />
      <OutputWizard
        key={wizardSession}
        target={wizard}
        onClose={() => setWizard(null)}
        onSaved={(name) => setSelection({ kind: "sink", name })}
      />
      <DeleteOutputDialog
        entry={removing}
        onClose={() => setRemoving(null)}
        onDeleted={() => setSelection(null)}
      />

      {loading ? (
        <LoadingSkeleton lines={8} />
      ) : isError ? (
        <ErrorState title="Unable to load the pipeline" description={errorMessage(error)} />
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
              {/* Below md the canvas would shrink to unreadable text: the same pipeline as a list. */}
              {wide ? (
                <PipelineCanvas
                  ref={canvasRef}
                  composite={composite}
                  statusByName={statusByName}
                  selection={selection}
                  onSelect={handleSelect}
                  onAdd={writes ? openCreate : undefined}
                />
              ) : (
                <ScrollArea className="h-full">
                  <PipelineList
                    composite={composite}
                    statusByName={statusByName}
                    selection={selection}
                    onSelect={handleSelect}
                    onAdd={writes ? openCreate : undefined}
                  />
                </ScrollArea>
              )}
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel id="pipeline-detail-panel" defaultSize={stacked ? "50%" : "30%"} minSize={stacked ? "440px" : "280px"}>
            <div className={cn("h-full min-h-0 min-w-0", stacked ? "pt-2" : "pl-2")}>
              <PipelineDetailPanel
                selection={selection}
                entry={selectedEntry}
                status={selectedStatus}
                actions={actions}
              />
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      )}
    </div>
  )
}

export default PipelinePage
