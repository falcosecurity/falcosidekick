import { ChevronRight, Plus, Server } from "lucide-react"
import type { ReactNode } from "react"

import falcoIcon from "@/assets/falco-icon.svg"
import { OriginMark } from "@/components/common/origin-mark"
import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { StatusBadge } from "@/components/common/status-badge"
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemMedia, ItemTitle } from "@/components/ui/item"
import { statusOf, type OutputStatus, type PipelineComposite } from "@/lib/types"

import type { PipelineSelection } from "./canvas"

interface PipelineListProps {
  composite: PipelineComposite
  statusByName: Record<string, OutputStatus>
  selection: PipelineSelection
  onSelect: (selection: PipelineSelection) => void
  onAdd?: () => void
}

function Row({
  media,
  title,
  description,
  actions,
  selected,
  onClick,
}: {
  media: ReactNode
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  selected?: boolean
  onClick: () => void
}) {
  return (
    <Item asChild variant="outline" size="sm" className="bg-card data-[selected=true]:border-brand data-[selected=true]:ring-1 data-[selected=true]:ring-brand">
      <button type="button" onClick={onClick} data-selected={selected || undefined} aria-pressed={selected}>
        <ItemMedia>{media}</ItemMedia>
        <ItemContent className="min-w-0 text-left">
          <ItemTitle className="w-full">{title}</ItemTitle>
          {description && <ItemDescription>{description}</ItemDescription>}
        </ItemContent>
        <ItemActions>
          {actions}
          <ChevronRight className="size-4 text-muted-foreground" aria-hidden />
        </ItemActions>
      </button>
    </Item>
  )
}

/** The pipeline as a list, for screens too narrow for the canvas. */
export function PipelineList({ composite, statusByName, selection, onSelect, onAdd }: PipelineListProps) {
  return (
    // Groups, not lists: the entries are buttons.
    <ItemGroup role="group" className="gap-2" aria-label="Pipeline">
      <Row
        media={
          <span className="flex size-8 items-center justify-center rounded-md bg-brand/15">
            <img src={falcoIcon} alt="" aria-hidden className="size-5" />
          </span>
        }
        title="Falco"
        description="event source"
        selected={selection?.kind === "source"}
        onClick={() => onSelect({ kind: "source" })}
      />
      <Row
        media={
          <span className="flex size-8 items-center justify-center rounded-md bg-brand text-brand-foreground">
            <Server className="size-4" aria-hidden />
          </span>
        }
        title="Falco Sidekick"
        description="event pipeline"
        selected={selection?.kind === "core"}
        onClick={() => onSelect({ kind: "core" })}
      />
      <ItemGroup role="group" className="ml-4 gap-2 border-l pl-3" aria-label="Outputs">
        {composite.outputs.map((out) => {
          const status = statusByName[out.name]
          return (
            <Row
              key={out.name}
              media={<OutputTypeIcon driver={out.name} size="sm" />}
              title={
                <span className="flex min-w-0 items-center gap-1.5">
                  <span className="truncate">{out.name}</span>
                  <OriginMark provisioned={out.provisioned} />
                </span>
              }
              actions={status && <StatusBadge status={statusOf(status)} />}
              selected={selection?.kind === "sink" && selection.name === out.name}
              onClick={() => onSelect({ kind: "sink", name: out.name })}
            />
          )
        })}
        {onAdd && (
          <Item asChild variant="outline" size="sm" className="border-dashed bg-transparent text-muted-foreground">
            <button type="button" onClick={onAdd}>
              <ItemMedia>
                <Plus className="size-4" aria-hidden />
              </ItemMedia>
              <ItemContent>
                <ItemTitle>Add output</ItemTitle>
              </ItemContent>
            </button>
          </Item>
        )}
      </ItemGroup>
    </ItemGroup>
  )
}
