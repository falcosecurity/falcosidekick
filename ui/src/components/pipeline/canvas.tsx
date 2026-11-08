import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useNodesInitialized,
  useNodesState,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react"
import ELK, { type ElkNode } from "elkjs/lib/elk.bundled.js"

import { centerOnCore } from "./center-on-core"
import { Server } from "lucide-react"
import {
  forwardRef,
  useCallback,
  useEffect,
  useEffectEvent,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react"

import falcoIcon from "@/assets/falco-icon.svg"
import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { StatusBadge } from "@/components/common/status-badge"
import { cn } from "@/lib/utils"
import type { OutputHealth, OutputStatus, PipelineComposite } from "@/lib/types"
import { isFlowing, statusOf } from "@/lib/types"

import "@xyflow/react/dist/style.css"

type NodeKind = "source" | "core" | "sink"

type KindData = {
  kind: NodeKind
  label: string
  subtype?: string
  status?: OutputStatus
  outputName?: string
  onSelect?: () => void
  selected?: boolean
}

type FlowNode = Node<KindData, NodeKind>
type FlowEdge = Edge

const elk = new ELK()
// NodeCard is w-58; its height follows its content, so the centering uses the measured height.
const NODE_WIDTH = 232
const NODE_HEIGHT = 96
const HIDDEN_HANDLE: React.CSSProperties = {
  width: 1,
  height: 1,
  background: "transparent",
  border: "none",
  opacity: 0,
  pointerEvents: "none",
}

function NodeCard({
  iconSlot,
  title,
  subtitle,
  accent,
  status,
  onSelect,
  selected,
  sourceHandle,
  targetHandle,
}: {
  iconSlot: ReactNode
  title: string
  subtitle?: string
  accent: "brand" | "neutral" | "solid"
  status?: OutputStatus
  onSelect?: () => void
  selected?: boolean
  sourceHandle?: boolean
  targetHandle?: boolean
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "nopan relative flex w-58 items-center gap-3 rounded-lg border bg-card px-3 py-3 text-left shadow-sm transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        onSelect ? "cursor-pointer hover:border-foreground/30" : "cursor-default",
        accent === "brand" && "border-brand/40",
        accent === "solid" &&
          "border-2 border-brand bg-brand/10 ring-2 ring-brand/30 ring-offset-0 shadow-md shadow-brand/15 hover:border-brand",
        selected && "ring-2 ring-brand",
      )}
    >
      {targetHandle && <Handle type="target" position={Position.Left} style={HIDDEN_HANDLE} />}
      {iconSlot}
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-semibold">{title}</div>
        {subtitle && <div className="truncate text-xs text-muted-foreground">{subtitle}</div>}
        {status && (
          <div className="mt-1">
            <StatusBadge status={statusOf(status)} />
          </div>
        )}
      </div>
      {sourceHandle && <Handle type="source" position={Position.Right} style={HIDDEN_HANDLE} />}
    </button>
  )
}

function BrandedIcon({ children }: { children: ReactNode }) {
  return (
    <span className="flex size-10 shrink-0 items-center justify-center rounded-md bg-brand/15 text-brand">
      {children}
    </span>
  )
}

function SolidBrandedIcon({ children }: { children: ReactNode }) {
  return (
    <span className="flex size-10 shrink-0 items-center justify-center rounded-md bg-brand text-brand-foreground shadow-sm">
      {children}
    </span>
  )
}

function SourceFlowNode({ data }: NodeProps<FlowNode>) {
  return (
    <NodeCard
      iconSlot={
        <BrandedIcon>
          <img src={falcoIcon} alt="" aria-hidden className="size-6" />
        </BrandedIcon>
      }
      title={data.label}
      subtitle={data.subtype}
      accent="brand"
      onSelect={data.onSelect}
      selected={data.selected}
      sourceHandle
    />
  )
}

function CoreFlowNode({ data }: NodeProps<FlowNode>) {
  return (
    <NodeCard
      iconSlot={
        <SolidBrandedIcon>
          <Server className="size-5" aria-hidden />
        </SolidBrandedIcon>
      }
      title={data.label}
      subtitle={data.subtype}
      accent="solid"
      onSelect={data.onSelect}
      selected={data.selected}
      sourceHandle
      targetHandle
    />
  )
}

function SinkFlowNode({ data }: NodeProps<FlowNode>) {
  return (
    <NodeCard
      iconSlot={<OutputTypeIcon driver={data.outputName ?? data.label} />}
      title={data.label}
      subtitle={data.subtype}
      accent="neutral"
      status={data.status}
      onSelect={data.onSelect}
      selected={data.selected}
      targetHandle
    />
  )
}

const nodeTypes = { source: SourceFlowNode, core: CoreFlowNode, sink: SinkFlowNode }

async function layoutElk(nodes: FlowNode[], edges: FlowEdge[]): Promise<FlowNode[]> {
  const graph: ElkNode = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.spacing.nodeNode": "32",
      "elk.layered.spacing.nodeNodeBetweenLayers": "90",
    },
    children: nodes.map((n) => ({ id: n.id, width: NODE_WIDTH, height: NODE_HEIGHT })),
    edges: edges.map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  }
  const positioned = await elk.layout(graph)
  const positionsById = new Map<string, { x: number; y: number }>()
  for (const child of positioned.children ?? []) {
    if (typeof child.x === "number" && typeof child.y === "number") {
      positionsById.set(child.id, { x: child.x, y: child.y })
    }
  }
  return centerOnCore(
    nodes.map((n) => {
      const pos = positionsById.get(n.id)
      return pos ? { ...n, position: pos } : n
    }),
    measuredHeight,
  )
}

function measuredHeight(node: FlowNode): number {
  return node.measured?.height ?? NODE_HEIGHT
}

export type PipelineSelection =
  | { kind: "source" }
  | { kind: "core" }
  | { kind: "sink"; name: string }
  | null

function anyFlowing(
  composite: PipelineComposite,
  statusByName: Record<string, OutputStatus>,
): boolean {
  return composite.outputs.some((o) => isFlowing(statusByName[o.name]))
}

function buildGraph(
  composite: PipelineComposite,
  statusByName: Record<string, OutputStatus>,
  selection: PipelineSelection,
  onSelect: (sel: PipelineSelection) => void,
): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const sourceSelected = selection?.kind === "source"
  const coreSelected = selection?.kind === "core"

  const nodes: FlowNode[] = [
    {
      id: "source:falco",
      type: "source",
      position: { x: 0, y: 0 },
      data: {
        kind: "source",
        label: "Falco",
        subtype: "event source",
        onSelect: () => onSelect({ kind: "source" }),
        selected: sourceSelected,
      },
    },
    {
      id: "core:sidekick",
      type: "core",
      position: { x: 0, y: 0 },
      data: {
        kind: "core",
        label: "Falco Sidekick",
        subtype: "event pipeline",
        onSelect: () => onSelect({ kind: "core" }),
        selected: coreSelected,
      },
    },
  ]
  const edges: FlowEdge[] = [
    {
      id: "falco->sidekick",
      source: "source:falco",
      target: "core:sidekick",
      markerEnd: { type: MarkerType.ArrowClosed },
      style: anyFlowing(composite, statusByName)
        ? { stroke: "var(--brand)", strokeWidth: 1.75 }
        : { stroke: "var(--brand)", strokeWidth: 1.5, strokeDasharray: "4 4" },
      animated: anyFlowing(composite, statusByName),
    },
  ]

  for (const out of composite.outputs) {
    const id = `sink:${out.name}`
    const status = statusByName[out.name]
    const sinkSelected = selection?.kind === "sink" && selection.name === out.name
    nodes.push({
      id,
      type: "sink",
      position: { x: 0, y: 0 },
      data: {
        kind: "sink",
        label: out.name,
        subtype: out.provisioned ? "from output files" : undefined,
        status,
        outputName: out.name,
        onSelect: () => onSelect({ kind: "sink", name: out.name }),
        selected: sinkSelected,
      },
    })
    edges.push({
      id: `sidekick->${out.name}`,
      source: "core:sidekick",
      target: id,
      markerEnd: { type: MarkerType.ArrowClosed },
      style: edgeStyleForStatus(status ? statusOf(status) : undefined),
      animated: isFlowing(status),
    })
  }

  return { nodes, edges }
}

function edgeStyleForStatus(status?: OutputHealth): React.CSSProperties {
  switch (status) {
    case "ok":
      return { stroke: "var(--status-ok)", strokeWidth: 1.75 }
    case "failed":
      return { stroke: "var(--status-error)", strokeWidth: 1.25, strokeDasharray: "4 4" }
    case "error":
      return { stroke: "var(--status-error)", strokeWidth: 1.5 }
    case "degraded":
      return { stroke: "var(--status-degraded)", strokeWidth: 1.5 }
    default:
      return { stroke: "var(--muted-foreground)", strokeWidth: 1.25, strokeDasharray: "4 4" }
  }
}

interface CanvasProps {
  composite: PipelineComposite
  statusByName: Record<string, OutputStatus>
  selection: PipelineSelection
  onSelect: (sel: PipelineSelection) => void
}

export interface PipelineCanvasHandle {
  resetPositions: () => void
}

function CanvasInner({
  composite,
  statusByName,
  selection,
  onSelect,
  handleRef,
}: CanvasProps & { handleRef: React.Ref<PipelineCanvasHandle> }) {
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([])
  const userPositions = useRef<Record<string, { x: number; y: number }>>({})
  const [layoutRevision, setLayoutRevision] = useState(0)
  const [layoutResult, setLayoutResult] = useState<{
    key: string
    revision: number
    error: boolean
  } | null>(null)

  const graphKey = JSON.stringify(composite.outputs.map((o) => [o.name, o.provisioned]))
  const graph = useMemo(
    () => buildGraph(composite, statusByName, selection, onSelect),
    [composite, statusByName, selection, onSelect],
  )
  const liveNodes = useMemo(() => {
    const dataById = new Map(graph.nodes.map((node) => [node.id, node.data]))
    return nodes.flatMap((node) => {
      const data = dataById.get(node.id)
      return data ? [{ ...node, data }] : []
    })
  }, [nodes, graph.nodes])
  const layoutPending = layoutResult?.key !== graphKey || layoutResult.revision !== layoutRevision

  // Polling and selection change node data, not the topology that ELK lays out.
  const runLayout = useEffectEvent(() => layoutElk(graph.nodes, graph.edges))

  useEffect(() => {
    let cancelled = false
    void runLayout().then(
      (positioned) => {
        if (cancelled) return
        setNodes((currentNodes) => {
          const currentById = new Map(currentNodes.map((node) => [node.id, node]))
          return positioned.map((node) => {
            const current = currentById.get(node.id)
            return {
              ...current,
              ...node,
              position: current?.dragging
                ? current.position
                : userPositions.current[node.id] ?? node.position,
              dragging: current?.dragging ?? false,
            }
          })
        })
        setLayoutResult({ key: graphKey, revision: layoutRevision, error: false })
      },
      () => {
        if (!cancelled) setLayoutResult({ key: graphKey, revision: layoutRevision, error: true })
      },
    )
    return () => {
      cancelled = true
    }
  }, [graphKey, layoutRevision, setNodes])

  // Heights follow the card content and are known once rendered: center again with them.
  const nodesMeasured = useNodesInitialized()
  useEffect(() => {
    if (!nodesMeasured || layoutPending) return
    setNodes((currentNodes) => {
      const centered = centerOnCore(currentNodes, measuredHeight)
      return centered.map((node, i) => {
        const current = currentNodes[i]
        return current && (current.dragging || userPositions.current[current.id]) ? current : node
      })
    })
  }, [nodesMeasured, layoutPending, setNodes])

  const handleNodesChange: typeof onNodesChange = useCallback(
    (changes) => {
      for (const change of changes) {
        if (change.type === "position" && !change.dragging && change.position) {
          userPositions.current[change.id] = { ...change.position }
        }
      }
      onNodesChange(changes)
    },
    [onNodesChange],
  )

  useImperativeHandle(
    handleRef,
    () => ({
      resetPositions: () => {
        userPositions.current = {}
        setLayoutRevision((revision) => revision + 1)
      },
    }),
    [],
  )

  return (
    <div className="pipeline-canvas h-full w-full rounded-lg border bg-card" aria-busy={layoutPending}>
      {!layoutPending && layoutResult?.error ? (
        <EmptyState title="Unable to lay out pipeline" />
      ) : liveNodes.length === 0 ? (
        <LoadingSkeleton lines={4} />
      ) : (
        <ReactFlow
          nodes={liveNodes}
          edges={graph.edges}
          nodeTypes={nodeTypes}
          onNodesChange={handleNodesChange}
          fitView
          fitViewOptions={{ padding: 0.25 }}
          minZoom={0.1}
          nodesDraggable
          nodesConnectable={false}
          nodesFocusable={false}
          edgesFocusable={false}
          elementsSelectable={false}
          panOnDrag
          zoomOnScroll
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={16} size={1} />
          <Controls position="bottom-right" showInteractive={false} />
        </ReactFlow>
      )}
    </div>
  )
}

export const PipelineCanvas = forwardRef<PipelineCanvasHandle, CanvasProps>(function PipelineCanvas(
  props,
  ref,
) {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} handleRef={ref} />
    </ReactFlowProvider>
  )
})
