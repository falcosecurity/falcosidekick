interface PlacedNode {
  id: string
  type?: string
  position: { x: number; y: number }
}

const SINK_GAP = 32
// The event source sits under Sidekick.
const STORE_GAP = 72

// centerOnCore puts the source on the Sidekick line and spreads the output centers evenly around
// it, keeping the columns and the order the layout gave them. heightOf gives each node's height.
export function centerOnCore<T extends PlacedNode>(nodes: T[], heightOf: (node: T) => number): T[] {
  const core = nodes.find((n) => n.type === "core")
  if (!core) return nodes
  const storeTop = core.position.y + heightOf(core) + STORE_GAP
  const line = core.position.y + heightOf(core) / 2
  // The "add" node belongs to the outputs column and always comes last.
  const sinks = nodes
    .filter((n) => n.type === "sink" || n.type === "add")
    .sort((a, b) => Number(a.type === "add") - Number(b.type === "add") || a.position.y - b.position.y)
  const step = Math.max(0, ...sinks.map(heightOf)) + SINK_GAP
  const first = line - ((sinks.length - 1) * step) / 2
  const sinkCenter = new Map(sinks.map((n, i) => [n.id, first + i * step]))
  return nodes.map((n) => {
    if (n.type === "store") return { ...n, position: { x: core.position.x, y: storeTop } }
    const center = n.type === "source" ? line : sinkCenter.get(n.id)
    if (center === undefined) return n
    return { ...n, position: { x: n.position.x, y: center - heightOf(n) / 2 } }
  })
}
