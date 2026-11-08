import { describe, expect, test } from "bun:test"

import { centerOnCore } from "./center-on-core"

interface TestNode {
  id: string
  type: string
  position: { x: number; y: number }
  height: number
}

const heightOf = (n: TestNode) => n.height

function graph(sinks: number): TestNode[] {
  return [
    { id: "source:falco", type: "source", position: { x: 0, y: 40 }, height: 64 },
    { id: "core:sidekick", type: "core", position: { x: 320, y: 200 }, height: 64 },
    ...Array.from({ length: sinks }, (_, i) => ({
      id: `sink:${i}`,
      type: "sink",
      position: { x: 640, y: i * 10 },
      height: i % 2 === 0 ? 86 : 70,
    })),
  ]
}

const center = (n: TestNode) => n.position.y + n.height / 2

describe("centerOnCore", () => {
  test.each([1, 2, 3, 4, 24])("%i outputs sit symmetrically around the Sidekick line", (count) => {
    const placed = centerOnCore(graph(count), heightOf)
    const line = 200 + 64 / 2
    const sinks = placed.filter((n) => n.type === "sink")
    const centers = sinks.map(center)
    const mid = centers.reduce((sum, c) => sum + c, 0) / centers.length
    expect(mid).toBeCloseTo(line)
    const steps = centers.slice(1).map((c, i) => c - (centers[i] ?? 0))
    expect(new Set(steps).size).toBeLessThanOrEqual(1)
    expect(sinks.every((n) => n.position.x === 640)).toBe(true)
    const source = placed.find((n) => n.type === "source")
    expect(source && center(source)).toBe(line)
  })

  test("keeps the order the layout gave the outputs", () => {
    const nodes = graph(3).map((n) => (n.id === "sink:0" ? { ...n, position: { x: 640, y: 500 } } : n))
    const order = centerOnCore(nodes, heightOf)
      .filter((n) => n.type === "sink")
      .sort((a, b) => a.position.y - b.position.y)
      .map((n) => n.id)
    expect(order).toEqual(["sink:1", "sink:2", "sink:0"])
  })

  test("leaves a graph without the Sidekick node unchanged", () => {
    const nodes = graph(2).filter((n) => n.type !== "core")
    expect(centerOnCore(nodes, heightOf)).toBe(nodes)
  })
})
