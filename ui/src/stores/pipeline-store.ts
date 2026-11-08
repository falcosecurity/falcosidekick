import { create } from "zustand"

import type { OutputStatus, PipelineComposite } from "@/lib/types"

interface PipelineState {
  composite: PipelineComposite | null
  statusByName: Record<string, OutputStatus>
  selectedOutput: string | null
  setComposite: (value: PipelineComposite | null) => void
  setStatus: (value: OutputStatus[]) => void
  selectOutput: (name: string | null) => void
}

export const usePipelineStore = create<PipelineState>((set) => ({
  composite: null,
  statusByName: {},
  selectedOutput: null,

  setComposite(value) {
    const statusByName: Record<string, OutputStatus> = {}
    if (value) {
      for (const s of value.status) statusByName[s.name] = s
    }
    set({ composite: value, statusByName })
  },

  setStatus(value) {
    const statusByName: Record<string, OutputStatus> = {}
    for (const s of value) statusByName[s.name] = s
    set({ statusByName })
  },

  selectOutput(name) {
    set({ selectedOutput: name })
  },
}))
