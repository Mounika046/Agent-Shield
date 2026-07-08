import type { ScanRun } from './types'

const RUNS_KEY = 'agentshield:runs'

const readRuns = (): ScanRun[] => {
  try {
    const raw = localStorage.getItem(RUNS_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as ScanRun[]
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

const writeRuns = (runs: ScanRun[]) => {
  localStorage.setItem(RUNS_KEY, JSON.stringify(runs))
}

export const runRepository = {
  getAll(): ScanRun[] {
    return readRuns().sort((a, b) => +new Date(b.startedAt) - +new Date(a.startedAt))
  },

  save(run: ScanRun): void {
    const existing = readRuns().filter((item) => item.id !== run.id)
    writeRuns([run, ...existing])
  },

  getById(id: string): ScanRun | undefined {
    return readRuns().find((run) => run.id === id)
  },
}
