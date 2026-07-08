export type AssetClassId = 'github-org' | 'server-apps-os' | 'laptop-apps-os'

export type RunScope = 'global' | 'asset' | 'asset-class'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type RunStatus = 'completed' | 'failed'

export type LogLevel = 'info' | 'warn' | 'error' | 'success'

export interface ScanSource {
  id: string
  name: string
  vendor: string
  channel: string
  url: string
}

export interface AssetClass {
  id: AssetClassId
  name: string
  description: string
  defaultSourceIds: string[]
}

export interface Asset {
  id: string
  classId: AssetClassId
  name: string
  vendor: string
  version: string
  os: string
  environment: string
  sourceOverrideIds?: string[]
  repoUrl?: string
  repoToken?: string
  githubScanReport?: Record<string, unknown>
}

export interface CVEFinding {
  id: string
  cveId: string
  title: string
  severity: Severity
  sourceId: string
  sourceName: string
  assetId: string
  publishedAt: string
  packageName?: string
  packageVersion?: string
}

export interface TerminalLogLine {
  id: string
  timestamp: string
  level: LogLevel
  message: string
}

export interface ScanRunSourceResult {
  sourceId: string
  sourceName: string
  status: RunStatus
  startedAt: string
  endedAt: string
  findings: CVEFinding[]
}

export interface ScanRunAssetResult {
  assetId: string
  assetName: string
  classId: AssetClassId
  className: string
  status: RunStatus
  startedAt: string
  endedAt: string
  sourceResults: ScanRunSourceResult[]
}

export interface ScanRunTotals {
  assetsScanned: number
  sourcesChecked: number
  findings: number
  severityCounts: Record<Severity, number>
}

export interface ScanRun {
  id: string
  scope: RunScope
  targetAssetId?: string
  targetClassId?: AssetClassId
  status: RunStatus
  startedAt: string
  endedAt: string
  triggeredBy: 'manual'
  logs: TerminalLogLine[]
  assetResults: ScanRunAssetResult[]
  totals: ScanRunTotals
}

export interface AppState {
  assetClasses: AssetClass[]
  assets: Asset[]
  scanSources: ScanSource[]
  runs: ScanRun[]
}
