import type { Asset, AssetClass, CVEFinding, ScanRun, Severity } from './types'

export interface AssetImpactView {
  assetId: string
  assetName: string
  className: string
  lastScannedAt: string
  findings: CVEFinding[]
  severityCounts: Record<Severity, number>
}

const newSeverityCounts = (): Record<Severity, number> => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
})

const findingsFromRunAsset = (run: ScanRun, assetId: string) => {
  const assetResult = run.assetResults.find((item) => item.assetId === assetId)
  return assetResult?.sourceResults.flatMap((source) => source.findings) ?? []
}

export const getAssetImpactList = (
  assets: Asset[],
  classes: AssetClass[],
  runs: ScanRun[],
): AssetImpactView[] => {
  const sortedRuns = [...runs].sort((a, b) => +new Date(b.startedAt) - +new Date(a.startedAt))

  return assets
    .map((asset) => {
      const latestRun = sortedRuns.find((run) => run.assetResults.some((result) => result.assetId === asset.id))
      if (!latestRun) return null
      const findings = findingsFromRunAsset(latestRun, asset.id)
      const severityCounts = findings.reduce((acc, finding) => {
        acc[finding.severity] += 1
        return acc
      }, newSeverityCounts())
      const className = classes.find((item) => item.id === asset.classId)?.name ?? asset.classId

      return {
        assetId: asset.id,
        assetName: asset.name,
        className,
        lastScannedAt: latestRun.endedAt,
        findings,
        severityCounts,
      }
    })
    .filter((item): item is AssetImpactView => Boolean(item))
    .sort((a, b) => b.findings.length - a.findings.length)
}

export const getClassSummary = (
  assetClass: AssetClass,
  assets: Asset[],
  impacts: AssetImpactView[],
) => {
  const classAssets = assets.filter((asset) => asset.classId === assetClass.id)
  const impacted = impacts.filter((impact) => classAssets.some((asset) => asset.id === impact.assetId))

  return {
    totalAssets: classAssets.length,
    impactedAssets: impacted.filter((impact) => impact.findings.length > 0).length,
    findings: impacted.reduce((count, impact) => count + impact.findings.length, 0),
  }
}
