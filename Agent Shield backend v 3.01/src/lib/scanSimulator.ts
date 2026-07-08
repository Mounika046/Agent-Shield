import type {
  Asset,
  AssetClass,
  CVEFinding,
  LogLevel,
  RunScope,
  ScanRun,
  ScanRunAssetResult,
  ScanRunSourceResult,
  ScanSource,
  Severity,
  TerminalLogLine,
} from './types'

interface SimulatorContext {
  assets: Asset[]
  assetClasses: AssetClass[]
  scanSources: ScanSource[]
}

type LogCallback = (line: TerminalLogLine) => void

const severityByIndex: Severity[] = ['critical', 'high', 'medium', 'low']

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const hashString = (value: string) => {
  let hash = 2166136261
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return Math.abs(hash)
}

const buildCveId = (seed: number) => {
  const year = 2022 + (seed % 5)
  const number = String((seed % 90000) + 10000)
  return `CVE-${year}-${number}`
}

const buildFinding = (
  asset: Asset,
  source: ScanSource,
  index: number,
  seed: number,
): CVEFinding => {
  const severity = severityByIndex[(seed + index) % severityByIndex.length]
  return {
    id: `${asset.id}-${source.id}-${index}`,
    cveId: buildCveId(seed + index * 37),
    title: `${asset.name} vulnerable component alert #${index + 1}`,
    severity,
    sourceId: source.id,
    sourceName: source.name,
    assetId: asset.id,
    publishedAt: new Date(Date.now() - ((seed % 10) + index) * 86400000).toISOString(),
  }
}

const createTotals = () => ({
  assetsScanned: 0,
  sourcesChecked: 0,
  findings: 0,
  severityCounts: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  } as Record<Severity, number>,
})

export const createScanSimulator = (context: SimulatorContext) => {
  const getClassById = (id: string) => context.assetClasses.find((item) => item.id === id)
  const getSourceById = (id: string) => context.scanSources.find((item) => item.id === id)

  const effectiveSourcesForAsset = (asset: Asset): ScanSource[] => {
    const assetClass = getClassById(asset.classId)
    if (!assetClass) return []
    const sourceIds = asset.sourceOverrideIds?.length
      ? asset.sourceOverrideIds
      : assetClass.defaultSourceIds

    return sourceIds
      .map((id) => getSourceById(id))
      .filter((source): source is ScanSource => Boolean(source))
  }

  const run = async (
    scope: RunScope,
    assets: Asset[],
    onLog?: LogCallback,
    targetAssetId?: string,
    targetClassId?: AssetClass['id'],
  ): Promise<ScanRun> => {
    const logs: TerminalLogLine[] = []

    const pushLog = (level: LogLevel, message: string) => {
      const line: TerminalLogLine = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        level,
        message,
      }
      logs.push(line)
      onLog?.(line)
    }

    const startedAt = new Date().toISOString()
    const totals = createTotals()
    const assetResults: ScanRunAssetResult[] = []

    pushLog('info', `Run started for ${assets.length} asset(s) in ${scope} scope.`)
    await sleep(380)

    for (const asset of assets) {
      const assetClass = getClassById(asset.classId)
      const className = assetClass?.name ?? asset.classId
      const assetStartedAt = new Date().toISOString()
      const sourceResults: ScanRunSourceResult[] = []
      const sources = effectiveSourcesForAsset(asset)

      pushLog('info', `Scanning asset ${asset.name} (${className}) with ${sources.length} source(s).`)
      await sleep(320)

      for (const source of sources) {
        const sourceStartedAt = new Date().toISOString()
        const seed = hashString(`${asset.id}:${source.id}`)
        const findingCount = seed % 3
        const findings = Array.from({ length: findingCount }, (_, index) =>
          buildFinding(asset, source, index, seed),
        )

        pushLog('info', `Checking ${source.name} for ${asset.name}...`)
        await sleep(280)

        for (const finding of findings) {
          totals.severityCounts[finding.severity] += 1
        }

        totals.findings += findings.length
        totals.sourcesChecked += 1

        const sourceResult: ScanRunSourceResult = {
          sourceId: source.id,
          sourceName: source.name,
          status: 'completed',
          startedAt: sourceStartedAt,
          endedAt: new Date().toISOString(),
          findings,
        }

        sourceResults.push(sourceResult)

        if (findings.length > 0) {
          pushLog(
            'warn',
            `${source.name} reported ${findings.length} finding(s) for ${asset.name}.`,
          )
        } else {
          pushLog('success', `${source.name} reported no issues for ${asset.name}.`)
        }

        await sleep(220)
      }

      totals.assetsScanned += 1

      const assetFindings = sourceResults.flatMap((result) => result.findings)
      pushLog(
        assetFindings.length ? 'warn' : 'success',
        `${asset.name} scan complete with ${assetFindings.length} finding(s).`,
      )

      assetResults.push({
        assetId: asset.id,
        assetName: asset.name,
        classId: asset.classId,
        className,
        status: 'completed',
        startedAt: assetStartedAt,
        endedAt: new Date().toISOString(),
        sourceResults,
      })

      await sleep(240)
    }

    const endedAt = new Date().toISOString()
    pushLog('success', `Run completed. ${totals.findings} total finding(s) detected.`)

    return {
      id: crypto.randomUUID(),
      scope,
      targetAssetId,
      targetClassId,
      status: 'completed',
      startedAt,
      endedAt,
      triggeredBy: 'manual',
      logs,
      assetResults,
      totals,
    }
  }

  return {
    runGlobal(onLog?: LogCallback) {
      return run('global', context.assets, onLog)
    },

    runAsset(assetId: string, onLog?: LogCallback) {
      const asset = context.assets.find((item) => item.id === assetId)
      if (!asset) {
        throw new Error(`Asset not found: ${assetId}`)
      }
      return run('asset', [asset], onLog, assetId)
    },

    runAssetClass(classId: AssetClass['id'], onLog?: LogCallback) {
      const assets = context.assets.filter((asset) => asset.classId === classId)
      return run('asset-class', assets, onLog, undefined, classId)
    },

    effectiveSourcesForAsset,
  }
}
