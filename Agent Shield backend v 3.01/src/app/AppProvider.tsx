import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type PropsWithChildren,
} from 'react'
import { assets as seedAssets, initialState, scanSources as seedSources } from '../lib/mockData'
import { runRepository } from '../lib/runRepository'
import { createScanSimulator } from '../lib/scanSimulator'
import type { Asset, AssetClass, ScanRun, ScanSource } from '../lib/types'

const ASSETS_KEY = 'agentshield:assets'
const CLASSES_KEY = 'agentshield:classes'
const SOURCES_KEY = 'agentshield:sources'

interface AppStoreValue {
  assetClasses: AssetClass[]
  assets: Asset[]
  scanSources: ScanSource[]
  runs: ScanRun[]
  isScanRunning: boolean
  addAsset: (payload: Omit<Asset, 'id'>) => void
  updateAsset: (assetId: string, payload: Omit<Asset, 'id' | 'classId'>) => void
  removeAsset: (assetId: string) => void
  setClassSources: (classId: AssetClass['id'], sourceIds: string[]) => void
  setAssetSources: (assetId: string, sourceIds?: string[]) => void
  addScanSource: (payload: { name: string; url: string }) => ScanSource
  runGlobalScan: (onLog?: (line: ScanRun['logs'][number]) => void) => Promise<ScanRun>
  runAssetScan: (
    assetId: string,
    onLog?: (line: ScanRun['logs'][number]) => void,
  ) => Promise<ScanRun>
  runClassResync: (
    classId: AssetClass['id'],
    onLog?: (line: ScanRun['logs'][number]) => void,
  ) => Promise<ScanRun>
  getRunById: (id: string) => ScanRun | undefined
}

const AppStoreContext = createContext<AppStoreValue | null>(null)

const readLocal = <T,>(key: string, fallback: T): T => {
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return fallback
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

const slugify = (value: string) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')

const getVendorFromUrl = (url: string): string => {
  try {
    const hostname = new URL(url).hostname.replace(/^www\./, '')
    return hostname.split('.')[0]?.toUpperCase() || 'CUSTOM'
  } catch {
    return 'CUSTOM'
  }
}

const backendBaseUrl = (import.meta.env.VITE_BACKEND_URL ?? 'http://localhost:8070').replace(/\/+$/, '')

const mapSeverity = (value: string | undefined): 'critical' | 'high' | 'medium' | 'low' => {
  const normalized = (value ?? '').toLowerCase()
  if (normalized === 'critical') return 'critical'
  if (normalized === 'high') return 'high'
  if (normalized === 'low') return 'low'
  return 'medium'
}

const runBackendAssetScan = async (
  asset: Asset,
  className: string,
  onLog?: (line: ScanRun['logs'][number]) => void,
): Promise<ScanRun> => {
  const pushLog = (level: ScanRun['logs'][number]['level'], message: string) => {
    const line = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      level,
      message,
    }
    onLog?.(line)
    return line
  }

  const logs: ScanRun['logs'] = []
  const startedAt = new Date().toISOString()
  logs.push(pushLog('info', `Starting backend web scan for ${asset.name}...`))

  const cachedReport = (asset.githubScanReport ?? {}) as Record<string, unknown>
  const cachedReportRepoUrl =
    typeof cachedReport.repo_url === 'string' ? cachedReport.repo_url.trim() : ''
  const repoUrl = asset.repoUrl?.trim() || cachedReportRepoUrl
  if (!repoUrl) {
    throw new Error(
      'Repository URL is missing for this asset. Re-add the asset from Add Asset modal using full GitHub URL.',
    )
  }

  const webResponse = await fetch(`${backendBaseUrl}/scan/web`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repo_url: repoUrl,
        token: asset.repoToken || null,
        github_scan_report: asset.githubScanReport ?? null,
      }),
  })

  if (!webResponse.ok) {
    const text = await webResponse.text()
    throw new Error(text || `Web scan failed (${webResponse.status})`)
  }

  const webData = (await webResponse.json()) as {
    summary?: string
    json_report?: {
      vulnerability_research?: {
        packages_checked?: Array<{
          package_name?: string
          version_checked?: string
          cve_ids?: string[]
          vulnerability_ids?: string[]
          nvd_details?: Array<{
            cve_id?: string
            published?: string
            status?: string
            severity?: string
            description?: string
          }>
        }>
        nvd_details?: Array<{
          cve_id?: string
          published?: string
          status?: string
          severity?: string
          description?: string
        }>
      }
    }
  }

  logs.push(pushLog('success', webData.summary ?? 'Backend web scan completed.'))

  const findings: ScanRun['assetResults'][number]['sourceResults'][number]['findings'] = []
  const packagesChecked = webData.json_report?.vulnerability_research?.packages_checked ?? []
  if (packagesChecked.length > 0) {
    let idx = 0
    for (const pkg of packagesChecked) {
      const packageName = pkg.package_name || asset.name
      const packageVersion = pkg.version_checked || asset.version
      const pkgNvdDetails = pkg.nvd_details ?? []

      const nvdByCve = new Map(
        pkgNvdDetails
          .filter((item) => item.cve_id)
          .map((item) => [item.cve_id as string, item]),
      )
      const packageCves = (pkg.cve_ids ?? []).filter(Boolean)

      for (const cveId of packageCves) {
        const item = nvdByCve.get(cveId)
        findings.push({
          id: `${asset.id}-nvd-${idx}`,
          cveId,
          title: item?.description || `OSV reported ${cveId}`,
          severity: mapSeverity(item?.severity),
          sourceId: 'nvd',
          sourceName: item ? 'NVD' : 'OSV',
          assetId: asset.id,
          publishedAt: item?.published || new Date().toISOString(),
          packageName,
          packageVersion,
        })
        idx += 1
      }
    }
  } else {
    const nvdDetails = webData.json_report?.vulnerability_research?.nvd_details ?? []
    nvdDetails.forEach((item, idx) => {
      findings.push({
        id: `${asset.id}-nvd-${idx}`,
        cveId: item.cve_id || `CVE-UNKNOWN-${idx}`,
        title: item.description || `NVD status: ${item.status ?? 'unknown'}`,
        severity: mapSeverity(item.severity),
        sourceId: 'nvd',
        sourceName: 'NVD',
        assetId: asset.id,
        publishedAt: item.published || new Date().toISOString(),
      })
    })
  }

  const run: ScanRun = {
    id: crypto.randomUUID(),
    scope: 'asset',
    targetAssetId: asset.id,
    status: 'completed',
    startedAt,
    endedAt: new Date().toISOString(),
    triggeredBy: 'manual',
    logs,
    assetResults: [
      {
        assetId: asset.id,
        assetName: asset.name,
        classId: asset.classId,
        className,
        status: 'completed',
        startedAt,
        endedAt: new Date().toISOString(),
        sourceResults: [
          {
            sourceId: 'nvd',
            sourceName: 'NVD',
            status: 'completed',
            startedAt,
            endedAt: new Date().toISOString(),
            findings,
          },
        ],
      },
    ],
    totals: {
      assetsScanned: 1,
      sourcesChecked: 1,
      findings: findings.length,
      severityCounts: {
        critical: findings.filter((f) => f.severity === 'critical').length,
        high: findings.filter((f) => f.severity === 'high').length,
        medium: findings.filter((f) => f.severity === 'medium').length,
        low: findings.filter((f) => f.severity === 'low').length,
      },
    },
  }

  return run
}

export const AppStoreProvider = ({ children }: PropsWithChildren) => {
  const [assetState, setAssetState] = useState<Asset[]>(() => readLocal(ASSETS_KEY, seedAssets))
  const [classState, setClassState] = useState<AssetClass[]>(() =>
    readLocal(CLASSES_KEY, initialState.assetClasses),
  )
  const [scanSourceState, setScanSourceState] = useState<ScanSource[]>(() =>
    readLocal(SOURCES_KEY, seedSources),
  )
  const [runs, setRuns] = useState<ScanRun[]>(() => runRepository.getAll())
  const [isScanRunning, setIsScanRunning] = useState(false)

  useEffect(() => {
    localStorage.setItem(ASSETS_KEY, JSON.stringify(assetState))
  }, [assetState])

  useEffect(() => {
    localStorage.setItem(CLASSES_KEY, JSON.stringify(classState))
  }, [classState])

  useEffect(() => {
    localStorage.setItem(SOURCES_KEY, JSON.stringify(scanSourceState))
  }, [scanSourceState])

  const runAndStore = useCallback(
    async (
      runMode: 'global' | 'asset' | 'asset-class',
      target: string | undefined,
      onLog?: (line: ScanRun['logs'][number]) => void,
    ) => {
      setIsScanRunning(true)
      try {
        let run: ScanRun
        if (runMode === 'asset' && target) {
          const asset = assetState.find((item) => item.id === target)
          const assetClass = classState.find((item) => item.id === asset?.classId)
          if (!asset) {
            throw new Error(`Asset not found: ${target}`)
          }

          if (asset.classId === 'github-org') {
            run = await runBackendAssetScan(asset, assetClass?.name ?? asset.classId, onLog)
          } else {
            const simulator = createScanSimulator({
              assets: assetState,
              assetClasses: classState,
              scanSources: scanSourceState,
            })
            run = await simulator.runAsset(target, onLog)
          }
        } else if (runMode === 'asset-class' && target) {
          const simulator = createScanSimulator({
            assets: assetState,
            assetClasses: classState,
            scanSources: scanSourceState,
          })
          run = await simulator.runAssetClass(target as AssetClass['id'], onLog)
        } else {
          const simulator = createScanSimulator({
            assets: assetState,
            assetClasses: classState,
            scanSources: scanSourceState,
          })
          run = await simulator.runGlobal(onLog)
        }

        runRepository.save(run)
        setRuns((current) => [run, ...current.filter((item) => item.id !== run.id)])
        return run
      } finally {
        setIsScanRunning(false)
      }
    },
    [assetState, classState, scanSourceState],
  )

  const value = useMemo<AppStoreValue>(
    () => ({
      assetClasses: classState,
      assets: assetState,
      scanSources: scanSourceState,
      runs,
      isScanRunning,
      addAsset(payload) {
        setAssetState((current) => [
          ...current,
          {
            ...payload,
            id: crypto.randomUUID(),
          },
        ])
      },
      updateAsset(assetId, payload) {
        setAssetState((current) =>
          current.map((asset) => (asset.id === assetId ? { ...asset, ...payload } : asset)),
        )
      },
      removeAsset(assetId) {
        setAssetState((current) => current.filter((asset) => asset.id !== assetId))
      },
      setClassSources(classId, sourceIds) {
        setClassState((current) =>
          current.map((assetClass) =>
            assetClass.id === classId ? { ...assetClass, defaultSourceIds: sourceIds } : assetClass,
          ),
        )
      },
      setAssetSources(assetId, sourceIds) {
        setAssetState((current) =>
          current.map((asset) =>
            asset.id === assetId
              ? {
                  ...asset,
                  sourceOverrideIds: sourceIds?.length ? sourceIds : undefined,
                }
              : asset,
          ),
        )
      },
      addScanSource(payload) {
        const normalizedName = payload.name.trim()
        const normalizedUrl = payload.url.trim()
        const source: ScanSource = {
          id: `${slugify(normalizedName) || 'source'}-${crypto.randomUUID().slice(0, 8)}`,
          name: normalizedName,
          url: normalizedUrl,
          vendor: getVendorFromUrl(normalizedUrl),
          channel: 'Custom source',
        }

        setScanSourceState((current) => [source, ...current])
        return source
      },
      runGlobalScan(onLog) {
        return runAndStore('global', undefined, onLog)
      },
      runAssetScan(assetId, onLog) {
        return runAndStore('asset', assetId, onLog)
      },
      runClassResync(classId, onLog) {
        return runAndStore('asset-class', classId, onLog)
      },
      getRunById(id) {
        return runs.find((run) => run.id === id)
      },
    }),
    [assetState, classState, isScanRunning, runAndStore, runs, scanSourceState],
  )

  return <AppStoreContext.Provider value={value}>{children}</AppStoreContext.Provider>
}

export const useAppStore = () => {
  const context = useContext(AppStoreContext)
  if (!context) {
    throw new Error('useAppStore must be used within AppStoreProvider')
  }
  return context
}

export const useAssetClassById = (classId: string) => {
  const { assetClasses } = useAppStore()
  return assetClasses.find((assetClass) => assetClass.id === classId)
}

export const useAssetById = (assetId: string) => {
  const { assets } = useAppStore()
  return assets.find((asset) => asset.id === assetId)
}

export const getEffectiveSourceIds = (
  asset: Asset,
  assetClass: AssetClass | undefined,
): string[] => {
  if (asset.sourceOverrideIds?.length) return asset.sourceOverrideIds
  return assetClass?.defaultSourceIds ?? []
}
