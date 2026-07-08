import { useMemo, useState } from 'react'
import { X } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { Button, buttonClass } from '../../components/ui/Button'
import { Card } from '../../components/ui/Card'
import { TerminalPanel } from '../../components/ui/TerminalPanel'
import { Badge } from '../../components/ui/Badge'
import { Table } from '../../components/ui/Table'
import { SourcePillSelector } from '../../components/ui/SourcePillSelector'
import { useAppStore, useAssetById, useAssetClassById, getEffectiveSourceIds } from '../../app/AppProvider'
import { formatDateTime, titleCase } from '../../lib/format'
import type { TerminalLogLine } from '../../lib/types'

const toneBySeverity = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
} as const

const toggleSelection = (selectedIds: string[], sourceId: string) => {
  const next = new Set(selectedIds)
  if (next.has(sourceId)) {
    next.delete(sourceId)
  } else {
    next.add(sourceId)
  }
  return Array.from(next)
}

const recommendedFixBySeverity = {
  critical:
    'Patch immediately to the latest secure release, verify exploitability, and add a temporary mitigation/WAF rule until rollout is complete.',
  high: 'Upgrade the affected package to a fixed version in the current sprint and validate dependency lockfiles.',
  medium:
    'Schedule update in the next release cycle and apply compensating controls if internet-exposed.',
  low: 'Track in backlog and update during routine dependency hygiene windows.',
} as const

export const AssetDetailPage = () => {
  const { assetId = '' } = useParams()
  const asset = useAssetById(assetId)
  const assetClass = useAssetClassById(asset?.classId ?? '')
  const { scanSources, setAssetSources, runAssetScan, isScanRunning, runs, addScanSource } = useAppStore()

  const [logLines, setLogLines] = useState<TerminalLogLine[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [isManageSourcesOpen, setIsManageSourcesOpen] = useState(false)
  const [isAddSourceOpen, setIsAddSourceOpen] = useState(false)
  const [newSourceName, setNewSourceName] = useState('')
  const [newSourceUrl, setNewSourceUrl] = useState('')

  const recentFindings = useMemo(() => {
    const latestRun = runs.find((run) => run.assetResults.some((result) => result.assetId === assetId))
    if (!latestRun) return []
    const result = latestRun.assetResults.find((item) => item.assetId === assetId)
    return result?.sourceResults.flatMap((source) => source.findings) ?? []
  }, [assetId, runs])

  const assetRuns = useMemo(
    () => runs.filter((run) => run.assetResults.some((result) => result.assetId === assetId)),
    [assetId, runs],
  )

  if (!asset || !assetClass) {
    return <p>Asset not found.</p>
  }

  const effectiveSourceIds = getEffectiveSourceIds(asset, assetClass)
  const latestAssetRun = assetRuns[0]
  const oldestAssetRun = assetRuns[assetRuns.length - 1]
  const masterRows = [...recentFindings].sort(
    (a, b) => +new Date(b.publishedAt) - +new Date(a.publishedAt),
  )
  return (
    <div className="page-stack">
      <header className="page-head">
        <div>
          <h1>{asset.name}</h1>
          <p>
            {assetClass.name} / {asset.environment}
          </p>
        </div>
        <div className="page-head-actions">
          <Button variant="secondary" onClick={() => setIsManageSourcesOpen(true)}>
            Manage Sources
          </Button>
          <Link className={buttonClass('secondary')} to={`/asset-classes/${asset.classId}`}>
            Back to class
          </Link>
        </div>
      </header>

      <section className="grid grid-3">
        <Card title="Vendor" subtitle="Software owner">
          <p>{asset.vendor}</p>
        </Card>
        <Card title="Version" subtitle="Configured build/track">
          <p>{asset.version}</p>
        </Card>
        <Card title="OS" subtitle="Underlying runtime">
          <p>{asset.os}</p>
        </Card>
      </section>

      <Card title="Manual Asset Scan" subtitle="Run on-demand CVE checks for this specific asset.">
        <div className="card-actions">
          <Button
            disabled={isScanRunning || isRunning}
            onClick={async () => {
              setLogLines([])
              setIsRunning(true)
              try {
                await runAssetScan(asset.id, (line) => setLogLines((current) => [...current, line]))
              } catch (error) {
                const message = error instanceof Error ? error.message : 'Asset scan failed.'
                setLogLines((current) => [
                  ...current,
                  {
                    id: crypto.randomUUID(),
                    timestamp: new Date().toISOString(),
                    level: 'error',
                    message,
                  },
                ])
              } finally {
                setIsRunning(false)
              }
            }}
          >
            {isRunning ? 'Scanning Asset...' : 'Run Asset Scan'}
          </Button>
          <Link className="table-link" to="/runs">
            Open Run History
          </Link>
        </div>
        <TerminalPanel logs={logLines} compact />
      </Card>

      <Card title="Asset Master Details" subtitle="Repository/package metadata with latest CVE reporting context.">
        <Table>
          <thead>
            <tr>
              <th>GitHub Repo</th>
              <th>Package</th>
              <th>Version</th>
              <th>Added Date</th>
              <th>Last Scan Date</th>
              <th>Last Scan Status</th>
              <th>Total Findings (Latest)</th>
              <th>Effective Sources</th>
              <th>Last CVE Reported</th>
              <th>Criticality</th>
              <th>Source</th>
              <th>CVE Reported Date</th>
            </tr>
          </thead>
          <tbody>
            {masterRows.length === 0 && (
              <tr>
                <td>{asset.classId === 'github-org' ? asset.name : 'N/A'}</td>
                <td>{asset.name}</td>
                <td>{asset.version}</td>
                <td>{oldestAssetRun ? formatDateTime(oldestAssetRun.startedAt) : 'N/A'}</td>
                <td>{latestAssetRun ? formatDateTime(latestAssetRun.startedAt) : 'N/A'}</td>
                <td>
                  <Badge tone={latestAssetRun?.status === 'completed' ? 'success' : 'default'}>
                    {latestAssetRun ? titleCase(latestAssetRun.status) : 'N/A'}
                  </Badge>
                </td>
                <td>0</td>
                <td>
                  <div className="source-badges">
                    {effectiveSourceIds.map((sourceId) => (
                      <span className="badge" key={sourceId}>
                        {sourceId}
                      </span>
                    ))}
                  </div>
                </td>
                <td>N/A</td>
                <td>
                  <Badge>None</Badge>
                </td>
                <td>N/A</td>
                <td>N/A</td>
              </tr>
            )}
            {masterRows.map((finding) => (
              <tr key={finding.id}>
                <td>{asset.classId === 'github-org' ? asset.name : 'N/A'}</td>
                <td>{finding.packageName || asset.name}</td>
                <td>{finding.packageVersion || asset.version}</td>
                <td>{oldestAssetRun ? formatDateTime(oldestAssetRun.startedAt) : 'N/A'}</td>
                <td>{latestAssetRun ? formatDateTime(latestAssetRun.startedAt) : 'N/A'}</td>
                <td>
                  <Badge tone={latestAssetRun?.status === 'completed' ? 'success' : 'default'}>
                    {latestAssetRun ? titleCase(latestAssetRun.status) : 'N/A'}
                  </Badge>
                </td>
                <td>{recentFindings.length}</td>
                <td>
                  <div className="source-badges">
                    {effectiveSourceIds.map((sourceId) => (
                      <span className="badge" key={sourceId}>
                        {sourceId}
                      </span>
                    ))}
                  </div>
                </td>
                <td>
                  <div className="cve-hover">
                    <a
                      className="cve-link"
                      href={`https://nvd.nist.gov/vuln/detail/${finding.cveId}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {finding.cveId}
                    </a>
                    <div className="cve-popover" role="tooltip">
                      <p className="cve-popover-title">{finding.cveId}</p>
                      <p>
                        <strong>Summary:</strong> {finding.title}
                      </p>
                      <p>
                        <strong>Severity:</strong> {titleCase(finding.severity)}
                      </p>
                      <p>
                        <strong>Recommended Fix:</strong> {recommendedFixBySeverity[finding.severity]}
                      </p>
                    </div>
                  </div>
                </td>
                <td>
                  <Badge tone={toneBySeverity[finding.severity]}>{titleCase(finding.severity)}</Badge>
                </td>
                <td>{finding.sourceName}</td>
                <td>{formatDateTime(finding.publishedAt)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>

      {isAddSourceOpen && (
        <div className="modal-backdrop" role="presentation">
          <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="asset-add-source-title">
            <header className="modal-head">
              <div>
                <h3 id="asset-add-source-title">Add Source</h3>
                <p>Add a custom source and auto-apply it to this asset.</p>
              </div>
              <button
                type="button"
                className="icon-btn modal-close-btn"
                aria-label="Close modal"
                onClick={() => setIsAddSourceOpen(false)}
              >
                <X size={16} />
              </button>
            </header>

            <form
              className="source-form"
              onSubmit={(event) => {
                event.preventDefault()
                if (!newSourceName.trim() || !newSourceUrl.trim()) return
                const source = addScanSource({ name: newSourceName, url: newSourceUrl })
                const selected = asset.sourceOverrideIds ?? effectiveSourceIds
                setAssetSources(asset.id, [...selected, source.id])
                setNewSourceName('')
                setNewSourceUrl('')
                setIsAddSourceOpen(false)
              }}
            >
              <input
                placeholder="Source name"
                value={newSourceName}
                onChange={(event) => setNewSourceName(event.target.value)}
              />
              <input
                placeholder="Source URL"
                type="url"
                value={newSourceUrl}
                onChange={(event) => setNewSourceUrl(event.target.value)}
              />
              <div className="modal-actions">
                <Button type="button" variant="secondary" onClick={() => setIsAddSourceOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit">Add Source</Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {isManageSourcesOpen && (
        <div className="modal-backdrop" role="presentation">
          <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="asset-manage-sources-title">
            <header className="modal-head">
              <div>
                <h3 id="asset-manage-sources-title">Manage Sources</h3>
                <p>Choose effective source mapping for this asset.</p>
              </div>
              <button
                type="button"
                className="icon-btn modal-close-btn"
                aria-label="Close modal"
                onClick={() => setIsManageSourcesOpen(false)}
              >
                <X size={16} />
              </button>
            </header>

            <SourcePillSelector
              sources={scanSources}
              selectedIds={asset.sourceOverrideIds ?? effectiveSourceIds}
              onToggle={(sourceId) => {
                const selected = asset.sourceOverrideIds ?? effectiveSourceIds
                setAssetSources(asset.id, toggleSelection(selected, sourceId))
              }}
            />

            <div className="modal-actions">
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setAssetSources(asset.id, undefined)
                  setIsManageSourcesOpen(false)
                }}
              >
                Reset to class defaults
              </Button>
              <Button
                type="button"
                onClick={() => {
                  setIsManageSourcesOpen(false)
                  setIsAddSourceOpen(true)
                }}
              >
                Add Source
              </Button>
              <Button type="button" variant="secondary" onClick={() => setIsManageSourcesOpen(false)}>
                Done
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
