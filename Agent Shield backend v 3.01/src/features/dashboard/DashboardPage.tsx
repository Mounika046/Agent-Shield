import { Link, useNavigate } from 'react-router-dom'
import { useMemo, useState } from 'react'
import { Card } from '../../components/ui/Card'
import { Stat } from '../../components/ui/Stat'
import { Table } from '../../components/ui/Table'
import { Badge } from '../../components/ui/Badge'
import { Button, buttonClass } from '../../components/ui/Button'
import { useAppStore } from '../../app/AppProvider'
import { formatRelative } from '../../lib/format'
import { getAssetImpactList } from '../../lib/selectors'
import type { Severity } from '../../lib/types'

const severityTone: Record<Severity, 'danger' | 'warning' | 'info'> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
}

export const DashboardPage = () => {
  const navigate = useNavigate()
  const { assetClasses, assets, runs, runClassResync, isScanRunning } = useAppStore()
  const [syncingClassId, setSyncingClassId] = useState<string | null>(null)

  const impacts = useMemo(
    () => getAssetImpactList(assets, assetClasses, runs),
    [assetClasses, assets, runs],
  )

  const totalFindings = useMemo(
    () =>
      impacts.reduce(
        (sum, impact) =>
          sum +
          impact.severityCounts.critical +
          impact.severityCounts.high +
          impact.severityCounts.medium +
          impact.severityCounts.low,
        0,
      ),
    [impacts],
  )

  const impactedAssets = impacts.filter(
    (impact) =>
      impact.severityCounts.critical +
        impact.severityCounts.high +
        impact.severityCounts.medium +
        impact.severityCounts.low >
      0,
  ).length

  const latestRun = runs[0]

  return (
    <div className="page-stack">
      <header className="page-head">
        <div>
          <p className="page-kicker">Security / Dashboard</p>
          <h1>Security Overview</h1>
          <p>
            Welcome back. Here is the latest CVE and asset exposure snapshot across your classes.
          </p>
        </div>
        <Button onClick={() => navigate('/scan-center')}>
          {isScanRunning ? 'Scan Running...' : 'Run Global Scan'}
        </Button>
      </header>

      <section className="grid grid-4">
        <Stat label="Asset Classes" value={assetClasses.length} />
        <Stat label="Total Assets" value={assets.length} />
        <Stat label="Impacted Assets" value={impactedAssets} />
        <Stat label="Total Findings" value={totalFindings} />
      </section>

      <section className="dashboard-panels">
        <Card title="Impacted Assets" subtitle="Latest severity distribution by asset.">
          <Table>
            <thead>
              <tr>
                <th>Asset</th>
                <th>Class</th>
                <th>Critical</th>
                <th>High</th>
                <th>Medium</th>
                <th>Low</th>
                <th>Last Scan</th>
              </tr>
            </thead>
            <tbody>
              {impacts.length === 0 && (
                <tr>
                  <td colSpan={7}>No scan history yet. Run a global scan to populate results.</td>
                </tr>
              )}
              {impacts.slice(0, 6).map((impact) => (
                <tr key={impact.assetId}>
                  <td>
                    <Link className="table-link" to={`/assets/${impact.assetId}`}>
                      {impact.assetName}
                    </Link>
                  </td>
                  <td>{impact.className}</td>
                  {(['critical', 'high', 'medium', 'low'] as Severity[]).map((severity) => (
                    <td key={severity}>
                      <Badge tone={impact.severityCounts[severity] ? severityTone[severity] : 'default'}>
                        {impact.severityCounts[severity]}
                      </Badge>
                    </td>
                  ))}
                  <td>{formatRelative(impact.lastScannedAt)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>

        <Card title="Priority Tasks" subtitle="Suggested next actions based on latest findings.">
          <div className="finding-list">
            {impacts.slice(0, 4).map((impact) => (
              <article key={impact.assetId} className="finding-row">
                <div>
                  <p>
                    <strong>{impact.assetName}</strong>
                  </p>
                  <small>{impact.className}</small>
                </div>
                <div className="finding-meta">
                  <Badge
                    tone={
                      impact.severityCounts.critical > 0
                        ? 'danger'
                        : impact.severityCounts.high > 0
                          ? 'warning'
                          : 'info'
                    }
                  >
                    {impact.severityCounts.critical > 0
                      ? `${impact.severityCounts.critical} critical`
                      : impact.severityCounts.high > 0
                        ? `${impact.severityCounts.high} high`
                        : 'Review'}
                  </Badge>
                  <Link className="table-link" to={`/assets/${impact.assetId}`}>
                    Open asset
                  </Link>
                </div>
              </article>
            ))}
            {impacts.length === 0 && <p className="helper-text">No pending tasks until first scan run.</p>}
          </div>
        </Card>
      </section>

      <section className="grid grid-3">
        {assetClasses.map((assetClass) => {
          const classAssets = assets.filter((asset) => asset.classId === assetClass.id)
          const classAssetIds = new Set(classAssets.map((asset) => asset.id))
          const classImpacts = impacts.filter((impact) => classAssetIds.has(impact.assetId))
          const classFindings = classImpacts.reduce(
            (sum, impact) =>
              sum +
              impact.severityCounts.critical +
              impact.severityCounts.high +
              impact.severityCounts.medium +
              impact.severityCounts.low,
            0,
          )

          return (
            <Card
              key={assetClass.id}
              title={assetClass.name}
              subtitle={assetClass.description}
              className="class-card"
            >
              <div className="grid grid-3 compact-grid">
                <Stat label="Mapped Assets" value={classAssets.length} />
                <Stat
                  label="Impacted"
                  value={
                    classImpacts.filter(
                      (impact) =>
                        impact.severityCounts.critical +
                          impact.severityCounts.high +
                          impact.severityCounts.medium +
                          impact.severityCounts.low >
                        0,
                    ).length
                  }
                />
                <Stat label="Findings" value={classFindings} />
              </div>
              <div className="card-actions">
                <Link className={buttonClass('secondary', 'sm')} to={`/asset-classes/${assetClass.id}`}>
                  Manage
                </Link>
                <Button
                  size="sm"
                  onClick={async () => {
                    setSyncingClassId(assetClass.id)
                    await runClassResync(assetClass.id)
                    setSyncingClassId(null)
                  }}
                  disabled={isScanRunning}
                >
                  {syncingClassId === assetClass.id ? 'Resyncing...' : 'Resync Class'}
                </Button>
              </div>
            </Card>
          )
        })}
      </section>

      <Card title="Latest Run" subtitle="Most recent execution snapshot.">
        {latestRun ? (
          <div className="run-inline-summary">
            <Badge tone="success">{latestRun.status}</Badge>
            <span>{latestRun.scope}</span>
            <span>{latestRun.totals.assetsScanned} assets scanned</span>
            <span>{latestRun.totals.findings} findings</span>
            <Link className="table-link" to={`/runs?runId=${latestRun.id}`}>
              View run details
            </Link>
          </div>
        ) : (
          <p>No runs yet.</p>
        )}
      </Card>
    </div>
  )
}
