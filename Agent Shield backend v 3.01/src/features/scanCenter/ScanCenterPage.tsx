import { useState } from 'react'
import { Card } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { TerminalPanel } from '../../components/ui/TerminalPanel'
import { Badge } from '../../components/ui/Badge'
import { useAppStore } from '../../app/AppProvider'
import type { ScanRun, TerminalLogLine } from '../../lib/types'

export const ScanCenterPage = () => {
  const { runGlobalScan, isScanRunning } = useAppStore()
  const [logs, setLogs] = useState<TerminalLogLine[]>([])
  const [latestRun, setLatestRun] = useState<ScanRun | null>(null)

  return (
    <div className="page-stack">
      <header className="page-head">
        <div>
          <h1>Manual Scan Center</h1>
          <p>Run full landscape CVE scans with live terminal execution logs.</p>
        </div>
      </header>

      <Card title="Global Asset Scan" subtitle="Scans all mapped assets using effective source mappings.">
        <div className="card-actions">
          <Button
            disabled={isScanRunning}
            onClick={async () => {
              setLogs([])
              setLatestRun(null)
              const run = await runGlobalScan((line) => setLogs((current) => [...current, line]))
              setLatestRun(run)
            }}
          >
            {isScanRunning ? 'Scan in progress...' : 'Start Global Manual Scan'}
          </Button>
          {latestRun && <Badge tone="success">Completed</Badge>}
        </div>
        <TerminalPanel logs={logs} />
      </Card>

      {latestRun && (
        <Card title="Run Summary" subtitle="Detailed totals from the latest global scan.">
          <div className="run-inline-summary">
            <span>Assets scanned: {latestRun.totals.assetsScanned}</span>
            <span>Sources checked: {latestRun.totals.sourcesChecked}</span>
            <span>Total findings: {latestRun.totals.findings}</span>
            <span>Critical: {latestRun.totals.severityCounts.critical}</span>
            <span>High: {latestRun.totals.severityCounts.high}</span>
            <span>Medium: {latestRun.totals.severityCounts.medium}</span>
            <span>Low: {latestRun.totals.severityCounts.low}</span>
          </div>
        </Card>
      )}
    </div>
  )
}
