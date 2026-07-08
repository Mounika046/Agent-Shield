import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Card } from '../../components/ui/Card'
import { Table } from '../../components/ui/Table'
import { Badge } from '../../components/ui/Badge'
import { useAppStore } from '../../app/AppProvider'
import { formatDateTime } from '../../lib/format'

export const RunsPage = () => {
  const { runs } = useAppStore()
  const [params, setParams] = useSearchParams()
  const selectedRunId = params.get('runId')

  const selectedRun = useMemo(
    () => runs.find((run) => run.id === selectedRunId) ?? runs[0],
    [runs, selectedRunId],
  )

  return (
    <div className="page-stack">
      <header className="page-head">
        <div>
          <h1>Run History</h1>
          <p>Every execution is logged with full asset and source-level details.</p>
        </div>
      </header>

      <Card title="Recent Runs" subtitle="Click a run to inspect full execution details.">
        <Table>
          <thead>
            <tr>
              <th>Started</th>
              <th>Scope</th>
              <th>Status</th>
              <th>Assets</th>
              <th>Sources</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {runs.length === 0 && (
              <tr>
                <td colSpan={6}>No runs yet.</td>
              </tr>
            )}
            {runs.map((run) => (
              <tr
                key={run.id}
                className={selectedRun?.id === run.id ? 'row-selected' : ''}
                onClick={() => setParams({ runId: run.id })}
              >
                <td>{formatDateTime(run.startedAt)}</td>
                <td>{run.scope}</td>
                <td>
                  <Badge tone="success">{run.status}</Badge>
                </td>
                <td>{run.totals.assetsScanned}</td>
                <td>{run.totals.sourcesChecked}</td>
                <td>{run.totals.findings}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>

      {selectedRun && (
        <Card title="Run Detail" subtitle={`Run ID: ${selectedRun.id}`}>
          <div className="finding-list">
            {selectedRun.assetResults.map((assetResult) => (
              <article key={assetResult.assetId} className="run-detail-asset">
                <header>
                  <strong>{assetResult.assetName}</strong>
                  <small>{assetResult.className}</small>
                </header>
                <div className="run-detail-sources">
                  {assetResult.sourceResults.map((sourceResult) => (
                    <div key={sourceResult.sourceId} className="run-detail-source">
                      <p>
                        <strong>{sourceResult.sourceName}</strong> - {sourceResult.findings.length} finding(s)
                      </p>
                      {sourceResult.findings.length > 0 && (
                        <ul>
                          {sourceResult.findings.map((finding) => (
                            <li key={finding.id}>
                              {finding.cveId} ({finding.severity})
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
