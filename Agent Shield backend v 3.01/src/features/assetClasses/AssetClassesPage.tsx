import { Link } from 'react-router-dom'
import { useMemo, useState } from 'react'
import { Card } from '../../components/ui/Card'
import { Button, buttonClass } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { useAppStore } from '../../app/AppProvider'

export const AssetClassesPage = () => {
  const { assetClasses, assets, scanSources, runClassResync, isScanRunning } = useAppStore()
  const [running, setRunning] = useState<string | null>(null)

  const sourceNameById = useMemo(
    () => new Map(scanSources.map((source) => [source.id, source.name])),
    [scanSources],
  )

  return (
    <div className="page-stack">
      <header className="page-head">
        <div>
          <h1>Manage Asset Classes</h1>
          <p>Maintain mapped assets and source tooling per fixed class.</p>
        </div>
      </header>

      <section className="grid grid-3">
        {assetClasses.map((assetClass) => {
          const classAssets = assets.filter((asset) => asset.classId === assetClass.id)
          return (
            <Card key={assetClass.id} title={assetClass.name} subtitle={assetClass.description}>
              <p>
                <strong>{classAssets.length}</strong> mapped assets
              </p>
              <div className="source-badges">
                {assetClass.defaultSourceIds.map((sourceId) => (
                  <Badge key={sourceId}>{sourceNameById.get(sourceId) ?? sourceId}</Badge>
                ))}
              </div>
              <div className="card-actions">
                <Link className={buttonClass('secondary', 'sm')} to={`/asset-classes/${assetClass.id}`}>
                  Manage Class
                </Link>
                <Button
                  size="sm"
                  disabled={isScanRunning}
                  onClick={async () => {
                    setRunning(assetClass.id)
                    await runClassResync(assetClass.id)
                    setRunning(null)
                  }}
                >
                  {running === assetClass.id ? 'Running...' : 'Resync'}
                </Button>
              </div>
            </Card>
          )
        })}
      </section>
    </div>
  )
}
