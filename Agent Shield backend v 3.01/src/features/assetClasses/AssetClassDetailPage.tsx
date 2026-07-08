import { useMemo, useState } from 'react'
import { X } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { Button, buttonClass } from '../../components/ui/Button'
import { Card } from '../../components/ui/Card'
import { Table } from '../../components/ui/Table'
import { Badge } from '../../components/ui/Badge'
import { SourcePillSelector } from '../../components/ui/SourcePillSelector'
import { useAppStore, useAssetClassById, getEffectiveSourceIds } from '../../app/AppProvider'

const toggleSelection = (selectedIds: string[], sourceId: string) => {
  const next = new Set(selectedIds)
  if (next.has(sourceId)) {
    next.delete(sourceId)
  } else {
    next.add(sourceId)
  }
  return Array.from(next)
}

export const AssetClassDetailPage = () => {
  const { classId = '' } = useParams()
  const assetClass = useAssetClassById(classId)
  const { assets, scanSources, runs, addAsset, removeAsset, setClassSources, setAssetSources, addScanSource } =
    useAppStore()
  const isGithubClass = classId === 'github-org'

  const classAssets = useMemo(
    () => assets.filter((asset) => asset.classId === classId),
    [assets, classId],
  )

  const [isManageSourcesOpen, setIsManageSourcesOpen] = useState(false)
  const [isAddAssetOpen, setIsAddAssetOpen] = useState(false)
  const [isAddSourceOpen, setIsAddSourceOpen] = useState(false)
  const [newAssetName, setNewAssetName] = useState('')
  const [newVendor, setNewVendor] = useState('')
  const [newVersion, setNewVersion] = useState('')
  const [newOs, setNewOs] = useState('')
  const [newEnvironment, setNewEnvironment] = useState('')
  const [githubAddMode, setGithubAddMode] = useState<'single' | 'bulk'>('single')
  const [repoVisibility, setRepoVisibility] = useState<'public' | 'private'>('public')
  const [repoUrl, setRepoUrl] = useState('')
  const [repoBulkText, setRepoBulkText] = useState('')
  const [repoToken, setRepoToken] = useState('')
  const [addAssetError, setAddAssetError] = useState('')
  const [isAddingAsset, setIsAddingAsset] = useState(false)
  const [newSourceName, setNewSourceName] = useState('')
  const [newSourceUrl, setNewSourceUrl] = useState('')
  const backendBaseUrl = (import.meta.env.VITE_BACKEND_URL ?? 'http://localhost:8070').replace(/\/+$/, '')

  const normalizeRepoPath = (input: string) =>
    input
      .trim()
      .replace(/^https?:\/\/github\.com\//i, '')
      .replace(/\/+$/g, '')

  const parseRepoLines = (text: string) => {
    const lines = text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)

    const seen = new Set<string>()
    const repos: string[] = []
    for (const line of lines) {
      const cells = line.split('\t').flatMap((tabCell) => tabCell.split(','))
      const picked =
        cells.find((cell) => /github\.com\//i.test(cell)) ??
        cells.find((cell) => /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(cell))

      if (!picked) continue
      const normalized = normalizeRepoPath(picked)
      if (!normalized || seen.has(normalized)) continue
      seen.add(normalized)
      repos.push(normalized)
    }
    return repos
  }

  const runGithubScan = async (repoPathOrUrl: string, token?: string) => {
    const repoUrlForApi = /^https?:\/\//i.test(repoPathOrUrl)
      ? repoPathOrUrl.trim()
      : `https://github.com/${repoPathOrUrl.trim()}`

    const response = await fetch(`${backendBaseUrl}/scan/github`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repo_url: repoUrlForApi,
        token: token?.trim() || null,
      }),
    })

    if (!response.ok) {
      let message = `GitHub scan failed (${response.status})`
      try {
        const data = (await response.json()) as { detail?: string }
        if (data?.detail) message = data.detail
      } catch {
        const raw = await response.text()
        if (raw) message = raw
      }
      throw new Error(message)
    }
    return (await response.json()) as { json_report: Record<string, unknown> }
  }

  if (!assetClass) {
    return <p>Asset class not found.</p>
  }

  const sourceNameById = new Map(scanSources.map((source) => [source.id, source.name]))

  return (
    <div className="page-stack">
      <header className="page-head">
        <div>
          <h1>{assetClass.name}</h1>
          <p>{assetClass.description}</p>
        </div>
        <div className="page-head-actions">
          <Button variant="secondary" onClick={() => setIsManageSourcesOpen(true)}>
            Manage Sources
          </Button>
          <Button onClick={() => setIsAddAssetOpen(true)}>Add Asset</Button>
          <Link className={buttonClass('secondary')} to="/asset-classes">
            Back to classes
          </Link>
        </div>
      </header>

      <Card title="Mapped Assets" subtitle="Full asset inventory with source mapping controls.">
        <Table>
          <thead>
            <tr>
              <th>Asset</th>
              <th>Vendor</th>
              <th>Version</th>
              <th>Open CVEs</th>
              <th>OS</th>
              <th>Environment</th>
              <th>Effective Sources</th>
              <th>Source Overrides</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {classAssets.length === 0 && (
              <tr>
                <td colSpan={9}>No assets mapped yet. Click Add Asset to create one.</td>
              </tr>
            )}
            {classAssets.map((asset) => {
              const effectiveSources = getEffectiveSourceIds(asset, assetClass)
              const latestRunWithAsset = runs.find((run) =>
                run.assetResults.some((assetResult) => assetResult.assetId === asset.id),
              )
              const latestAssetResult = latestRunWithAsset?.assetResults.find(
                (assetResult) => assetResult.assetId === asset.id,
              )
              const openCveCount =
                latestAssetResult?.sourceResults.reduce(
                  (sum, sourceResult) => sum + sourceResult.findings.length,
                  0,
                ) ?? 0

              return (
                <tr key={asset.id}>
                  <td>{asset.name}</td>
                  <td>{asset.vendor}</td>
                  <td>{asset.version}</td>
                  <td>
                    <Badge tone={openCveCount > 0 ? 'danger' : 'success'}>{openCveCount}</Badge>
                  </td>
                  <td>{asset.os}</td>
                  <td>{asset.environment}</td>
                  <td>
                    <div className="source-badges">
                      {effectiveSources.map((sourceId) => (
                        <span className="badge" key={sourceId}>
                          {sourceNameById.get(sourceId) ?? sourceId}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <details>
                      <summary>Override sources</summary>
                      <SourcePillSelector
                        sources={scanSources}
                        selectedIds={asset.sourceOverrideIds ?? effectiveSources}
                        onToggle={(sourceId) => {
                          const selected = asset.sourceOverrideIds ?? effectiveSources
                          setAssetSources(asset.id, toggleSelection(selected, sourceId))
                        }}
                      />
                      <div className="details-actions">
                        <button
                          type="button"
                          className="table-link"
                          onClick={() => setAssetSources(asset.id, undefined)}
                        >
                          Reset to class defaults
                        </button>
                      </div>
                    </details>
                  </td>
                  <td>
                    <div className="row-actions">
                      <Link className="table-link" to={`/assets/${asset.id}`}>
                        Open
                      </Link>
                      <button type="button" className="table-link danger-link" onClick={() => removeAsset(asset.id)}>
                        Remove
                      </button>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </Table>
      </Card>

      {isManageSourcesOpen && (
        <div className="modal-backdrop" role="presentation">
          <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="manage-sources-title">
            <header className="modal-head">
              <div>
                <h3 id="manage-sources-title">Manage Sources</h3>
                <p>Choose class defaults and add custom source feeds.</p>
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
              selectedIds={assetClass.defaultSourceIds}
              onToggle={(sourceId) =>
                setClassSources(assetClass.id, toggleSelection(assetClass.defaultSourceIds, sourceId))
              }
            />

            <div className="card-actions">
              <Button onClick={() => setIsAddSourceOpen(true)}>Add Source</Button>
            </div>

            <footer className="modal-actions">
              <Button variant="secondary" onClick={() => setIsManageSourcesOpen(false)}>
                Done
              </Button>
            </footer>
          </div>
        </div>
      )}

      {isAddSourceOpen && (
        <div className="modal-backdrop" role="presentation">
          <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="add-source-title">
            <header className="modal-head">
              <div>
                <h3 id="add-source-title">Add Source</h3>
                <p>Add a custom CVE source feed for this class.</p>
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
                const newSource = addScanSource({ name: newSourceName, url: newSourceUrl })
                setClassSources(assetClass.id, [...assetClass.defaultSourceIds, newSource.id])
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

      {isAddAssetOpen && (
        <div className="modal-backdrop" role="presentation">
          <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="add-asset-title">
            <header className="modal-head">
              <div>
                <h3 id="add-asset-title">Add Asset</h3>
                <p>Map a new asset to this class for CVE scanning.</p>
              </div>
              <button
                type="button"
                className="icon-btn modal-close-btn"
                aria-label="Close modal"
                onClick={() => setIsAddAssetOpen(false)}
              >
                <X size={16} />
              </button>
            </header>

            <form
              className={isGithubClass ? 'modal-form-stack' : 'form-grid'}
              onSubmit={(event) => {
                event.preventDefault()

                if (!newAssetName.trim()) return
                addAsset({
                  classId: assetClass.id,
                  name: newAssetName.trim(),
                  vendor: newVendor.trim() || 'Unknown',
                  version: newVersion.trim() || 'N/A',
                  os: newOs.trim() || 'N/A',
                  environment: newEnvironment.trim() || 'Unknown',
                })
                setNewAssetName('')
                setNewVendor('')
                setNewVersion('')
                setNewOs('')
                setNewEnvironment('')
                setIsAddAssetOpen(false)
              }}
            >
              {isGithubClass ? (
                <>
                  <div className="modal-tabs" role="tablist" aria-label="Add mode">
                    <button
                      type="button"
                      role="tab"
                      aria-selected={githubAddMode === 'single'}
                      className={githubAddMode === 'single' ? 'modal-tab active' : 'modal-tab'}
                      onClick={() => setGithubAddMode('single')}
                    >
                      Single Repo
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={githubAddMode === 'bulk'}
                      className={githubAddMode === 'bulk' ? 'modal-tab active' : 'modal-tab'}
                      onClick={() => setGithubAddMode('bulk')}
                    >
                      Bulk Import (Excel)
                    </button>
                  </div>

                  <div className="visibility-toggle" role="radiogroup" aria-label="Repository visibility">
                    <label
                      className={repoVisibility === 'public' ? 'radio-card active' : 'radio-card'}
                      aria-label="Public Repo"
                    >
                      <input
                        type="radio"
                        name="repoVisibility"
                        value="public"
                        checked={repoVisibility === 'public'}
                        onChange={() => setRepoVisibility('public')}
                        className="radio-card-input"
                      />
                      <span className="radio-card-indicator" aria-hidden="true" />
                      <span className="radio-card-content">
                        <strong>Public Repo</strong>
                        <small>Scan with public metadata.</small>
                      </span>
                    </label>
                    <label
                      className={repoVisibility === 'private' ? 'radio-card active' : 'radio-card'}
                      aria-label="Private Repo"
                    >
                      <input
                        type="radio"
                        name="repoVisibility"
                        value="private"
                        checked={repoVisibility === 'private'}
                        onChange={() => setRepoVisibility('private')}
                        className="radio-card-input"
                      />
                      <span className="radio-card-indicator" aria-hidden="true" />
                      <span className="radio-card-content">
                        <strong>Private Repo</strong>
                        <small>Token required to access advisories.</small>
                      </span>
                    </label>
                  </div>

                  {githubAddMode === 'single' ? (
                    <input
                      placeholder="GitHub repo URL (e.g. https://github.com/org/repo)"
                      type="url"
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                      required
                    />
                  ) : (
                    <>
                      <textarea
                        className="bulk-textarea"
                        placeholder={
                          'Paste from Excel (one repo per row).\nExamples:\nhttps://github.com/org/repo\norg/repo'
                        }
                        value={repoBulkText}
                        onChange={(e) => setRepoBulkText(e.target.value)}
                        required
                      />
                      <p className="helper-text">
                        Tip: you can paste an Excel column or full rows; GitHub repo URLs will be detected.
                      </p>
                    </>
                  )}

                  {repoVisibility === 'private' && (
                    <input
                      placeholder="GitHub token"
                      type="password"
                      value={repoToken}
                      onChange={(e) => setRepoToken(e.target.value)}
                      required
                    />
                  )}
                </>
              ) : (
                <>
                  <input
                    placeholder="Asset name"
                    value={newAssetName}
                    onChange={(e) => setNewAssetName(e.target.value)}
                  />
                  <input placeholder="Vendor" value={newVendor} onChange={(e) => setNewVendor(e.target.value)} />
                  <input placeholder="Version" value={newVersion} onChange={(e) => setNewVersion(e.target.value)} />
                  <input placeholder="OS" value={newOs} onChange={(e) => setNewOs(e.target.value)} />
                  <input
                    placeholder="Environment"
                    value={newEnvironment}
                    onChange={(e) => setNewEnvironment(e.target.value)}
                  />
                </>
              )}

              <div className="modal-actions">
                <Button type="button" variant="secondary" onClick={() => setIsAddAssetOpen(false)}>
                  Cancel
                </Button>
                <Button
                  type="submit"
                  onClick={async (event) => {
                    if (!isGithubClass) return
                    event.preventDefault()
                    setAddAssetError('')
                    if (repoVisibility === 'private' && !repoToken.trim()) {
                      setAddAssetError('Private repository requires a GitHub token.')
                      return
                    }

                    const token = repoVisibility === 'private' ? repoToken.trim() : undefined
                    setIsAddingAsset(true)
                    try {
                      if (githubAddMode === 'single') {
                        const repoPath = normalizeRepoPath(repoUrl)
                        if (!repoPath) {
                          setAddAssetError('Please provide a valid GitHub repository URL.')
                          return
                        }

                        const githubScan = await runGithubScan(repoPath, token)
                        const fallbackName = repoPath.split('/').filter(Boolean).pop() || repoPath

                        addAsset({
                          classId: assetClass.id,
                          name: fallbackName,
                          vendor: 'GitHub',
                          version: repoVisibility === 'private' ? 'private' : 'public',
                          os: 'N/A',
                          environment: 'SaaS',
                          repoUrl: `https://github.com/${repoPath}`,
                          repoToken: token,
                          githubScanReport: githubScan.json_report,
                        })
                        setRepoUrl('')
                        setRepoToken('')
                        setRepoVisibility('public')
                        setGithubAddMode('single')
                        setIsAddAssetOpen(false)
                        return
                      }

                      const repos = parseRepoLines(repoBulkText)
                      if (repos.length === 0) {
                        setAddAssetError('No valid GitHub repositories detected in bulk input.')
                        return
                      }

                      let successCount = 0
                      for (const repoPath of repos) {
                        try {
                          const githubScan = await runGithubScan(repoPath, token)
                          const repoUrl = `https://github.com/${repoPath}`
                          const name = repoPath.split('/').filter(Boolean).pop() || repoPath
                          successCount += 1
                          addAsset({
                            classId: assetClass.id,
                            name,
                            vendor: 'GitHub',
                            version: repoVisibility === 'private' ? 'private' : 'public',
                            os: 'N/A',
                            environment: 'SaaS',
                            repoUrl,
                            repoToken: token,
                            githubScanReport: githubScan.json_report,
                          })
                        } catch {
                          continue
                        }
                      }

                      if (successCount === 0) {
                        setAddAssetError('Could not add any repositories. Please verify URLs/token.')
                        return
                      }

                      setRepoBulkText('')
                      setRepoToken('')
                      setRepoVisibility('public')
                      setGithubAddMode('single')
                      setIsAddAssetOpen(false)
                    } catch (error) {
                      const message = error instanceof Error ? error.message : 'Failed to add repository.'
                      setAddAssetError(message)
                    } finally {
                      setIsAddingAsset(false)
                    }
                  }}
                  disabled={isAddingAsset}
                >
                  {isAddingAsset
                    ? 'Adding...'
                    : isGithubClass && githubAddMode === 'bulk'
                      ? 'Import Repos'
                      : 'Add Asset'}
                </Button>
              </div>
              {isGithubClass && addAssetError && <p className="helper-text" style={{ color: '#ef4444' }}>{addAssetError}</p>}
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
