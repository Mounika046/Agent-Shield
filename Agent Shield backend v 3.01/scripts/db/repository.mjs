export const upsertSeedData = (db, { assetClasses, scanSources, assets }) => {
  const upsertAssetClass = db.prepare(`
    INSERT INTO asset_classes (id, name, description)
    VALUES (@id, @name, @description)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      description = excluded.description
  `)

  const upsertScanSource = db.prepare(`
    INSERT INTO scan_sources (id, name, vendor, channel, url)
    VALUES (@id, @name, @vendor, @channel, @url)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      vendor = excluded.vendor,
      channel = excluded.channel,
      url = excluded.url
  `)

  const upsertAsset = db.prepare(`
    INSERT INTO assets (id, class_id, name, vendor, version, os, environment)
    VALUES (@id, @class_id, @name, @vendor, @version, @os, @environment)
    ON CONFLICT(id) DO UPDATE SET
      class_id = excluded.class_id,
      name = excluded.name,
      vendor = excluded.vendor,
      version = excluded.version,
      os = excluded.os,
      environment = excluded.environment,
      updated_at = datetime('now')
  `)

  const clearClassSources = db.prepare(`DELETE FROM asset_class_sources WHERE class_id = ?`)
  const insertClassSource = db.prepare(`
    INSERT OR IGNORE INTO asset_class_sources (class_id, source_id)
    VALUES (?, ?)
  `)

  const run = db.transaction(() => {
    for (const scanSource of scanSources) {
      upsertScanSource.run(scanSource)
    }

    for (const assetClass of assetClasses) {
      upsertAssetClass.run({
        id: assetClass.id,
        name: assetClass.name,
        description: assetClass.description,
      })
      clearClassSources.run(assetClass.id)
      for (const sourceId of assetClass.defaultSourceIds) {
        insertClassSource.run(assetClass.id, sourceId)
      }
    }

    for (const asset of assets) {
      upsertAsset.run({
        id: asset.id,
        class_id: asset.classId,
        name: asset.name,
        vendor: asset.vendor,
        version: asset.version,
        os: asset.os,
        environment: asset.environment,
      })
    }
  })

  run()
}

export const saveScanRun = (db, run) => {
  const insertRun = db.prepare(`
    INSERT OR REPLACE INTO scan_runs (
      id, scope, target_asset_id, target_class_id, status, started_at, ended_at,
      triggered_by, assets_scanned, sources_checked, findings,
      critical_count, high_count, medium_count, low_count
    ) VALUES (
      @id, @scope, @target_asset_id, @target_class_id, @status, @started_at, @ended_at,
      @triggered_by, @assets_scanned, @sources_checked, @findings,
      @critical_count, @high_count, @medium_count, @low_count
    )
  `)

  const clearRunData = db.prepare(`DELETE FROM scan_run_asset_results WHERE run_id = ?`)
  const clearLogs = db.prepare(`DELETE FROM scan_run_logs WHERE run_id = ?`)

  const insertLog = db.prepare(`
    INSERT INTO scan_run_logs (id, run_id, timestamp, level, message)
    VALUES (@id, @run_id, @timestamp, @level, @message)
  `)

  const insertAssetResult = db.prepare(`
    INSERT INTO scan_run_asset_results (
      run_id, asset_id, asset_name, class_id, class_name, status, started_at, ended_at
    ) VALUES (
      @run_id, @asset_id, @asset_name, @class_id, @class_name, @status, @started_at, @ended_at
    )
  `)

  const insertSourceResult = db.prepare(`
    INSERT INTO scan_run_source_results (
      run_id, asset_result_id, source_id, source_name, status, started_at, ended_at
    ) VALUES (
      @run_id, @asset_result_id, @source_id, @source_name, @status, @started_at, @ended_at
    )
  `)

  const insertFinding = db.prepare(`
    INSERT OR REPLACE INTO cve_findings (
      id, run_id, asset_result_id, source_result_id, cve_id, title, severity,
      source_id, source_name, asset_id, published_at
    ) VALUES (
      @id, @run_id, @asset_result_id, @source_result_id, @cve_id, @title, @severity,
      @source_id, @source_name, @asset_id, @published_at
    )
  `)

  const runTx = db.transaction(() => {
    insertRun.run({
      id: run.id,
      scope: run.scope,
      target_asset_id: run.targetAssetId ?? null,
      target_class_id: run.targetClassId ?? null,
      status: run.status,
      started_at: run.startedAt,
      ended_at: run.endedAt,
      triggered_by: run.triggeredBy,
      assets_scanned: run.totals.assetsScanned,
      sources_checked: run.totals.sourcesChecked,
      findings: run.totals.findings,
      critical_count: run.totals.severityCounts.critical,
      high_count: run.totals.severityCounts.high,
      medium_count: run.totals.severityCounts.medium,
      low_count: run.totals.severityCounts.low,
    })

    clearLogs.run(run.id)
    clearRunData.run(run.id)

    for (const log of run.logs) {
      insertLog.run({
        id: log.id,
        run_id: run.id,
        timestamp: log.timestamp,
        level: log.level,
        message: log.message,
      })
    }

    for (const assetResult of run.assetResults) {
      const assetInsert = insertAssetResult.run({
        run_id: run.id,
        asset_id: assetResult.assetId,
        asset_name: assetResult.assetName,
        class_id: assetResult.classId,
        class_name: assetResult.className,
        status: assetResult.status,
        started_at: assetResult.startedAt,
        ended_at: assetResult.endedAt,
      })

      const assetResultId = Number(assetInsert.lastInsertRowid)
      for (const sourceResult of assetResult.sourceResults) {
        const sourceInsert = insertSourceResult.run({
          run_id: run.id,
          asset_result_id: assetResultId,
          source_id: sourceResult.sourceId,
          source_name: sourceResult.sourceName,
          status: sourceResult.status,
          started_at: sourceResult.startedAt,
          ended_at: sourceResult.endedAt,
        })

        const sourceResultId = Number(sourceInsert.lastInsertRowid)
        for (const finding of sourceResult.findings) {
          insertFinding.run({
            id: finding.id,
            run_id: run.id,
            asset_result_id: assetResultId,
            source_result_id: sourceResultId,
            cve_id: finding.cveId,
            title: finding.title,
            severity: finding.severity,
            source_id: finding.sourceId,
            source_name: finding.sourceName,
            asset_id: finding.assetId,
            published_at: finding.publishedAt,
          })
        }
      }
    }
  })

  runTx()
}
