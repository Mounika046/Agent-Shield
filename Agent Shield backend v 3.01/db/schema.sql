PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS asset_classes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_sources (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  vendor TEXT NOT NULL,
  channel TEXT NOT NULL,
  url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_class_sources (
  class_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  PRIMARY KEY (class_id, source_id),
  FOREIGN KEY (class_id) REFERENCES asset_classes(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES scan_sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  class_id TEXT NOT NULL,
  name TEXT NOT NULL,
  vendor TEXT NOT NULL,
  version TEXT NOT NULL,
  os TEXT NOT NULL,
  environment TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (class_id) REFERENCES asset_classes(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS asset_source_overrides (
  asset_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  PRIMARY KEY (asset_id, source_id),
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES scan_sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('global', 'asset', 'asset-class')),
  target_asset_id TEXT,
  target_class_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
  started_at TEXT NOT NULL,
  ended_at TEXT NOT NULL,
  triggered_by TEXT NOT NULL CHECK (triggered_by = 'manual'),
  assets_scanned INTEGER NOT NULL,
  sources_checked INTEGER NOT NULL,
  findings INTEGER NOT NULL,
  critical_count INTEGER NOT NULL,
  high_count INTEGER NOT NULL,
  medium_count INTEGER NOT NULL,
  low_count INTEGER NOT NULL,
  FOREIGN KEY (target_asset_id) REFERENCES assets(id) ON DELETE SET NULL,
  FOREIGN KEY (target_class_id) REFERENCES asset_classes(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS scan_run_logs (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('info', 'warn', 'error', 'success')),
  message TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_run_asset_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  asset_name TEXT NOT NULL,
  class_id TEXT NOT NULL,
  class_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
  started_at TEXT NOT NULL,
  ended_at TEXT NOT NULL,
  UNIQUE (run_id, asset_id),
  FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
  FOREIGN KEY (class_id) REFERENCES asset_classes(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS scan_run_source_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  asset_result_id INTEGER NOT NULL,
  source_id TEXT NOT NULL,
  source_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
  started_at TEXT NOT NULL,
  ended_at TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
  FOREIGN KEY (asset_result_id) REFERENCES scan_run_asset_results(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES scan_sources(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS cve_findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  asset_result_id INTEGER NOT NULL,
  source_result_id INTEGER NOT NULL,
  cve_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  source_id TEXT NOT NULL,
  source_name TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  published_at TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
  FOREIGN KEY (asset_result_id) REFERENCES scan_run_asset_results(id) ON DELETE CASCADE,
  FOREIGN KEY (source_result_id) REFERENCES scan_run_source_results(id) ON DELETE CASCADE,
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
  FOREIGN KEY (source_id) REFERENCES scan_sources(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_assets_class_id ON assets(class_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started_at ON scan_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_run_logs_run_id ON scan_run_logs(run_id);
CREATE INDEX IF NOT EXISTS idx_scan_run_asset_results_run_id ON scan_run_asset_results(run_id);
CREATE INDEX IF NOT EXISTS idx_scan_run_source_results_asset_result_id ON scan_run_source_results(asset_result_id);
CREATE INDEX IF NOT EXISTS idx_cve_findings_run_id ON cve_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_cve_findings_asset_id ON cve_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_cve_findings_severity ON cve_findings(severity);
