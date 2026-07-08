import { useEffect, useMemo, useState } from 'react';
import { DependencyGraphView } from './DependencyGraphView.js';
import type { DependencyGraphEntry, SummaryCards } from './chatTypes.js';
import { TableRenderer } from './TableRenderer.js';
import styles from './ChatPage.module.css';

type ResponseArtifactsProps = {
  cards?: SummaryCards;
  dependenciesDiscoveredTable?: Array<Record<string, unknown>>;
  vulnerableDependenciesTable?: Array<Record<string, unknown>>;
  licenseComplianceTable?: Array<Record<string, unknown>>;
  dependencyGraphs?: Record<string, DependencyGraphEntry>;
};

const cardDefinitions: Array<{ key: keyof SummaryCards; label: string }> = [
  { key: 'dependencies_discovered', label: 'Dependencies discovered' },
  { key: 'exact_versions', label: 'Exact versions' },
  { key: 'packages_checked', label: 'Packages checked' },
  { key: 'unique_cves_found', label: 'Unique CVEs found' },
];

const vulnerabilityColumns = [
  { key: 'package', label: 'Package' },
  { key: 'version', label: 'Version' },
  { key: 'severity', label: 'Severity' },
  { key: 'vulnerability_id', label: 'Vulnerability ID' },
  { key: 'summary', label: 'Summary' },
  { key: 'fixed_version', label: 'Fixed Version' },
  { key: 'references', label: 'References' },
] as const;

export function ResponseArtifacts({
  cards,
  dependenciesDiscoveredTable,
  vulnerableDependenciesTable,
  licenseComplianceTable,
  dependencyGraphs,
}: ResponseArtifactsProps) {
  const hasCards = cardDefinitions.some(({ key }) => cards?.[key] != null);
  const hasDependencies = Boolean(dependenciesDiscoveredTable?.length);
  const hasVulnerabilities = Boolean(vulnerableDependenciesTable?.length);
  const hasLicenses = Boolean(licenseComplianceTable?.length);
  const graphEntries = useMemo(() => Object.entries(dependencyGraphs || {}), [dependencyGraphs]);
  const hasDependencyGraphs = graphEntries.length > 0;
  const [selectedGraphKey, setSelectedGraphKey] = useState<string>(graphEntries[0]?.[0] || '');
  const [graphView, setGraphView] = useState<'table' | 'graph'>('table');

  useEffect(() => {
    if (graphEntries.length && !graphEntries.some(([key]) => key === selectedGraphKey)) {
      setSelectedGraphKey(graphEntries[0][0]);
    }
  }, [graphEntries, selectedGraphKey]);

  const activeGraphKey = graphEntries.some(([key]) => key === selectedGraphKey) ? selectedGraphKey : graphEntries[0]?.[0] || '';
  const activeGraph = activeGraphKey ? (dependencyGraphs || {})[activeGraphKey] : undefined;
  const dependencyGraphRows = (activeGraph?.dependencies || []).map((dependency) => ({
    package: activeGraph?.package || '',
    version: activeGraph?.version || '',
    dependency: dependency.name,
    dependency_version: dependency.version || 'unknown',
  }));

  if (!hasCards && !hasDependencies && !hasVulnerabilities && !hasLicenses && !hasDependencyGraphs) {
    return null;
  }

  return (
    <div className={styles.artifactStack}>
      {hasCards && (
        <section className={styles.artifactSection}>
          <div className={styles.cardGrid}>
            {cardDefinitions.map(({ key, label }) => (
              <div key={key} className={styles.summaryCard}>
                <span className={styles.summaryCardLabel}>{label}</span>
                <strong className={styles.summaryCardValue}>{cards?.[key] ?? 0}</strong>
              </div>
            ))}
          </div>
        </section>
      )}

      {hasDependencies && (
        <section className={styles.artifactSection}>
          <TableRenderer title="Dependencies discovered" data={dependenciesDiscoveredTable} />
        </section>
      )}

      {hasVulnerabilities && (
        <section className={styles.artifactSection}>
          <TableRenderer
            title="Vulnerable dependencies"
            data={vulnerableDependenciesTable}
            columns={[...vulnerabilityColumns]}
            variant="vulnerabilities"
          />
        </section>
      )}

      {hasLicenses && (
        <section className={styles.artifactSection}>
          <div className={styles.tableHeaderBlock}>
            <h3 className={styles.tableHeaderTitle}>License compliance</h3>
            <p className={styles.tableDescription}>
              This table contains links to package repositories and documentation. Refer to them to review license details.
            </p>
          </div>
          <TableRenderer data={licenseComplianceTable} variant="licenses" />
        </section>
      )}

      {hasDependencyGraphs && activeGraph && (
        <section className={styles.artifactSection}>
          <div className={styles.tableHeaderBlock}>
            <h3 className={styles.tableHeaderTitle}>Dependency graph</h3>
            <p className={styles.tableDescription}>
              Developer Mode fetches direct dependency relationships from deps.dev for the top vulnerable exact-version packages.
            </p>
          </div>

          <div className={styles.graphToolbar}>
            <label className={styles.graphControl}>
              <span className={styles.graphControlLabel}>Package</span>
              <select
                className={styles.graphSelect}
                value={activeGraphKey}
                onChange={(event) => setSelectedGraphKey(event.target.value)}
              >
                {graphEntries.map(([key, graph]) => (
                  <option key={key} value={key}>
                    {graph.package}@{graph.version}
                  </option>
                ))}
              </select>
            </label>

            <div className={styles.graphToggle} role="tablist" aria-label="Dependency graph view">
              <button
                type="button"
                className={`${styles.graphToggleButton} ${graphView === 'table' ? styles.graphToggleButtonActive : ''}`}
                onClick={() => setGraphView('table')}
              >
                Table
              </button>
              <button
                type="button"
                className={`${styles.graphToggleButton} ${graphView === 'graph' ? styles.graphToggleButtonActive : ''}`}
                onClick={() => setGraphView('graph')}
              >
                Graph
              </button>
            </div>
          </div>

          <div className={styles.graphMeta}>
            <span className={styles.graphMetaChip}>{activeGraph.package}@{activeGraph.version}</span>
            <span className={styles.graphMetaChip}>{activeGraph.dependency_count ?? activeGraph.dependencies.length} direct dependencies</span>
            {activeGraph.truncated && <span className={styles.graphMetaChip}>Showing first {activeGraph.dependencies.length}</span>}
          </div>

          {graphView === 'table' ? (
            <TableRenderer
              title="Direct dependencies"
              data={dependencyGraphRows}
              columns={[
                { key: 'package', label: 'Package' },
                { key: 'version', label: 'Version' },
                { key: 'dependency', label: 'Dependency' },
                { key: 'dependency_version', label: 'Version' },
              ]}
            />
          ) : (
            <DependencyGraphView graph={activeGraph} />
          )}
        </section>
      )}
    </div>
  );
}
