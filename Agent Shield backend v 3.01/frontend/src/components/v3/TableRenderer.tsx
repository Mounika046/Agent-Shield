import type { TableColumn } from './chatTypes.js';
import styles from './ChatPage.module.css';

type TableRendererProps = {
  title?: string;
  data?: Array<Record<string, unknown>>;
  columns?: TableColumn[];
  variant?: 'default' | 'vulnerabilities' | 'licenses';
};

function stringifyCell(value: unknown): string {
  if (value == null) return '';
  if (Array.isArray(value)) return value.join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function inferColumns(data: Array<Record<string, unknown>>): TableColumn[] {
  const first = data[0];
  if (!first) return [];
  return Object.keys(first).map((key) => ({ key, label: key.replace(/_/g, ' ') }));
}

function severityClassName(value: string) {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'critical' || normalized === 'high') return styles.severityHigh;
  if (normalized === 'medium' || normalized === 'moderate') return styles.severityMedium;
  if (normalized === 'low') return styles.severityLow;
  return styles.severityUnknown;
}

function vulnerabilityLinkForId(id: string): string {
  const normalized = id.trim();
  if (!normalized) return '';
  if (normalized.toUpperCase().startsWith('CVE-')) {
    return `https://nvd.nist.gov/vuln/detail/${normalized}`;
  }
  return `https://osv.dev/vulnerability/${normalized}`;
}

function renderVulnerabilityCell(key: string, row: Record<string, unknown>) {
  if (key === 'severity') {
    const label = stringifyCell(row[key]) || 'unknown';
    return <span className={`${styles.severityBadge} ${severityClassName(label)}`}>{label}</span>;
  }

  if (key === 'vulnerability_id') {
    const label = stringifyCell(row[key]);
    const href = vulnerabilityLinkForId(label);
    if (href) {
      return (
        <a href={href} target="_blank" rel="noreferrer" className={styles.tableLink}>
          {label}
        </a>
      );
    }
    return label;
  }

  if (key === 'references') {
    const links = Array.isArray(row.references) ? row.references : [];
    if (!links.length) return '';
    return (
      <div className={styles.referenceList}>
        {links.map((link, index) => {
          if (!link || typeof link !== 'object') return null;
          const href = stringifyCell((link as Record<string, unknown>).url);
          const label = stringifyCell((link as Record<string, unknown>).label) || `Link ${index + 1}`;
          if (!href) return null;
          return (
            <a key={`${href}-${index}`} href={href} target="_blank" rel="noreferrer" className={styles.tableLink}>
              {label}
            </a>
          );
        })}
      </div>
    );
  }

  if (key === 'fixed_version') {
    const value = stringifyCell(row[key]);
    if (!value) {
      return <span className={styles.mutedCell}>No fixed version</span>;
    }
    return value;
  }

  return stringifyCell(row[key]);
}

function renderDefaultCell(key: string, row: Record<string, unknown>) {
  if (key === 'origin') {
    const origin = row.origin;
    if (!origin || typeof origin !== 'object') {
      return <span className={styles.mutedCell}>Unavailable</span>;
    }
    const href = stringifyCell((origin as Record<string, unknown>).url);
    const label = stringifyCell((origin as Record<string, unknown>).label) || 'Registry';
    if (!href) {
      return <span className={styles.mutedCell}>Unavailable</span>;
    }
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className={styles.tableLink}>
        {label}
      </a>
    );
  }

  return stringifyCell(row[key]);
}

function policyStatusClassName(value: string) {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'allowed') return styles.statusAllowed;
  return styles.statusReview;
}

function renderLicenseCell(key: string, row: Record<string, unknown>) {
  if (key === 'policy_status') {
    const label = stringifyCell(row[key]) || 'Review required';
    return <span className={`${styles.statusBadgePill} ${policyStatusClassName(label)}`}>{label}</span>;
  }

  if (key === 'source_links') {
    const links = Array.isArray(row.source_links) ? row.source_links : [];
    if (!links.length) return '';
    return (
      <div className={styles.referenceList}>
        {links.map((link, index) => {
          if (!link || typeof link !== 'object') return null;
          const label = stringifyCell((link as Record<string, unknown>).label) || `Link ${index + 1}`;
          const href = stringifyCell((link as Record<string, unknown>).url);
          if (!href) return null;
          return (
            <a key={`${href}-${index}`} href={href} target="_blank" rel="noreferrer" className={styles.tableLink}>
              {label}
            </a>
          );
        })}
      </div>
    );
  }

  return stringifyCell(row[key]);
}

function columnClassName(key: string, variant: NonNullable<TableRendererProps['variant']>) {
  if (variant !== 'vulnerabilities') return '';
  if (key === 'package' || key === 'version' || key === 'severity' || key === 'fixed_version' || key === 'vulnerability_id') {
    return styles.tableCellNoWrap;
  }
  if (key === 'summary' || key === 'references') {
    return styles.tableCellWrap;
  }
  return '';
}

const licenseColumns = [
  { key: 'package', label: 'Package' },
  { key: 'version', label: 'Version' },
  { key: 'detected_license', label: 'Detected License' },
  { key: 'policy_status', label: 'Policy Status' },
  { key: 'reason', label: 'Reason' },
  { key: 'source_links', label: 'Source Links' },
] as const;

export function TableRenderer({ title, data = [], columns, variant = 'default' }: TableRendererProps) {
  if (!data.length) return null;
  const resolvedColumns =
    columns?.length
      ? columns
      : variant === 'licenses'
        ? [...licenseColumns]
        : inferColumns(data);
  if (!resolvedColumns.length) return null;

  return (
    <div className={styles.tableWrapper}>
      {title && <h4 className={styles.tableTitle}>{title}</h4>}
      <div className={styles.tableShell}>
        <table className={`${styles.table} ${variant === 'vulnerabilities' ? styles.tableVulnerabilities : ''}`}>
          <thead>
            <tr>
              {resolvedColumns.map((column) => (
                <th key={column.key} className={columnClassName(column.key, variant)}>
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {resolvedColumns.map((column) => (
                  <td key={column.key} className={columnClassName(column.key, variant)}>
                    {variant === 'vulnerabilities'
                      ? renderVulnerabilityCell(column.key, row)
                      : variant === 'licenses'
                        ? renderLicenseCell(column.key, row)
                        : renderDefaultCell(column.key, row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
