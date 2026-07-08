import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Badge,
  Button,
  Card,
  ComponentMessage,
  DataManagementPage,
  EmptyState,
  InputPassword,
  InputText,
  Select,
  Table,
  TextArea,
  type Columns,
} from '@idp/nitro-redwood';
import {
  askAgentShield,
  checkHealth,
  runScan,
  type AgentChatResponse,
  type AgentChatRequest,
  type AgentSummaryCards,
  type PackageCoordinate,
  type ScanMode,
  type ScanReport,
  type ScanRequest,
  type ScanResponse,
  type VulnerabilityFinding,
} from '../api/agentShieldApi.js';
import styles from './AgentShieldWorkspace.module.css';

type InputSource = 'repository' | 'file' | 'manual' | 'packages';

const sourceOptions: Array<{ id: InputSource; label: string }> = [
  { id: 'repository', label: 'GitHub repository' },
  { id: 'file', label: 'Dependency file' },
  { id: 'manual', label: 'Paste dependencies' },
  { id: 'packages', label: 'Direct packages' },
];

const modeOptions = [
  { value: 'fast', label: 'Fast — CVE analysis' },
  { value: 'detailed', label: 'Detailed — CVEs and deps.dev metadata' },
  { value: 'developer', label: 'Developer — engineering priorities and repository context' },
];

const ecosystemOptions = [
  { value: 'PyPI', label: 'Python / PyPI' },
  { value: 'npm', label: 'JavaScript / npm' },
  { value: 'Maven', label: 'Java / Maven' },
  { value: 'Conda', label: 'Conda' },
];

interface FindingRow {
  key: string;
  packageName: string;
  version: string;
  severity: string;
  identifier: string;
  cvss: string;
  summary: string;
  fixedVersion: string;
  referenceUrl: string;
}

interface DependencyRow {
  key: string;
  name: string;
  version: string;
  versionKind: string;
  ecosystem: string;
  source: string;
}

interface LicenseRow {
  key: string;
  packageName: string;
  version: string;
  license: string;
  policyStatus: string;
  source: string;
}

interface ChatMessage {
  id: number;
  role: 'assistant' | 'user';
  text: string;
  responseSource?: 'oci' | 'deterministic';
  artifacts?: ChatArtifacts;
}

interface ChatArtifacts {
  cards?: AgentSummaryCards;
  dependencies: ChatDependencyRow[];
  vulnerabilities: ChatVulnerabilityRow[];
  licenses: ChatLicenseRow[];
  fixSummary?: string;
}

interface ChatDependencyRow {
  key: string;
  packageName: string;
  version: string;
  ecosystem: string;
  source: string;
}

interface ChatVulnerabilityRow {
  key: string;
  packageName: string;
  version: string;
  severity: string;
  vulnerabilityId: string;
  summary: string;
  fixedVersion: string;
}

interface ChatLicenseRow {
  key: string;
  packageName: string;
  version: string;
  license: string;
  policyStatus: string;
  reason: string;
}

function renderInlineText(text: string) {
  return text.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g).map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={`${part}-${index}`}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={`${part}-${index}`}>{part.slice(1, -1)}</code>;
    }
    if (part.startsWith('*') && part.endsWith('*')) {
      return <em key={`${part}-${index}`}>{part.slice(1, -1)}</em>;
    }
    return part;
  });
}

function ChatResponseContent({ text, preview = false }: { text: string; preview?: boolean }) {
  return (
    <div className={preview ? styles.responsePreview : styles.richResponse}>
      {text.split('\n').map((line, index) => {
        const trimmed = line.trim();
        if (!trimmed) return <span key={`space-${index}`} className={styles.responseSpace} aria-hidden="true" />;
        if (trimmed.startsWith('### ')) return <h4 key={index}>{renderInlineText(trimmed.slice(4))}</h4>;
        if (trimmed.startsWith('## ')) return <h3 key={index}>{renderInlineText(trimmed.slice(3))}</h3>;
        if (trimmed.startsWith('# ')) return <h2 key={index}>{renderInlineText(trimmed.slice(2))}</h2>;
        const numberedItem = trimmed.match(/^(\d+)[.)]\s+(.*)$/);
        if (numberedItem) {
          return <p key={index} className={styles.responseListItem}><span>{numberedItem[1]}.</span><span>{renderInlineText(numberedItem[2])}</span></p>;
        }
        if (/^[-*]\s+/.test(trimmed)) {
          return <p key={index} className={styles.responseListItem}><span>•</span><span>{renderInlineText(trimmed.slice(2))}</span></p>;
        }
        return <p key={index}>{renderInlineText(trimmed)}</p>;
      })}
    </div>
  );
}

const findingColumns: Columns<string, FindingRow> = {
  packageName: { headerText: 'Package', field: 'packageName' },
  version: { headerText: 'Version', field: 'version' },
  severity: { headerText: 'Severity', field: 'severity' },
  cvss: { headerText: 'CVSS', field: 'cvss' },
  identifier: { headerText: 'CVE / advisory', field: 'identifier' },
  summary: { headerText: 'Details', field: 'summary' },
  fixedVersion: { headerText: 'Fixed version', field: 'fixedVersion' },
};

const dependencyColumns: Columns<string, DependencyRow> = {
  name: { headerText: 'Dependency', field: 'name' },
  version: { headerText: 'Version', field: 'version' },
  versionKind: { headerText: 'Version quality', field: 'versionKind' },
  ecosystem: { headerText: 'Ecosystem', field: 'ecosystem' },
  source: { headerText: 'Source', field: 'source' },
};

const licenseColumns: Columns<string, LicenseRow> = {
  packageName: { headerText: 'Package', field: 'packageName' },
  version: { headerText: 'Version', field: 'version' },
  license: { headerText: 'Detected license', field: 'license' },
  policyStatus: { headerText: 'Policy status', field: 'policyStatus' },
  source: { headerText: 'Source', field: 'source' },
};

const chatDependencyColumns: Columns<string, ChatDependencyRow> = {
  packageName: { headerText: 'Package', field: 'packageName' },
  version: { headerText: 'Version', field: 'version' },
  ecosystem: { headerText: 'Ecosystem', field: 'ecosystem' },
  source: { headerText: 'Source', field: 'source' },
};

const chatVulnerabilityColumns: Columns<string, ChatVulnerabilityRow> = {
  packageName: { headerText: 'Package', field: 'packageName' },
  version: { headerText: 'Version', field: 'version' },
  severity: { headerText: 'Severity', field: 'severity' },
  vulnerabilityId: { headerText: 'CVE / advisory', field: 'vulnerabilityId' },
  summary: { headerText: 'Details', field: 'summary' },
  fixedVersion: { headerText: 'Fixed version', field: 'fixedVersion' },
};

const chatLicenseColumns: Columns<string, ChatLicenseRow> = {
  packageName: { headerText: 'Package', field: 'packageName' },
  version: { headerText: 'Version', field: 'version' },
  license: { headerText: 'Detected license', field: 'license' },
  policyStatus: { headerText: 'Policy status', field: 'policyStatus' },
  reason: { headerText: 'Reason', field: 'reason' },
};

function uniqueFindings(report: ScanReport): VulnerabilityFinding[] {
  return (report.vulnerability_research?.packages_checked ?? []).filter(
    (finding) => finding.vulnerability_count > 0,
  );
}

function findingRowsFrom(findings: VulnerabilityFinding[]): FindingRow[] {
  return findings.flatMap((finding, findingIndex) => {
    const advisories = finding.advisory_summaries ?? [];
    if (advisories.length) {
      return advisories.map((advisory, advisoryIndex) => {
        const identifier = advisory.id || advisory.aliases?.[0] || advisory.alternate_ids?.[0] || 'Advisory found';
        const relatedIds = [identifier, ...(advisory.aliases ?? []), ...(advisory.alternate_ids ?? [])].map((item) => item.toUpperCase());
        const nvd = (finding.nvd_details ?? []).find((item) => relatedIds.includes(item.cve_id.toUpperCase()));
        return {
          key: `${finding.package_name}-${finding.version_checked}-${identifier}-${findingIndex}-${advisoryIndex}`,
          packageName: finding.package_name,
          version: finding.version_checked || 'Unknown',
          severity: advisory.severity || nvd?.severity || finding.severity || 'Not provided',
          cvss: nvd?.base_score != null ? String(nvd.base_score) : '—',
          identifier,
          summary: advisory.summary || advisory.details || nvd?.description || 'No description provided by the advisory source.',
          fixedVersion: advisory.fixed_version || 'Not confirmed',
          referenceUrl: advisory.primary_reference || advisory.references?.[0]?.url || '',
        };
      });
    }

    if (finding.nvd_details?.length) {
      return finding.nvd_details.map((detail, detailIndex) => ({
        key: `${finding.package_name}-${finding.version_checked}-${detail.cve_id}-${findingIndex}-${detailIndex}`,
        packageName: finding.package_name,
        version: finding.version_checked || 'Unknown',
        severity: detail.severity || finding.severity || 'Not provided',
        cvss: detail.base_score != null ? String(detail.base_score) : '—',
        identifier: detail.cve_id,
        summary: detail.description || 'No description provided by NVD.',
        fixedVersion: 'Not confirmed',
        referenceUrl: `https://nvd.nist.gov/vuln/detail/${detail.cve_id}`,
      }));
    }

    const identifiers = Array.from(new Set([...finding.cve_ids, ...finding.vulnerability_ids]));
    return (identifiers.length ? identifiers : ['Advisory found']).map((identifier, identifierIndex) => ({
      key: `${finding.package_name}-${finding.version_checked}-${identifier}-${findingIndex}-${identifierIndex}`,
      packageName: finding.package_name,
      version: finding.version_checked || 'Unknown',
      severity: finding.severity || 'Not provided',
      cvss: '—',
      identifier,
      summary: 'The backend returned an identifier without additional advisory details.',
      fixedVersion: 'Not confirmed',
      referenceUrl: identifier.toUpperCase().startsWith('CVE-')
        ? `https://nvd.nist.gov/vuln/detail/${identifier}`
        : identifier !== 'Advisory found'
          ? `https://osv.dev/vulnerability/${identifier}`
          : '',
    }));
  });
}

function recordText(row: Record<string, unknown>, key: string, fallback = '—'): string {
  const value = row[key];
  if (value == null || value === '') return fallback;
  return String(value);
}

function buildChatArtifacts(response: AgentChatResponse): ChatArtifacts | undefined {
  const dependencies = (response.dependencies_discovered_table ?? []).map((row, index) => ({
    key: `dependency-${index}`,
    packageName: recordText(row, 'package'),
    version: recordText(row, 'version'),
    ecosystem: recordText(row, 'ecosystem'),
    source: recordText(row, 'source'),
  }));
  const vulnerabilities = (response.vulnerable_dependencies_table ?? []).map((row, index) => ({
    key: `vulnerability-${index}`,
    packageName: recordText(row, 'package'),
    version: recordText(row, 'version'),
    severity: recordText(row, 'severity', 'Unknown'),
    vulnerabilityId: recordText(row, 'vulnerability_id'),
    summary: recordText(row, 'summary', 'No description provided.'),
    fixedVersion: recordText(row, 'fixed_version', 'Not confirmed'),
  }));
  const licenses = (response.license_compliance_table ?? []).map((row, index) => ({
    key: `license-${index}`,
    packageName: recordText(row, 'package'),
    version: recordText(row, 'version'),
    license: recordText(row, 'detected_license', 'Unknown'),
    policyStatus: recordText(row, 'policy_status', 'Review required'),
    reason: recordText(row, 'reason', 'No explanation provided.'),
  }));
  const fix = response.fix_analysis;
  const fixSummary = fix?.highest_fixed_version
    ? `Recommended fixed version: ${fix.highest_fixed_version}`
    : fix?.fix_status === 'no_fixed'
      ? 'No confirmed fixed version is currently available.'
      : undefined;
  const hasCards = Boolean(response.cards && Object.values(response.cards).some((value) => value != null));
  if (!hasCards && !dependencies.length && !vulnerabilities.length && !licenses.length && !fixSummary) return undefined;
  return { cards: response.cards, dependencies, vulnerabilities, licenses, fixSummary };
}

function ChatArtifactsContent({ artifacts }: { artifacts: ChatArtifacts }) {
  const metrics = [
    ['Dependencies', artifacts.cards?.dependencies_discovered],
    ['Exact versions', artifacts.cards?.exact_versions],
    ['Packages checked', artifacts.cards?.packages_checked],
    ['Unique CVEs', artifacts.cards?.unique_cves_found],
  ].filter((item) => item[1] != null) as Array<[string, number]>;

  return (
    <div className={styles.chatArtifacts}>
      {metrics.length > 0 && (
        <div className={styles.chatArtifactMetrics}>
          {metrics.map(([label, value]) => (
            <Card key={label} primaryText={String(value)} secondaryText={label} visualStyle="overview" responsiveWidth containerStyle={{ width: '100%', maxWidth: 'none' }} />
          ))}
        </div>
      )}
      {artifacts.fixSummary && <ComponentMessage severity="info" message={artifacts.fixSummary} />}
      {artifacts.dependencies.length > 0 && (
        <section className={styles.chatArtifactSection}>
          <h3>Dependencies discovered</h3>
          <div className={styles.chatArtifactTable}>
            <Table aria-label="Agent dependencies discovered" data={artifacts.dependencies} getRowKey={(item) => item.key} columns={chatDependencyColumns} getAccessibleRowHeaders={() => new Set(['packageName'])} width="100%" />
          </div>
        </section>
      )}
      {artifacts.vulnerabilities.length > 0 && (
        <section className={styles.chatArtifactSection}>
          <h3>Vulnerable dependencies</h3>
          <div className={styles.chatArtifactTable}>
            <Table aria-label="Agent vulnerability findings" data={artifacts.vulnerabilities} getRowKey={(item) => item.key} columns={chatVulnerabilityColumns} getAccessibleRowHeaders={() => new Set(['packageName'])} width="100%" />
          </div>
        </section>
      )}
      {artifacts.licenses.length > 0 && (
        <section className={styles.chatArtifactSection}>
          <h3>Open-source license compliance</h3>
          <div className={styles.chatArtifactTable}>
            <Table aria-label="Agent license compliance" data={artifacts.licenses} getRowKey={(item) => item.key} columns={chatLicenseColumns} getAccessibleRowHeaders={() => new Set(['packageName'])} width="100%" />
          </div>
        </section>
      )}
    </div>
  );
}

export function AgentShieldWorkspace() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [source, setSource] = useState<InputSource>('repository');
  const [mode, setMode] = useState<ScanMode>('fast');
  const [repoUrl, setRepoUrl] = useState('');
  const [token, setToken] = useState('');
  const [fileName, setFileName] = useState('');
  const [fileContent, setFileContent] = useState('');
  const [manualText, setManualText] = useState('');
  const [packages, setPackages] = useState<PackageCoordinate[]>([]);
  const [packageName, setPackageName] = useState('');
  const [packageVersion, setPackageVersion] = useState('');
  const [ecosystem, setEcosystem] = useState('PyPI');
  const [scanResponse, setScanResponse] = useState<ScanResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [showAllFindings, setShowAllFindings] = useState(false);
  const [showAllDependencies, setShowAllDependencies] = useState(false);
  const [showAllLicenses, setShowAllLicenses] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [chatInput, setChatInput] = useState('');
  const [chatBusy, setChatBusy] = useState(false);
  const [chatError, setChatError] = useState('');
  const [chatExpanded, setChatExpanded] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      id: 1,
      role: 'assistant',
      text: 'Ask me to scan a GitHub repository or an exact package version. Include PyPI, npm, or Maven when the ecosystem is not obvious.',
    },
  ]);
  const chatMessagesRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    checkHealth()
      .then(() => setBackendOnline(true))
      .catch(() => setBackendOnline(false));
  }, []);

  useEffect(() => {
    chatMessagesRef.current?.scrollTo({ top: chatMessagesRef.current.scrollHeight, behavior: 'smooth' });
  }, [chatMessages, chatBusy]);

  const pendingPackageValid = Boolean(packageName.trim() && packageVersion.trim() && ecosystem);
  const activeModeLabel = mode === 'fast' ? 'Fast' : mode === 'detailed' ? 'Detailed' : 'Developer';
  const canScan =
    !busy &&
    ((source === 'repository' && Boolean(repoUrl.trim())) ||
      (source === 'file' && Boolean(fileName && fileContent)) ||
      (source === 'manual' && Boolean(manualText.trim())) ||
      (source === 'packages' && (packages.length > 0 || pendingPackageValid)));

  function buildScanRequest(): ScanRequest {
    const base: ScanRequest = { mode };
    if (source === 'repository') {
      return { ...base, repo_url: repoUrl.trim(), token: token.trim() || undefined };
    }
    if (source === 'file') {
      return { ...base, file_name: fileName, file_content: fileContent };
    }
    if (source === 'manual') {
      return { ...base, raw_text: manualText };
    }
    const pendingPackage = pendingPackageValid
      ? [{ package_name: packageName.trim(), package_version: packageVersion.trim(), ecosystem }]
      : [];
    return { ...base, packages: [...packages, ...pendingPackage] };
  }

  async function handleFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    setFileContent(await file.text());
    setError('');
  }

  function addPackage() {
    if (!pendingPackageValid) return;
    setPackages((current) => [
      ...current,
      { package_name: packageName.trim(), package_version: packageVersion.trim(), ecosystem },
    ]);
    setPackageName('');
    setPackageVersion('');
  }

  async function handleScan() {
    if (!canScan) return;
    setBusy(true);
    setError('');
    setScanResponse(null);
    try {
      const response = await runScan(buildScanRequest());
      setScanResponse(response);
      setBackendOnline(true);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The scan failed.');
      setBackendOnline(false);
    } finally {
      setBusy(false);
    }
  }

  function buildChatRequest(message: string): AgentChatRequest {
    return {
      message,
      include_debug: false,
    };
  }

  async function handleChatSubmit() {
    const message = chatInput.trim();
    if (!message || chatBusy) return;
    const userMessage: ChatMessage = { id: Date.now(), role: 'user', text: message };
    setChatMessages((current) => [...current, userMessage]);
    setChatInput('');
    setChatError('');
    setChatBusy(true);
    try {
      const response = await askAgentShield(buildChatRequest(message));
      setChatMessages((current) => [
        ...current,
        {
          id: Date.now() + 1,
          role: 'assistant',
          text: response.message || response.llm_response || 'The analysis completed, but no explanation was returned.',
          responseSource: response.response_meta.llm_available ? 'oci' : 'deterministic',
          artifacts: buildChatArtifacts(response),
        },
      ]);
      setBackendOnline(true);
    } catch (requestError) {
      setChatError(requestError instanceof Error ? requestError.message : 'AgentShield could not answer that request.');
      setBackendOnline(false);
    } finally {
      setChatBusy(false);
    }
  }

  function clearChat() {
    setChatMessages([
      {
        id: Date.now(),
        role: 'assistant',
        text: 'Conversation cleared. What would you like AgentShield to analyze?',
      },
    ]);
    setChatError('');
  }

  const report = scanResponse?.json_report;
  const scanSummary = report?.llm_context?.scan_summary;
  const findings = useMemo(() => (report ? uniqueFindings(report) : []), [report]);
  const findingRows = useMemo<FindingRow[]>(
    () => findingRowsFrom(findings),
    [findings],
  );
  const dependencyRows = useMemo<DependencyRow[]>(
    () =>
      (report?.direct_dependencies ?? []).map((dependency, index) => ({
        key: `${dependency.name}-${dependency.version}-${index}`,
        name: dependency.name,
        version: dependency.version || 'Unresolved',
        versionKind: dependency.version_kind,
        ecosystem: dependency.ecosystem || 'Unknown',
        source: dependency.source_type,
      })),
    [report],
  );
  const visibleFindingRows = showAllFindings ? findingRows : findingRows.slice(0, 20);
  const visibleDependencyRows = showAllDependencies ? dependencyRows : dependencyRows.slice(0, 30);
  const licenseRows = useMemo<LicenseRow[]>(
    () =>
      (report?.license_analysis?.findings ?? []).map((finding, index) => ({
        key: `${finding.package_name}-${finding.version}-${index}`,
        packageName: finding.package_name,
        version: finding.version || 'Unresolved',
        license: finding.license_expression,
        policyStatus: finding.policy_status,
        source: finding.source,
      })),
    [report],
  );
  const visibleLicenseRows = showAllLicenses ? licenseRows : licenseRows.slice(0, 30);
  const licenseAnalysis = report?.license_analysis;
  const resultMode = String(report?.mode || mode).toLowerCase();
  const showLicenseResults = resultMode === 'detailed' || resultMode === 'developer';
  const normalizedLicenseStatus = String(licenseAnalysis?.status || '').toLowerCase().replace(/[\s_]+/g, '_');
  const licenseMessageSeverity =
    normalizedLicenseStatus === 'blocked'
      ? 'error'
      : normalizedLicenseStatus === 'review_required'
        ? 'warning'
        : 'confirmation';
  const discoveryMessage =
    report?.result_type === 'discovery_only'
      ? `Dependencies were discovered, but CVE matching was not run because exact package versions were unavailable.${showLicenseResults ? ' License analysis applies only where exact package metadata is available.' : ''}`
      : report?.result_type === 'partial_discovery'
        ? 'CVE matching covered only dependencies with exact versions. Review unresolved dependencies before treating this result as complete.'
        : null;

  return (
    <DataManagementPage
      pageTitle="Agent Shield"
      pageSubtitle="Scan open-source dependencies for vulnerabilities and license risk."
      avatar={{ initials: 'AS' }}
      badge={{
        text: backendOnline === true ? 'Backend connected' : backendOnline === false ? 'Backend offline' : 'Checking backend',
        status: backendOnline === true ? 'success' : backendOnline === false ? 'danger' : 'neutral',
      }}
      displayMode="mixed"
      displayOptions={{ timestamp: false, density: 'compact' }}
      className={styles.page}
    >
      <div className={styles.workspace}>
        {error && <ComponentMessage severity="error" message={error} />}

        <section className={styles.analysisStrip} aria-label="Analysis coverage">
          <div className={styles.analysisCoverage}>
            <span className={styles.analysisLabel}>Analysis coverage</span>
            <div className={styles.analysisBadges}>
              <Badge label="CVE intelligence" variant="dangerSubtle" size="sm" />
              <Badge label="License compliance" variant="warningSubtle" size="sm" />
              <Badge label="Dependency inventory" variant="infoSubtle" size="sm" />
            </div>
          </div>
          <div className={styles.analysisMode}>
            <span>Mode</span>
            <strong>{activeModeLabel}</strong>
          </div>
        </section>

        <div className={styles.contentGrid}>
          <main className={styles.primaryColumn}>
        <Card
          overlineText="Manual scan"
          primaryText="Analyze a project"
          secondaryText="Choose an input source and analysis depth."
          badge={{ text: 'Ready to configure', status: 'info', emphasis: 'subtle' }}
          visualStyle="promoted"
          className={styles.scanCard}
          responsiveWidth
          containerStyle={{ width: '100%', maxWidth: 'none' }}
        >
          <div className={styles.cardBody}>
            <span className={styles.fieldLabel}>Input source</span>
            <div className={styles.sourceSelector} role="tablist" aria-label="Dependency source">
              {sourceOptions.map((option) => (
                <Button
                  key={option.id}
                  label={option.label}
                  chroming={source === option.id ? 'solid' : 'outlined'}
                  onClick={() => {
                    setSource(option.id);
                    setError('');
                  }}
                />
              ))}
            </div>

            <div className={styles.modeControl}>
            <Select
              label="Analysis mode"
              labelEdge="top"
              data={modeOptions}
              value={mode}
              itemText="label"
              onChange={(value) => setMode(value as ScanMode)}
              width="100%"
            />
            <div className={styles.modeGuide} aria-label="Analysis mode guide">
              <span className={mode === 'fast' ? styles.modeGuideActive : ''}>Fast <small>CVE essentials</small></span>
              <span className={mode === 'detailed' ? styles.modeGuideActive : ''}>Detailed <small>Licenses + metadata</small></span>
              <span className={mode === 'developer' ? styles.modeGuideActive : ''}>Developer <small>Engineering priorities</small></span>
            </div>
            </div>

            {source === 'repository' && (
              <div className={styles.repositoryFields}>
                <InputText
                  label="GitHub repository URL"
                  labelEdge="top"
                  value={repoUrl}
                  placeholder="https://github.com/owner/repository"
                  onChange={setRepoUrl}
                  required
                />
                <div className={styles.advancedToggle}>
                  <Button
                    label={showAdvanced ? 'Hide advanced options' : 'Advanced options'}
                    chroming="borderless"
                    onClick={() => setShowAdvanced((value) => !value)}
                  />
                </div>
                {showAdvanced && (
                  <div className={styles.advancedPanel}>
                  <InputPassword
                    label="GitHub PAT override"
                    labelEdge="top"
                    assistiveText="Leave blank to use GITHUB_TOKEN from the backend .env."
                    value={token}
                    onChange={setToken}
                    hasRevealToggle="always"
                    autoComplete="off"
                  />
                  </div>
                )}
              </div>
            )}

            {source === 'file' && (
              <div className={styles.dropZone}>
                <input
                  ref={fileInputRef}
                  className={styles.fileInput}
                  type="file"
                  accept=".txt,.json,.lock,.toml,.xml,.yml,.yaml,text/plain,application/json"
                  aria-label="Choose dependency file"
                  onChange={handleFileChange}
                />
                <div>
                  <strong>{fileName || 'Choose a supported dependency file'}</strong>
                  <p>Requirements, npm, Poetry, Pipenv, Maven, pyproject, and Conda files are supported.</p>
                </div>
                <Button
                  label={fileName ? 'Choose another file' : 'Choose file'}
                  chroming="outlined"
                  onClick={() => fileInputRef.current?.click()}
                />
              </div>
            )}

            {source === 'manual' && (
              <TextArea
                label="Dependency list"
                labelEdge="top"
                value={manualText}
                rows={7}
                resize="vertical"
                placeholder={'requests==2.31.0\nfastapi==0.104.1'}
                onChange={setManualText}
                width="100%"
              />
            )}

            {source === 'packages' && (
              <div className={styles.packageBuilder}>
                <div className={styles.packageFields}>
                  <InputText label="Package" labelEdge="top" value={packageName} onChange={setPackageName} />
                  <InputText label="Exact version" labelEdge="top" value={packageVersion} onChange={setPackageVersion} />
                  <Select
                    label="Ecosystem"
                    labelEdge="top"
                    data={ecosystemOptions}
                    value={ecosystem}
                    itemText="label"
                    onChange={setEcosystem}
                    width="100%"
                  />
                  <Button label="Add package" chroming="outlined" disabled={!pendingPackageValid} onClick={addPackage} />
                </div>
                {packages.length > 0 && (
                  <div className={styles.packageList}>
                    {packages.map((item, index) => (
                      <div key={`${item.package_name}-${item.package_version}-${index}`}>
                        <span>{item.package_name} {item.package_version} · {item.ecosystem}</span>
                        <Button
                          label="Remove"
                          chroming="borderless"
                          onClick={() => setPackages((current) => current.filter((_, itemIndex) => itemIndex !== index))}
                        />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className={styles.actions}>
              <Button
                label={busy ? 'Analyzing…' : 'Analyze dependencies'}
                chroming="callToAction"
                disabled={!canScan}
                onClick={handleScan}
              />
            </div>
          </div>
        </Card>

        {!report ? (
          <section aria-label="AgentShield capabilities">
            <Card overlineText="Coverage" primaryText="One scan, three views" secondaryText="Results appear here after analysis." badge={{ text: 'Unified analysis', status: 'success', emphasis: 'subtle' }} visualStyle="overview" responsiveWidth containerStyle={{ width: '100%', maxWidth: 'none' }}>
              <div className={styles.capabilityStrip}>
                <div>
                  <span>Security</span>
                  <strong>CVE detection</strong>
                  <p>Known vulnerabilities for exact package versions.</p>
                </div>
                <div>
                  <span>Compliance</span>
                  <strong>License compliance</strong>
                  <p>Detected licenses checked against your policy.</p>
                </div>
                <div>
                  <span>Inventory</span>
                  <strong>Dependency insight</strong>
                  <p>Normalized packages, versions, and source details.</p>
                </div>
              </div>
            </Card>
          </section>
        ) : (
          <section className={styles.results} aria-label="Analysis results">
            <ComponentMessage severity="confirmation" message={scanResponse?.summary || 'Analysis completed.'} />
            {discoveryMessage && <ComponentMessage severity="warning" message={discoveryMessage} />}
            <div className={styles.summaryGrid}>
              <Card className={styles.metricInventory} badge={{ text: 'Inventory', status: 'info', emphasis: 'subtle' }} visualStyle="overview" primaryText={String(report.total_packages)} secondaryText="Dependencies discovered" responsiveWidth containerStyle={{ width: '100%', maxWidth: 'none' }} />
              <Card className={styles.metricExact} badge={{ text: 'Coverage', status: 'success', emphasis: 'subtle' }} visualStyle="overview" primaryText={String(scanSummary?.exact_versions ?? 0)} secondaryText="Exact versions" responsiveWidth containerStyle={{ width: '100%', maxWidth: 'none' }} />
              <Card className={styles.metricChecked} badge={{ text: 'OSV / NVD', status: 'warning', emphasis: 'subtle' }} visualStyle="overview" primaryText={String(report.vulnerability_research?.packages_checked_count ?? 0)} secondaryText="Packages checked" responsiveWidth containerStyle={{ width: '100%', maxWidth: 'none' }} />
              <Card className={styles.metricRisk} badge={{ text: 'Security risk', status: report.vulnerability_research?.cves_found.length ? 'danger' : 'success', emphasis: 'subtle' }} visualStyle="overview" primaryText={String(report.vulnerability_research?.cves_found.length ?? 0)} secondaryText="Unique CVEs found" responsiveWidth containerStyle={{ width: '100%', maxWidth: 'none' }} />
            </div>

            <Card className={styles.inventoryResultCard} badge={{ text: 'Inventory', status: 'info', emphasis: 'subtle' }} overlineText="Inventory" primaryText="Discovered dependencies" secondaryText={`${dependencyRows.length} normalized dependency records`} responsiveWidth containerStyle={{ width: '100%', maxWidth: 'none' }}>
              <div className={styles.tableWrap}>
                {dependencyRows.length > 30 && (
                  <div className={styles.tableMeta}>
                    <span>Showing {visibleDependencyRows.length} of {dependencyRows.length} dependencies</span>
                    <Button label={showAllDependencies ? 'Show first 30' : 'Show all'} chroming="borderless" onClick={() => setShowAllDependencies((value) => !value)} />
                  </div>
                )}
                <Table
                  aria-label="Discovered dependencies"
                  data={visibleDependencyRows}
                  getRowKey={(item) => item.key}
                  columns={dependencyColumns}
                  getAccessibleRowHeaders={() => new Set(['name'])}
                  noData={<EmptyState primaryText="No dependencies returned" secondaryText="Check the selected source and backend warnings." displayOptions={{ layout: 'other' }} />}
                  width="100%"
                />
              </div>
            </Card>

            <Card className={styles.securityResultCard} badge={{ text: findingRows.length ? 'Action required' : 'No confirmed findings', status: findingRows.length ? 'danger' : 'success', emphasis: 'subtle' }} overlineText="Security results" primaryText="Vulnerable dependencies" secondaryText={`${findingRows.length} vulnerability findings`} responsiveWidth containerStyle={{ width: '100%', maxWidth: 'none' }}>
              <div className={styles.tableWrap}>
                {findingRows.length > 20 && (
                  <div className={styles.tableMeta}>
                    <span>Showing {visibleFindingRows.length} of {findingRows.length} findings</span>
                    <Button label={showAllFindings ? 'Show first 20' : 'Show all'} chroming="borderless" onClick={() => setShowAllFindings((value) => !value)} />
                  </div>
                )}
                <Table
                  aria-label="Vulnerability findings"
                  data={visibleFindingRows}
                  getRowKey={(item) => item.key}
                  columns={findingColumns}
                  getAccessibleRowHeaders={() => new Set(['packageName'])}
                  noData={
                    <EmptyState
                      primaryText={report.result_type === 'discovery_only' ? 'CVE matching not performed' : 'No known vulnerabilities confirmed'}
                      secondaryText="Review warnings for unresolved or non-exact versions."
                      displayOptions={{ layout: 'other' }}
                    />
                  }
                  width="100%"
                />
                {visibleFindingRows.some((finding) => finding.referenceUrl) && (
                  <div className={styles.evidenceLinks}>
                    <strong>Advisory evidence</strong>
                    <div>
                      {visibleFindingRows.filter((finding) => finding.referenceUrl).map((finding) => (
                        <a key={`${finding.key}-evidence`} href={finding.referenceUrl} target="_blank" rel="noreferrer">
                          {finding.identifier}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </Card>

            {showLicenseResults && (
            <Card className={styles.complianceResultCard} badge={{ text: licenseAnalysis?.status || 'Not available', status: normalizedLicenseStatus === 'blocked' ? 'danger' : normalizedLicenseStatus === 'review_required' ? 'warning' : 'success', emphasis: 'subtle' }} overlineText="Compliance results" primaryText="Open-source license compliance" secondaryText={licenseAnalysis ? `${licenseAnalysis.summary.detected} of ${licenseAnalysis.summary.total} dependency licenses detected` : 'No license analysis returned'} responsiveWidth containerStyle={{ width: '100%', maxWidth: 'none' }}>
              <div className={styles.cardBody}>
                {licenseAnalysis ? (
                  <>
                    <ComponentMessage
                      severity={licenseMessageSeverity}
                      message={`Compliance status: ${licenseAnalysis.status} · ${licenseAnalysis.summary.allowed} allowed · ${licenseAnalysis.summary.review} review · ${licenseAnalysis.summary.denied} denied · ${licenseAnalysis.summary.unknown} unknown`}
                    />
                    <div className={styles.tableWrapFlush}>
                      {licenseRows.length > 30 && (
                        <div className={styles.tableMeta}>
                          <span>Showing {visibleLicenseRows.length} of {licenseRows.length} license findings</span>
                          <Button label={showAllLicenses ? 'Show first 30' : 'Show all'} chroming="borderless" onClick={() => setShowAllLicenses((value) => !value)} />
                        </div>
                      )}
                      <Table
                        aria-label="License compliance findings"
                        data={visibleLicenseRows}
                        getRowKey={(item) => item.key}
                        columns={licenseColumns}
                        getAccessibleRowHeaders={() => new Set(['packageName'])}
                        noData={<EmptyState primaryText="No license findings" secondaryText="No dependencies were available for license analysis." displayOptions={{ layout: 'other' }} />}
                        width="100%"
                      />
                    </div>
                    <p className={styles.disclaimer}>{licenseAnalysis.policy.disclaimer}</p>
                  </>
                ) : (
                  <ComponentMessage severity="warning" message="The backend did not return a license analysis result." />
                )}
              </div>
            </Card>
            )}

          </section>
        )}
          </main>

          <aside className={styles.chatColumn} aria-label="Ask AgentShield">
            <Card
              overlineText="Agent interaction"
              primaryText="Ask AgentShield"
              secondaryText="Open the dedicated conversational security workspace."
              badge={{ text: 'OCI-assisted', status: 'info', emphasis: 'subtle' }}
              visualStyle="overview"
              className={styles.agentCard}
              responsiveWidth
              containerStyle={{ width: '100%', maxWidth: 'none' }}
            >
              <div className={styles.chatLauncher}>
                <p>Use Fast, Detailed or Developer mode, attach dependency files, and review structured result tables.</p>
                <Button label="Open Agent Chat" chroming="callToAction" onClick={() => { window.location.hash = '#/chat'; }} />
              </div>
            </Card>
          </aside>
        </div>
      </div>
    </DataManagementPage>
  );
}
