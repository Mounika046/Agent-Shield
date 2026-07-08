export type ScanMode = 'fast' | 'detailed' | 'developer';

export interface PackageCoordinate {
  package_name: string;
  package_version: string;
  ecosystem: string;
}

export interface ScanRequest {
  repo_url?: string;
  token?: string;
  packages?: PackageCoordinate[];
  file_name?: string;
  file_content?: string;
  raw_text?: string;
  mode: ScanMode;
}

export interface NormalizedDependency {
  name: string;
  version: string;
  version_kind: 'exact' | 'range' | 'unknown';
  ecosystem: string;
  source_type: string;
  relationship?: string | null;
  file_path?: string | null;
}

export interface VulnerabilityFinding {
  package_name: string;
  version_checked: string;
  vulnerability_count: number;
  cve_ids: string[];
  vulnerability_ids: string[];
  severity?: string | null;
  match_confidence: string;
  relationship?: string | null;
  warnings: string[];
  nvd_details?: CVEEnrichment[];
  advisory_summaries?: VulnerabilityAdvisory[];
}

export interface AdvisoryReference {
  type?: string;
  label?: string;
  url: string;
}

export interface VulnerabilityAdvisory {
  id?: string | null;
  aliases?: string[];
  alternate_ids?: string[];
  summary?: string | null;
  details?: string | null;
  severity?: string | null;
  fixed_version?: string | null;
  references?: AdvisoryReference[];
  primary_reference?: string | null;
}

export interface CVEEnrichment {
  cve_id: string;
  status?: string | null;
  published?: string | null;
  last_modified?: string | null;
  severity?: string | null;
  base_score?: number | null;
  description?: string | null;
}

export interface LicenseFinding {
  package_name: string;
  version: string;
  ecosystem: string;
  license_expression: string;
  license_ids: string[];
  source: string;
  policy_status: 'Allowed' | 'Review required' | 'Denied' | 'allowed' | 'review' | 'denied';
  reason: string;
  source_links?: AdvisoryReference[];
}

export interface LicenseAnalysis {
  status: 'passed' | 'Review required' | 'review required' | 'review_required' | 'blocked' | 'no_dependencies';
  summary: {
    total: number;
    detected: number;
    allowed: number;
    review: number;
    denied: number;
    unknown: number;
  };
  findings: LicenseFinding[];
  policy: {
    allowed: string[];
    denied: string[];
    review: string[];
    disclaimer: string;
  };
  providers: Record<string, string>;
}

export interface ScanReport {
  repo_url?: string | null;
  language: string;
  input_type: string;
  result_type?: 'vulnerability_scan' | 'partial_discovery' | 'discovery_only';
  analysis_blocked_reason?: string | null;
  scan_mode?: string;
  mode?: string;
  total_packages: number;
  direct_dependencies?: NormalizedDependency[];
  vulnerability_research?: {
    packages_checked_count: number;
    packages_checked: VulnerabilityFinding[];
    cves_found: string[];
    skipped_packages: Array<Record<string, unknown>>;
    warnings: string[];
    errors: string[];
  };
  metadata_enrichment?: Array<{
    provider: string;
    status: string;
    data: Record<string, unknown>;
    errors: string[];
  }>;
  dependency_graphs?: Record<string, DependencyGraphEntry>;
  recommendations?: string[];
  warnings?: string[];
  warning_details?: Array<Record<string, unknown>>;
  license_analysis?: LicenseAnalysis;
  llm_context?: {
    scan_summary?: {
      total_dependencies?: number;
      exact_versions?: number;
      range_versions?: number;
      unknown_versions?: number;
      packages_checked_for_vulnerabilities?: number;
      packages_skipped_for_exact_matching?: number;
      cves_found?: number;
    };
  };
}

export interface ScanResponse {
  json_report: ScanReport;
  summary: string;
}

export interface AgentChatRequest {
  message: string;
  conversation_id?: string;
  repo_url?: string;
  token?: string;
  packages?: PackageCoordinate[];
  package_name?: string;
  package_version?: string;
  ecosystem?: string;
  file_name?: string;
  file_content?: string;
  mode?: ScanMode;
  include_debug?: boolean;
}

export interface AgentChatResponse {
  status: string;
  message?: string;
  llm_response?: string;
  backend_called: boolean;
  mode?: string | null;
  mode_source?: string | null;
  input_type: string;
  response_type?: string;
  cards?: AgentSummaryCards;
  dependencies_discovered_table?: Array<Record<string, unknown>>;
  vulnerable_dependencies_table?: Array<Record<string, unknown>>;
  license_compliance_table?: Array<Record<string, unknown>>;
  dependency_graphs?: Record<string, DependencyGraphEntry>;
  table_data?: Array<Record<string, unknown>>;
  table_columns?: Array<{ key: string; label: string }>;
  fix_analysis?: {
    fix_status?: string;
    highest_fixed_version?: string | null;
    all_fixed_versions?: string[];
  };
  license_sources?: Array<Record<string, unknown>>;
  scan_result?: ScanResponse | null;
  response_meta: {
    llm_available?: boolean;
    llm_input_stage?: boolean;
    llm_output_stage?: boolean;
    result_type?: string;
  };
}

export interface AgentSummaryCards {
  dependencies_discovered?: number | null;
  exact_versions?: number | null;
  packages_checked?: number | null;
  unique_cves_found?: number | null;
}

export interface DependencyGraphEntry {
  package: string;
  version: string;
  ecosystem?: string;
  dependency_count?: number;
  truncated?: boolean;
  source?: string;
  dependencies: Array<{ name: string; version: string }>;
}

export interface HealthResponse {
  status: string;
  service: string;
}

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL as string | undefined;
const API_BASE_URL = (configuredBaseUrl || '/api').replace(/\/$/, '');

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...init?.headers,
      },
    });
  } catch {
    throw new Error('Cannot reach the AgentShield backend. Start it on port 8070 and try again.');
  }

  const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
  if (!response.ok) {
    throw new Error(payload?.detail || `Backend request failed with status ${response.status}.`);
  }
  return payload as T;
}

export function checkHealth(): Promise<HealthResponse> {
  return requestJson<HealthResponse>('/health');
}

export function runScan(request: ScanRequest): Promise<ScanResponse> {
  return requestJson<ScanResponse>('/scan', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

export function askAgentShield(request: AgentChatRequest): Promise<AgentChatResponse> {
  return requestJson<AgentChatResponse>('/agent/chat', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}
