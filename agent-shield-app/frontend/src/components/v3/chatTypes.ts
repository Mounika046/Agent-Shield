import type { ScanMode } from '../../api/agentShieldApi.js';

export type TableColumn = {
  key: string;
  label: string;
};

export type SummaryCards = {
  dependencies_discovered?: number | null;
  exact_versions?: number | null;
  packages_checked?: number | null;
  unique_cves_found?: number | null;
};

export type DependencyGraphEntry = {
  package: string;
  version: string;
  ecosystem?: string;
  dependency_count?: number;
  truncated?: boolean;
  source?: string;
  dependencies: Array<{ name: string; version: string }>;
};

export type ChatMessage = {
  id: string;
  role: 'user' | 'assistant' | 'system';
  text: string;
  displayedText?: string;
  status?: 'pending' | 'typing' | 'done' | 'error';
  cards?: SummaryCards;
  dependenciesDiscoveredTable?: Array<Record<string, unknown>>;
  vulnerableDependenciesTable?: Array<Record<string, unknown>>;
  licenseComplianceTable?: Array<Record<string, unknown>>;
  dependencyGraphs?: Record<string, DependencyGraphEntry>;
  tableData?: Array<Record<string, unknown>>;
  tableColumns?: TableColumn[];
  mode?: ScanMode | string;
  fileName?: string;
  responseType?: string;
  error?: boolean;
};

export type AttachedFile = {
  name: string;
  content: string;
};
