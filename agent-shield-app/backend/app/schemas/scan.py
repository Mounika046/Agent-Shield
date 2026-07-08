from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class InputType(str, Enum):
    GITHUB_REPO = "github_repo"
    PACKAGE = "package"
    DEPENDENCY_FILE = "dependency_file"
    UNKNOWN = "unknown"


class ScanMode(str, Enum):
    GITHUB_DEPENDENCIES = "github_dependencies"
    WEB_ENRICHMENT = "web_enrichment"
    FAST = "fast"
    DETAILED = "detailed"
    DEVELOPER = "developer"
    FULL = "full"


class DependencySourceType(str, Enum):
    GITHUB_FILE = "github_file"
    GITHUB_SBOM = "github_sbom"
    OSV_SCANNER = "osv_scanner"
    DIRECT_PACKAGE = "direct_package"
    UPLOADED_FILE = "uploaded_file"
    UNKNOWN = "unknown"


class VersionKind(str, Enum):
    EXACT = "exact"
    RANGE = "range"
    UNKNOWN = "unknown"


class ScanResultType(str, Enum):
    VULNERABILITY_SCAN = "vulnerability_scan"
    PARTIAL_DISCOVERY = "partial_discovery"
    DISCOVERY_ONLY = "discovery_only"


class PackageCoordinate(BaseModel):
    package_name: str
    package_version: str
    ecosystem: str


class NormalizedDependency(BaseModel):
    name: str
    version: str = ""
    version_kind: VersionKind = VersionKind.UNKNOWN
    version_specifier: Optional[str] = None
    language: str = ""
    source: str = ""
    ecosystem: str = ""
    source_type: DependencySourceType = DependencySourceType.GITHUB_FILE
    file_path: Optional[str] = None
    package_url: Optional[str] = None
    relationship: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DependencyInventory(BaseModel):
    repo_url: Optional[str] = None
    language: str = "unknown"
    input_type: InputType = InputType.GITHUB_REPO
    result_type: ScanResultType = ScanResultType.VULNERABILITY_SCAN
    analysis_blocked_reason: Optional[str] = None
    dependency_files: Dict[str, List[str]] = Field(default_factory=lambda: {"lockfiles": [], "manifests": []})
    has_lockfile: bool = False
    dependencies: List[NormalizedDependency] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    warning_details: List[Dict[str, Any]] = Field(default_factory=list)

    @property
    def package_version_map(self) -> Dict[str, str]:
        return {dep.name: dep.version for dep in self.dependencies if dep.name}

    @property
    def package_version_kind_map(self) -> Dict[str, str]:
        return {dep.name: dep.version_kind.value for dep in self.dependencies if dep.name}

    @property
    def package_metadata_map(self) -> Dict[str, Dict[str, str]]:
        return {
            dep.name: {
                "source": dep.source,
                "ecosystem": dep.ecosystem,
                "language": dep.language,
                "source_type": dep.source_type.value,
                "file_path": dep.file_path or "",
                "package_url": dep.package_url or "",
                "relationship": dep.relationship or "",
                "version_kind": dep.version_kind.value,
                "version_specifier": dep.version_specifier or "",
            }
            for dep in self.dependencies
            if dep.name
        }

    @property
    def exact_dependencies(self) -> List[NormalizedDependency]:
        return [dep for dep in self.dependencies if dep.version_kind == VersionKind.EXACT]

    @property
    def unresolved_dependencies(self) -> List[NormalizedDependency]:
        return [dep for dep in self.dependencies if dep.version_kind != VersionKind.EXACT]


class CVEEnrichment(BaseModel):
    cve_id: str
    status: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    severity: Optional[str] = None
    base_score: Optional[float] = None
    description: Optional[str] = None


class VulnerabilityFinding(BaseModel):
    package_name: str
    version_checked: str
    vulnerability_count: int = 0
    cve_ids: List[str] = Field(default_factory=list)
    vulnerability_ids: List[str] = Field(default_factory=list)
    ecosystem_used: str = ""
    source: Optional[str] = None
    nvd_details: List[CVEEnrichment] = Field(default_factory=list)
    version_kind: VersionKind = VersionKind.EXACT
    match_confidence: str = "exact"
    warnings: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    relationship: Optional[str] = None
    source_type: Optional[str] = None
    file_path: Optional[str] = None
    advisory_summaries: List[Dict[str, Any]] = Field(default_factory=list)


class VulnerabilityResearch(BaseModel):
    ecosystem: str = ""
    packages_checked_count: int = 0
    packages_checked: List[VulnerabilityFinding] = Field(default_factory=list)
    cves_found: List[str] = Field(default_factory=list)
    nvd_details: List[CVEEnrichment] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    skipped_packages: List[Dict[str, Any]] = Field(default_factory=list)


class MetadataEnrichment(BaseModel):
    provider: str
    status: str = "not_implemented"
    data: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)


class ScanRequestContext(BaseModel):
    raw_text: Optional[str] = None
    repo_url: Optional[str] = None
    token: Optional[str] = None
    packages: List[PackageCoordinate] = Field(default_factory=list)
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    ecosystem: Optional[str] = None
    file_name: Optional[str] = None
    file_content: Optional[str] = None
    mode: Optional[ScanMode] = None
    input_type: InputType = InputType.UNKNOWN
    mode_source: str = "inferred"


class ScanReport(BaseModel):
    repo_url: Optional[str] = None
    language: str = "unknown"
    input_type: InputType = InputType.GITHUB_REPO
    scan_mode: ScanMode
    dependency_files: Dict[str, List[str]] = Field(default_factory=lambda: {"lockfiles": [], "manifests": []})
    direct_dependencies: List[NormalizedDependency] = Field(default_factory=list)
    package_version_map: Dict[str, str] = Field(default_factory=dict)
    package_metadata_map: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    total_packages: int = 0
    vulnerability_research: Optional[VulnerabilityResearch] = None
    metadata_enrichment: List[MetadataEnrichment] = Field(default_factory=list)
    oci_analysis: Dict[str, Any] = Field(default_factory=dict)
    route: Dict[str, Any] = Field(default_factory=dict)
    status: Optional[str] = None
    warning_code: Optional[str] = None
    error_code: Optional[str] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
