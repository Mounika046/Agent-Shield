from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

try:
    from app.schemas import PackageCoordinate, ScanMode
except ModuleNotFoundError:
    from schemas import PackageCoordinate, ScanMode

class Dependency(BaseModel):
    name: str
    version: str
    language: str  # e.g., "python", "javascript", "java"
    source: Optional[str] = None  # e.g., pip, poetry, conda, npm, maven
    ecosystem: Optional[str] = None  # e.g., PyPI, npm, Maven, Conda

class Vulnerability(BaseModel):
    package: str
    version: str
    severity: str  # e.g., "high", "medium", "low"
    description: str
    cve: Optional[str] = None
    language: str

class TransitiveDependency(BaseModel):
    name: str
    version: str
    parent: str  # the direct dependency that brings this
    language: str

class AnalysisState(BaseModel):
    repo_url: str
    token: Optional[str] = None
    language: str = ""
    dependency_files: Dict[str, List[str]] = {}  # {"lockfiles": [...], "manifests": [...]}
    has_lockfile: bool = False
    dependencies: List[Dependency] = []
    vulnerabilities: List[Vulnerability] = []
    transitive_deps: List[TransitiveDependency] = []
    report: Dict[str, Any] = {}

class AnalysisRequest(BaseModel):
    repo_url: str
    token: Optional[str] = None

class AnalysisResponse(BaseModel):
    json_report: Dict[str, Any]
    summary: str


class GithubScanRequest(BaseModel):
    repo_url: str
    token: Optional[str] = None


class GithubScanResponse(BaseModel):
    json_report: Dict[str, Any]
    summary: str


class WebScrapeRequest(BaseModel):
    repo_url: Optional[str] = None
    start_url: Optional[str] = None  # Backward-compatible alias for repo_url
    token: Optional[str] = None
    github_scan_report: Optional[Dict[str, Any]] = None


class WebScrapeResponse(BaseModel):
    json_report: Dict[str, Any]
    summary: str


class UnifiedScanRequest(BaseModel):
    raw_text: Optional[str] = None
    repo_url: Optional[str] = None
    start_url: Optional[str] = None  # Backward-compatible alias for repo_url
    token: Optional[str] = None
    packages: List[PackageCoordinate] = Field(default_factory=list)
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    ecosystem: Optional[str] = None
    file_name: Optional[str] = None
    file_content: Optional[str] = None
    mode: Optional[ScanMode] = None


class UnifiedScanResponse(BaseModel):
    json_report: Dict[str, Any]
    summary: str


class AgentChatRequest(BaseModel):
    message: str
    repo_url: Optional[str] = None
    start_url: Optional[str] = None
    token: Optional[str] = None
    packages: List[PackageCoordinate] = Field(default_factory=list)
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    ecosystem: Optional[str] = None
    file_name: Optional[str] = None
    file_content: Optional[str] = None
    mode: Optional[ScanMode] = None
    include_debug: bool = False


class AgentChatResponse(BaseModel):
    status: str
    message: Optional[str] = None
    llm_response: Optional[str] = None
    backend_called: bool
    backend_payload: Optional[Dict[str, Any]] = None
    mode: Optional[str] = None
    mode_source: Optional[str] = None
    input_type: str
    response_type: Optional[str] = None
    cards: Optional[Dict[str, Any]] = None
    dependencies_discovered_table: Optional[List[Dict[str, Any]]] = None
    vulnerable_dependencies_table: Optional[List[Dict[str, Any]]] = None
    license_compliance_table: Optional[List[Dict[str, Any]]] = None
    dependency_graphs: Optional[Dict[str, Any]] = None
    fix_analysis: Optional[Dict[str, Any]] = None
    license_sources: Optional[List[Dict[str, Any]]] = None
    scan_result: Optional[Dict[str, Any]] = None
    response_meta: Dict[str, Any] = Field(default_factory=dict)
    controller_prompt_loaded: bool = False
