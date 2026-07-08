from typing import Any, Dict


class WebScanState(Dict[str, Any]):
    repo_url: str
    github_scan_report: Dict[str, Any]
    package_version_map: Dict[str, str]
    package_metadata_map: Dict[str, Dict[str, str]]
    vulnerability_research: Any
    oci_analysis: Dict[str, Any]
    report: Dict[str, Any]
