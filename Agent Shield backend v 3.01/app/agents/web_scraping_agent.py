from typing import Any, Dict, List

from langgraph.graph import END, StateGraph

try:
    from app.graph import WebScanState
    from app.schemas import VulnerabilityResearch
    from app.services.enrichment import run_oci_analysis
    from app.services.reporting import build_web_scan_report, web_report_to_api_dict
    from app.services.vulnerability import enrich_vulnerabilities
except ModuleNotFoundError:
    from graph import WebScanState
    from schemas import VulnerabilityResearch
    from services.enrichment import run_oci_analysis
    from services.reporting import build_web_scan_report, web_report_to_api_dict
    from services.vulnerability import enrich_vulnerabilities


def normalize_github_report_node(state: WebScanState) -> WebScanState:
    incoming_report = state.get("github_scan_report", {})
    if "json_report" in incoming_report and isinstance(incoming_report["json_report"], dict):
        state["github_scan_report"] = incoming_report["json_report"]
    else:
        state["github_scan_report"] = incoming_report
    return state


def build_package_version_map_node(state: WebScanState) -> WebScanState:
    report = state.get("github_scan_report", {})
    dependencies: List[Dict[str, Any]] = report.get("direct_dependencies", [])

    package_version_map: Dict[str, str] = {}
    package_metadata_map: Dict[str, Dict[str, str]] = {}
    for dep in dependencies:
        name = str(dep.get("name", "")).strip()
        version = str(dep.get("version", "")).strip()
        if name:
            package_version_map[name] = version
            package_metadata_map[name] = {
                "source": str(dep.get("source", "")).strip(),
                "ecosystem": str(dep.get("ecosystem", "")).strip(),
                "language": str(dep.get("language", "")).strip(),
                "source_type": str(dep.get("source_type", "")).strip(),
                "file_path": str(dep.get("file_path", "")).strip(),
            }

    state["package_version_map"] = package_version_map
    state["package_metadata_map"] = package_metadata_map
    return state


def run_vulnerability_research_node(state: WebScanState) -> WebScanState:
    state["vulnerability_research"] = enrich_vulnerabilities(
        github_report=state.get("github_scan_report", {}),
        package_version_map=state.get("package_version_map", {}),
        package_metadata_map=state.get("package_metadata_map", {}),
    )
    return state


def run_oci_analysis_node(state: WebScanState) -> WebScanState:
    vulnerability_research = state.get("vulnerability_research")
    if not isinstance(vulnerability_research, VulnerabilityResearch):
        vulnerability_research = VulnerabilityResearch()
    state["oci_analysis"] = run_oci_analysis(
        package_version_map=state.get("package_version_map", {}),
        vulnerability_research=vulnerability_research,
    )
    return state


def build_web_report_node(state: WebScanState) -> WebScanState:
    vulnerability_research = state.get("vulnerability_research")
    if not isinstance(vulnerability_research, VulnerabilityResearch):
        vulnerability_research = VulnerabilityResearch()
    typed_report = build_web_scan_report(
        repo_url=state.get("repo_url", ""),
        github_report=state.get("github_scan_report", {}),
        package_version_map=state.get("package_version_map", {}),
        package_metadata_map=state.get("package_metadata_map", {}),
        vulnerability_research=vulnerability_research,
        oci_analysis=state.get("oci_analysis", {}),
    )
    state["report"] = web_report_to_api_dict(typed_report)
    return state


workflow = StateGraph(WebScanState)
workflow.add_node("normalize_github_report", normalize_github_report_node)
workflow.add_node("build_package_version_map", build_package_version_map_node)
workflow.add_node("run_vulnerability_research", run_vulnerability_research_node)
workflow.add_node("run_oci_analysis", run_oci_analysis_node)
workflow.add_node("build_web_report", build_web_report_node)

workflow.set_entry_point("normalize_github_report")
workflow.add_edge("normalize_github_report", "build_package_version_map")
workflow.add_edge("build_package_version_map", "run_vulnerability_research")
workflow.add_edge("run_vulnerability_research", "run_oci_analysis")
workflow.add_edge("run_oci_analysis", "build_web_report")
workflow.add_edge("build_web_report", END)

web_scraping_agent = workflow.compile()


def run_web_scrape(repo_url: str, github_scan_report: Dict[str, Any]) -> Dict[str, Any]:
    initial_state: WebScanState = {
        "repo_url": repo_url,
        "github_scan_report": github_scan_report,
        "package_version_map": {},
        "package_metadata_map": {},
        "vulnerability_research": VulnerabilityResearch(),
        "oci_analysis": {},
        "report": {},
    }

    result = web_scraping_agent.invoke(initial_state)
    report = result["report"]
    summary = (
        f"Web scan complete. Extracted {report['total_packages']} packages from manifest/lock files. "
        "Dictionary name: package_version_map."
    )
    return {"json_report": report, "summary": summary}
