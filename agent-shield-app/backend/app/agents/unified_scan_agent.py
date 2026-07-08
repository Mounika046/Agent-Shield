import logging
from typing import Any, Dict, Optional

from langgraph.graph import END, StateGraph

try:
    from app.schemas import DependencyInventory, InputType, PackageCoordinate, ScanMode, ScanRequestContext, ScanResultType, VulnerabilityResearch
    from app.services.dependency_graph import fetch_dependency_graphs_for_inventory
    from app.services.dependency_inputs import acquire_direct_package_inventory, acquire_file_dependency_inventory
    from app.services.enrichment import enrich_github_repo, enrich_with_deps_dev
    from app.services.github.acquisition import acquire_github_dependency_inventory
    from app.services.input import infer_scan_mode, normalize_request_context
    from app.services.reporting import build_license_analysis, build_llm_context
    from app.services.vulnerability import enrich_vulnerabilities
except ModuleNotFoundError:
    from schemas import DependencyInventory, InputType, PackageCoordinate, ScanMode, ScanRequestContext, ScanResultType, VulnerabilityResearch
    from services.dependency_graph import fetch_dependency_graphs_for_inventory
    from services.dependency_inputs import acquire_direct_package_inventory, acquire_file_dependency_inventory
    from services.enrichment import enrich_github_repo, enrich_with_deps_dev
    from services.github.acquisition import acquire_github_dependency_inventory
    from services.input import infer_scan_mode, normalize_request_context
    from services.reporting import build_license_analysis, build_llm_context
    from services.vulnerability import enrich_vulnerabilities


class UnifiedScanState(Dict[str, Any]):
    context: ScanRequestContext
    route: Dict[str, Any]
    inventory: DependencyInventory
    vulnerability_research: VulnerabilityResearch
    metadata_enrichment: list
    dependency_graphs: Dict[str, Any]
    report: Dict[str, Any]
    summary: str


def classify_request_node(state: UnifiedScanState) -> UnifiedScanState:
    context = state["context"]
    mode = infer_scan_mode(context)
    context.mode = mode
    state["context"] = context
    state["route"] = {
        "input_type": context.input_type.value,
        "mode": mode.value,
        "mode_source": context.mode_source,
    }
    return state


def route_by_input(state: UnifiedScanState) -> str:
    input_type = state["context"].input_type
    if input_type == InputType.GITHUB_REPO:
        return "acquire_repo_dependencies"
    if input_type == InputType.PACKAGE:
        return "acquire_package_dependency"
    if input_type == InputType.DEPENDENCY_FILE:
        return "acquire_file_dependencies"
    return "format_output"


def acquire_repo_dependencies_node(state: UnifiedScanState) -> UnifiedScanState:
    context = state["context"]
    state["inventory"] = acquire_github_dependency_inventory(context.repo_url or "", context.token)
    return state


def acquire_package_dependency_node(state: UnifiedScanState) -> UnifiedScanState:
    context = state["context"]
    state["inventory"] = acquire_direct_package_inventory(
        package_name=context.package_name or "",
        package_version=context.package_version or "",
        ecosystem=context.ecosystem,
        packages=context.packages,
    )
    return state


def acquire_file_dependencies_node(state: UnifiedScanState) -> UnifiedScanState:
    context = state["context"]
    state["inventory"] = acquire_file_dependency_inventory(
        file_name=context.file_name or "dependencies.txt",
        file_content=context.file_content or "",
    )
    return state


def query_vulnerabilities_node(state: UnifiedScanState) -> UnifiedScanState:
    inventory = state.get("inventory") or DependencyInventory()
    github_report = {
        "language": inventory.language,
        "dependency_files": inventory.dependency_files,
        "direct_dependencies": [dep.model_dump() for dep in inventory.dependencies],
    }
    state["vulnerability_research"] = enrich_vulnerabilities(
        github_report=github_report,
        package_version_map=inventory.package_version_map,
        package_metadata_map=inventory.package_metadata_map,
        dependencies=[dep.model_dump() for dep in inventory.dependencies],
    )
    return state


def route_after_inventory(state: UnifiedScanState) -> str:
    inventory = state.get("inventory") or DependencyInventory()
    if inventory.result_type == ScanResultType.DISCOVERY_ONLY:
        return "format_output"
    return "query_vulnerabilities"


def route_by_mode_after_vulns(state: UnifiedScanState) -> str:
    mode = state["context"].mode
    if mode in {ScanMode.DETAILED, ScanMode.DEVELOPER, ScanMode.FULL}:
        return "enrich_deps_dev"
    return "format_output"


def enrich_deps_dev_node(state: UnifiedScanState) -> UnifiedScanState:
    inventory = state.get("inventory") or DependencyInventory()
    state.setdefault("metadata_enrichment", [])
    state["metadata_enrichment"].append(enrich_with_deps_dev(inventory, max_packages=None))
    return state


def route_after_deps_dev(state: UnifiedScanState) -> str:
    if state["context"].mode in {ScanMode.DEVELOPER, ScanMode.FULL}:
        return "fetch_dependency_graphs"
    return "format_output"


def fetch_dependency_graphs_node(state: UnifiedScanState) -> UnifiedScanState:
    inventory = state.get("inventory") or DependencyInventory()
    vulnerability_research = state.get("vulnerability_research") or VulnerabilityResearch()
    state["dependency_graphs"] = fetch_dependency_graphs_for_inventory(
        inventory=inventory,
        vulnerability_research=vulnerability_research,
    )
    return state


def route_after_dependency_graphs(state: UnifiedScanState) -> str:
    context = state["context"]
    if context.repo_url:
        return "enrich_github_api"
    return "format_output"


def enrich_github_api_node(state: UnifiedScanState) -> UnifiedScanState:
    context = state["context"]
    state.setdefault("metadata_enrichment", [])
    if context.repo_url:
        state["metadata_enrichment"].append(enrich_github_repo(context.repo_url, context.token))
    return state


def format_output_node(state: UnifiedScanState) -> UnifiedScanState:
    context = state["context"]
    inventory = state.get("inventory") or DependencyInventory(input_type=context.input_type)
    vulnerability_research = state.get("vulnerability_research") or VulnerabilityResearch()
    metadata_enrichment = state.get("metadata_enrichment", [])
    mode = context.mode or ScanMode.FAST

    report: Dict[str, Any] = {
        "input_type": context.input_type.value,
        "mode": mode.value,
        "result_type": inventory.result_type.value,
        "analysis_blocked_reason": inventory.analysis_blocked_reason,
        "route": state.get("route", {}),
        "repo_url": inventory.repo_url or context.repo_url,
        "language": inventory.language,
        "dependency_files": inventory.dependency_files,
        "total_packages": len(inventory.dependencies),
        "direct_dependencies": [dep.model_dump() for dep in inventory.dependencies],
        "package_version_map": inventory.package_version_map,
        "package_version_kind_map": inventory.package_version_kind_map,
        "vulnerability_research": vulnerability_research.model_dump(),
        "warnings": inventory.warnings,
        "warning_details": inventory.warning_details,
        "errors": inventory.errors,
    }

    if mode in {ScanMode.DETAILED, ScanMode.DEVELOPER, ScanMode.FULL}:
        report["package_metadata_map"] = inventory.package_metadata_map
        report["metadata_enrichment"] = [item.model_dump() for item in metadata_enrichment]
        report["license_analysis"] = build_license_analysis(
            inventory=inventory,
            metadata_enrichment=metadata_enrichment,
        )
        logger.info("License analysis count: %s", len(report["license_analysis"].get("findings", [])))

    if mode in {ScanMode.DEVELOPER, ScanMode.FULL}:
        report["provider_plan"] = {
            "github_sbom": "attempted for repo input",
            "custom_parser": "fallback for repo/file input",
            "osv_scanner": "provider boundary present; external binary not configured",
            "deps_dev": "enabled",
            "github_api": "enabled for repo input",
        }
        report["dependency_graphs"] = state.get("dependency_graphs", {})

    report["llm_context"] = build_llm_context(
        report=report,
        inventory=inventory,
        vulnerability_research=vulnerability_research,
        metadata_enrichment=metadata_enrichment,
    )

    state["report"] = report
    if inventory.result_type == ScanResultType.DISCOVERY_ONLY:
        state["summary"] = (
            f"Discovery-only result for {context.input_type.value}. "
            f"Found {len(inventory.dependencies)} dependencies, but no exact versions were available for vulnerability matching."
        )
    elif inventory.result_type == ScanResultType.PARTIAL_DISCOVERY:
        state["summary"] = (
            f"Partial vulnerability scan complete for {context.input_type.value}. "
            f"Found {len(inventory.dependencies)} dependencies, scanned {len(inventory.exact_dependencies)} exact versions, "
            f"and identified {len(vulnerability_research.cves_found)} CVEs."
        )
    else:
        state["summary"] = (
            f"{mode.value.title()} scan complete for {context.input_type.value}. "
            f"Found {len(inventory.dependencies)} dependencies and "
            f"{len(vulnerability_research.cves_found)} CVEs."
        )
    return state


workflow = StateGraph(UnifiedScanState)
workflow.add_node("classify_request", classify_request_node)
workflow.add_node("acquire_repo_dependencies", acquire_repo_dependencies_node)
workflow.add_node("acquire_package_dependency", acquire_package_dependency_node)
workflow.add_node("acquire_file_dependencies", acquire_file_dependencies_node)
workflow.add_node("query_vulnerabilities", query_vulnerabilities_node)
workflow.add_node("enrich_deps_dev", enrich_deps_dev_node)
workflow.add_node("fetch_dependency_graphs", fetch_dependency_graphs_node)
workflow.add_node("enrich_github_api", enrich_github_api_node)
workflow.add_node("format_output", format_output_node)

workflow.set_entry_point("classify_request")
workflow.add_conditional_edges(
    "classify_request",
    route_by_input,
    {
        "acquire_repo_dependencies": "acquire_repo_dependencies",
        "acquire_package_dependency": "acquire_package_dependency",
        "acquire_file_dependencies": "acquire_file_dependencies",
        "format_output": "format_output",
    },
)
workflow.add_conditional_edges(
    "acquire_repo_dependencies",
    route_after_inventory,
    {"query_vulnerabilities": "query_vulnerabilities", "format_output": "format_output"},
)
workflow.add_conditional_edges(
    "acquire_package_dependency",
    route_after_inventory,
    {"query_vulnerabilities": "query_vulnerabilities", "format_output": "format_output"},
)
workflow.add_conditional_edges(
    "acquire_file_dependencies",
    route_after_inventory,
    {"query_vulnerabilities": "query_vulnerabilities", "format_output": "format_output"},
)
workflow.add_conditional_edges(
    "query_vulnerabilities",
    route_by_mode_after_vulns,
    {"enrich_deps_dev": "enrich_deps_dev", "format_output": "format_output"},
)
workflow.add_conditional_edges(
    "enrich_deps_dev",
    route_after_deps_dev,
    {"fetch_dependency_graphs": "fetch_dependency_graphs", "format_output": "format_output"},
)
workflow.add_conditional_edges(
    "fetch_dependency_graphs",
    route_after_dependency_graphs,
    {"enrich_github_api": "enrich_github_api", "format_output": "format_output"},
)
workflow.add_edge("enrich_github_api", "format_output")
workflow.add_edge("format_output", END)

unified_scan_agent = workflow.compile()


def run_unified_scan(
    raw_text: Optional[str] = None,
    repo_url: Optional[str] = None,
    token: Optional[str] = None,
    packages: Optional[list[PackageCoordinate]] = None,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    file_name: Optional[str] = None,
    file_content: Optional[str] = None,
    mode: Optional[ScanMode] = None,
) -> Dict[str, Any]:
    context = normalize_request_context(
        raw_text=raw_text,
        repo_url=repo_url,
        token=token,
        packages=packages,
        package_name=package_name,
        package_version=package_version,
        ecosystem=ecosystem,
        file_name=file_name,
        file_content=file_content,
        mode=mode,
    )
    initial_state: UnifiedScanState = {
        "context": context,
        "explicit_mode": mode is not None,
        "route": {},
        "inventory": DependencyInventory(input_type=context.input_type),
        "vulnerability_research": VulnerabilityResearch(),
        "metadata_enrichment": [],
        "dependency_graphs": {},
        "report": {},
        "summary": "",
    }
    result = unified_scan_agent.invoke(initial_state)
    return {"json_report": result["report"], "summary": result["summary"]}
logger = logging.getLogger(__name__)
