from typing import Any, Dict, List, Optional

try:
    from app.models.models import Dependency
    from app.schemas import DependencyInventory
    from app.services.github.acquisition import (
        acquire_github_dependency_inventory,
        derive_source_and_ecosystem,
        detect_has_lockfile,
    )
    from app.services.reporting import build_github_scan_report, github_report_to_api_dict
    from app.utils.repo_utils import collect_file_paths, detect_language_from_structure, find_dependency_files, get_repo_structure
except ModuleNotFoundError:
    from models.models import Dependency
    from schemas import DependencyInventory
    from services.github.acquisition import (
        acquire_github_dependency_inventory,
        derive_source_and_ecosystem,
        detect_has_lockfile,
    )
    from services.reporting import build_github_scan_report, github_report_to_api_dict
    from utils.repo_utils import collect_file_paths, detect_language_from_structure, find_dependency_files, get_repo_structure


def detect_repo_language(repo_url: str, token: Optional[str]) -> Dict[str, Any]:
    structure = get_repo_structure(repo_url, token)
    all_file_paths = collect_file_paths(structure)
    language = detect_language_from_structure(all_file_paths)
    dependency_files = find_dependency_files(all_file_paths)
    return {
        "language": language,
        "dependency_files": dependency_files,
        "has_lockfile": detect_has_lockfile(language, dependency_files),
    }


def _derive_source_and_ecosystem(filename: str, fallback_language: str) -> tuple[str, str]:
    return derive_source_and_ecosystem(filename, fallback_language)


def extract_dependencies(
    repo_url: str,
    token: Optional[str],
    language: str,
    dependency_files: Dict[str, List[str]],
) -> List[Dependency]:
    """Compatibility wrapper for callers expecting legacy Dependency objects."""
    inventory = acquire_github_dependency_inventory(repo_url, token)
    return [
        Dependency(
            name=dep.name,
            version=dep.version,
            language=dep.language,
            source=dep.source,
            ecosystem=dep.ecosystem,
        )
        for dep in inventory.dependencies
    ]


def build_report(
    repo_url: str,
    language: str,
    dependency_files: Dict[str, List[str]],
    has_lockfile: bool,
    dependencies: List[Dependency],
) -> Dict[str, Any]:
    inventory = DependencyInventory(
        repo_url=repo_url,
        language=language,
        dependency_files=dependency_files,
        has_lockfile=has_lockfile,
        dependencies=[
            {
                "name": dep.name,
                "version": dep.version,
                "language": dep.language,
                "source": dep.source or "",
                "ecosystem": dep.ecosystem or "",
            }
            for dep in dependencies
        ],
    )
    return github_report_to_api_dict(build_github_scan_report(inventory))


def run_github_scan(repo_url: str, token: Optional[str] = None) -> Dict[str, Any]:
    inventory = acquire_github_dependency_inventory(repo_url, token)
    typed_report = build_github_scan_report(inventory)
    report = github_report_to_api_dict(typed_report)

    if report.get("status") == "incomplete":
        summary = f"{report['message']} {report['suggestion']}"
    else:
        summary = (
            f"Analysis complete for {report.get('language', 'unknown')} repo. "
            f"Found {report.get('summary', {}).get('total_deps', 0)} dependencies."
        )

    return {"json_report": report, "summary": summary}
