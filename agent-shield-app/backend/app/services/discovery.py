from collections import OrderedDict
from typing import Dict, List, Optional

try:
    from app.schemas import DependencyInventory, ScanResultType, VersionKind
except ModuleNotFoundError:
    from schemas import DependencyInventory, ScanResultType, VersionKind


def _dedupe_names(values: List[str], limit: int = 10) -> List[str]:
    seen = OrderedDict()
    for value in values:
        if value and value not in seen:
            seen[value] = True
        if len(seen) >= limit:
            break
    return list(seen.keys())


def classify_inventory_result(
    inventory: DependencyInventory,
    *,
    blocked_reason: Optional[str] = None,
    discovery_source: Optional[str] = None,
) -> DependencyInventory:
    exact_count = len(inventory.exact_dependencies)
    unresolved = inventory.unresolved_dependencies
    missing_version = [dep for dep in unresolved if dep.version_kind == VersionKind.UNKNOWN and not dep.version]
    if not inventory.dependencies:
        return inventory

    if unresolved:
        sample_names = _dedupe_names([dep.name for dep in unresolved])
        detail = {
            "code": "UNRESOLVED_DEPENDENCIES",
            "message": "Some discovered dependencies do not have exact versions, so vulnerability matching is incomplete.",
            "unresolved_count": len(unresolved),
            "exact_count": exact_count,
            "missing_version_count": len(missing_version),
            "sample_packages": sample_names,
        }
        if discovery_source:
            detail["source"] = discovery_source
        inventory.warning_details.append(detail)

    if exact_count == 0:
        inventory.result_type = ScanResultType.DISCOVERY_ONLY
        inventory.analysis_blocked_reason = blocked_reason or "no_exact_versions"
        inventory.warnings.append(
            "Dependencies were discovered, but no exact versions were available for reliable vulnerability matching."
        )
        inventory.warning_details.append(
            {
                "code": "DISCOVERY_ONLY",
                "message": "Dependency discovery succeeded, but vulnerability analysis was blocked because no exact versions were available.",
                "dependency_count": len(inventory.dependencies),
                "missing_version_count": len(missing_version),
                "source": discovery_source,
            }
        )
        return inventory

    if unresolved:
        inventory.result_type = ScanResultType.PARTIAL_DISCOVERY
        inventory.analysis_blocked_reason = blocked_reason if exact_count == 0 else None

    return inventory
