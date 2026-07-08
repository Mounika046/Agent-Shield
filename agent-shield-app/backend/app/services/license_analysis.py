import re
from typing import Any, Dict, Iterable, List, Optional, Set

try:
    from app.config import get_config
    from app.schemas import DependencyInventory, MetadataEnrichment
except ModuleNotFoundError:
    from config import get_config
    from schemas import DependencyInventory, MetadataEnrichment


_SPDX_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
_EXPRESSION_WORDS = {"AND", "OR", "WITH", "NONE", "NOASSERTION", "UNKNOWN"}


def _csv_set(value: str) -> Set[str]:
    return {item.strip().upper() for item in value.split(",") if item.strip()}


def _license_values(raw_value: Any) -> List[str]:
    if isinstance(raw_value, str):
        return [raw_value.strip()] if raw_value.strip() else []
    if isinstance(raw_value, list):
        values: List[str] = []
        for item in raw_value:
            values.extend(_license_values(item))
        return values
    if isinstance(raw_value, dict):
        for key in ("license", "name", "id", "spdx", "expression"):
            if raw_value.get(key):
                return _license_values(raw_value[key])
    return []


def _license_ids(expressions: Iterable[str]) -> List[str]:
    ids: List[str] = []
    for expression in expressions:
        for token in _SPDX_TOKEN.findall(expression):
            normalized = token.strip().upper()
            if normalized not in _EXPRESSION_WORDS and normalized not in ids:
                ids.append(normalized)
    return ids


def _policy_status(
    license_ids: List[str],
    denied: Set[str],
    review: Set[str],
    allowed: Set[str],
) -> tuple[str, str]:
    if not license_ids:
        return "review", "No license metadata was available; manual review is required."
    denied_hits = [item for item in license_ids if item in denied]
    if denied_hits:
        return "denied", f"Denied by policy: {', '.join(denied_hits)}."
    review_hits = [item for item in license_ids if item in review or item.startswith("LICENSEREF-")]
    if review_hits:
        return "review", f"Manual review required: {', '.join(review_hits)}."
    unclassified = [item for item in license_ids if item not in allowed]
    if unclassified:
        return "review", f"License is not classified by policy: {', '.join(unclassified)}."
    return "allowed", "All detected licenses are on the configured allow list."


def _deps_dev_licenses(metadata: Optional[MetadataEnrichment]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    if not metadata or not isinstance(metadata.data, dict):
        return results
    for package in metadata.data.get("packages", []):
        if not isinstance(package, dict):
            continue
        name = str(package.get("name", "")).strip().lower()
        version = str(package.get("version", "")).strip().lower()
        if name:
            value = {
                "licenses": _license_values(package.get("licenses", [])),
                "metadata_version": str(package.get("version", "")),
                "version_source": str(package.get("version_source", "exact_dependency")),
            }
            results[f"{name}@{version}"] = value
            results.setdefault(name, value)
    return results


def build_license_analysis(
    inventory: DependencyInventory,
    deps_dev_metadata: Optional[MetadataEnrichment] = None,
) -> Dict[str, Any]:
    config = get_config()
    denied = _csv_set(config.license_denied)
    allowed = _csv_set(config.license_allowed)
    review = _csv_set(config.license_review)
    deps_dev = _deps_dev_licenses(deps_dev_metadata)
    findings: List[Dict[str, Any]] = []

    for dependency in inventory.dependencies:
        metadata = dependency.metadata if isinstance(dependency.metadata, dict) else {}
        expressions: List[str] = []
        source = "unknown"
        for key in ("license_concluded", "license_declared", "license_info_from_files"):
            values = [value for value in _license_values(metadata.get(key)) if value.upper() != "NOASSERTION"]
            if values:
                expressions = values
                source = "github_sbom"
                break

        if not expressions:
            key = f"{dependency.name.strip().lower()}@{dependency.version.strip().lower()}"
            metadata_result = deps_dev.get(key) or deps_dev.get(dependency.name.strip().lower()) or {}
            expressions = metadata_result.get("licenses", [])
            if expressions:
                source = "deps.dev"
        else:
            metadata_result = {}

        ids = _license_ids(expressions)
        policy_status, reason = _policy_status(ids, denied, review, allowed)
        findings.append(
            {
                "package_name": dependency.name,
                "version": dependency.version,
                "ecosystem": dependency.ecosystem,
                "license_expression": " OR ".join(expressions) if expressions else "UNKNOWN",
                "license_ids": ids,
                "source": source,
                "metadata_version": metadata_result.get("metadata_version") if source == "deps.dev" else dependency.version,
                "version_source": metadata_result.get("version_source") if source == "deps.dev" else "exact_dependency",
                "policy_status": policy_status,
                "reason": reason,
            }
        )

    counts = {
        "total": len(findings),
        "detected": sum(1 for item in findings if item["license_ids"]),
        "allowed": sum(1 for item in findings if item["policy_status"] == "allowed"),
        "review": sum(1 for item in findings if item["policy_status"] == "review"),
        "denied": sum(1 for item in findings if item["policy_status"] == "denied"),
        "unknown": sum(1 for item in findings if not item["license_ids"]),
    }
    overall_status = (
        "no_dependencies"
        if not findings
        else "blocked"
        if counts["denied"]
        else "review_required"
        if counts["review"]
        else "passed"
    )
    return {
        "status": overall_status,
        "summary": counts,
        "findings": findings,
        "policy": {
            "allowed": sorted(allowed),
            "denied": sorted(denied),
            "review": sorted(review),
            "disclaimer": "Engineering policy signal only; obtain legal review for licensing decisions.",
        },
        "providers": {
            "github_sbom": "used when SPDX license fields are available",
            "deps_dev": deps_dev_metadata.status if deps_dev_metadata else "not_available",
        },
    }
