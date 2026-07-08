from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from packaging.version import InvalidVersion, Version

try:
    from app.schemas import DependencyInventory, MetadataEnrichment, ScanMode, ScanReport, VulnerabilityResearch
except ModuleNotFoundError:
    from schemas import DependencyInventory, MetadataEnrichment, ScanMode, ScanReport, VulnerabilityResearch


MAX_LLM_ITEMS = 10
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1}
FAST_DEPENDENCY_LIST_LIMIT = 15
TOP_VULN_LIMIT = 5


def _count_label(count: int, singular: str, plural: Optional[str] = None) -> str:
    suffix = plural or f"{singular}s"
    return f"{count} {singular if count == 1 else suffix}"


def _dependency_files(inventory: DependencyInventory) -> Dict[str, list[str]]:
    return {
        "lockfiles": inventory.dependency_files.get("lockfiles", []),
        "manifests": inventory.dependency_files.get("manifests", []),
    }


def build_github_scan_report(inventory: DependencyInventory) -> ScanReport:
    dependency_files = _dependency_files(inventory)
    recommendations = [
        "Update vulnerable packages to latest secure versions.",
        "Use dependency scanning tools regularly.",
    ]

    if not inventory.has_lockfile and inventory.language != "unknown":
        if dependency_files["manifests"]:
            return ScanReport(
                repo_url=inventory.repo_url,
                language=inventory.language,
                input_type=inventory.input_type,
                scan_mode=ScanMode.GITHUB_DEPENDENCIES,
                dependency_files=dependency_files,
                direct_dependencies=inventory.dependencies,
                status="warning",
                warning_code="LOCKFILE_MISSING",
                message=(
                    "No lockfile found in the repository. "
                    "Exact dependency versions cannot be determined, but dependencies were extracted from manifest files."
                ),
                suggestion=(
                    "Add a lockfile such as poetry.lock, Pipfile.lock, or package-lock.json "
                    "to improve version accuracy and re-run the analysis."
                ),
                summary={"total_deps": len(inventory.dependencies)},
                recommendations=recommendations,
            )

        return ScanReport(
            repo_url=inventory.repo_url,
            language=inventory.language,
            input_type=inventory.input_type,
            scan_mode=ScanMode.GITHUB_DEPENDENCIES,
            dependency_files=dependency_files,
            status="incomplete",
            error_code="LOCKFILE_MISSING",
            message="No lockfile found in the repository. Exact dependency versions cannot be determined.",
            suggestion="Add a lockfile such as poetry.lock, Pipfile.lock, or package-lock.json and re-run the analysis.",
        )

    return ScanReport(
        repo_url=inventory.repo_url,
        language=inventory.language,
        input_type=inventory.input_type,
        scan_mode=ScanMode.GITHUB_DEPENDENCIES,
        dependency_files=dependency_files,
        direct_dependencies=inventory.dependencies,
        summary={"total_deps": len(inventory.dependencies)},
        recommendations=recommendations,
    )


def github_report_to_api_dict(report: ScanReport) -> Dict[str, Any]:
    data = report.model_dump(exclude_none=True)
    data.pop("scan_mode", None)
    data.pop("input_type", None)
    data.pop("package_version_map", None)
    data.pop("package_metadata_map", None)
    data.pop("total_packages", None)
    data.pop("vulnerability_research", None)
    data.pop("metadata_enrichment", None)
    data.pop("oci_analysis", None)
    return data


def build_web_scan_report(
    repo_url: str,
    github_report: Dict[str, Any],
    package_version_map: Dict[str, str],
    package_metadata_map: Dict[str, Dict[str, str]],
    vulnerability_research: VulnerabilityResearch,
    oci_analysis: Dict[str, Any],
) -> ScanReport:
    dependency_files = github_report.get("dependency_files", {"lockfiles": [], "manifests": []})
    return ScanReport(
        repo_url=repo_url,
        language=str(github_report.get("language", "unknown")),
        scan_mode=ScanMode.WEB_ENRICHMENT,
        dependency_files=dependency_files,
        package_version_map=package_version_map,
        package_metadata_map=package_metadata_map,
        total_packages=len(package_version_map),
        vulnerability_research=vulnerability_research,
        oci_analysis=oci_analysis,
    )


def web_report_to_api_dict(report: ScanReport) -> Dict[str, Any]:
    return {
        "repo_url": report.repo_url,
        "dependency_files": report.dependency_files,
        "package_version_map": report.package_version_map,
        "package_metadata_map": report.package_metadata_map,
        "package_version_kind_map": {
            name: metadata.get("version_kind", "")
            for name, metadata in report.package_metadata_map.items()
        },
        "total_packages": report.total_packages,
        "vulnerability_research": report.vulnerability_research.model_dump() if report.vulnerability_research else {},
        "oci_analysis": report.oci_analysis,
    }


def _dedupe_limited(items: List[Any], limit: int = MAX_LLM_ITEMS) -> List[Any]:
    seen = set()
    result = []
    for item in items:
        key = repr(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
        if len(result) >= limit:
            break
    return result


def _warning_summary(warning_details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counter = Counter(str(item.get("code", "WARNING")) for item in warning_details)
    examples: Dict[str, Dict[str, Any]] = {}
    for item in warning_details:
        code = str(item.get("code", "WARNING"))
        examples.setdefault(
            code,
            {
                "code": code,
                "count": counter[code],
                "message": item.get("message", ""),
                "example_package": item.get("package"),
                "reason": item.get("reason"),
            },
        )
    return list(examples.values())[:MAX_LLM_ITEMS]


def _metadata_facts(metadata_enrichment: List[MetadataEnrichment]) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []
    for item in metadata_enrichment:
        if item.provider == "deps.dev":
            packages = item.data.get("packages", []) if isinstance(item.data, dict) else []
            skipped_count = item.data.get("skipped_count", 0) if isinstance(item.data, dict) else 0
            facts.append(
                {
                    "provider": "deps.dev",
                    "status": item.status,
                    "packages_enriched": len(packages),
                    "packages_skipped": skipped_count,
                    "packages_with_links": sum(1 for pkg in packages if _normalized_links(pkg.get("links"))),
                    "packages_with_license_data": sum(1 for pkg in packages if _license_names(pkg.get("licenses"))),
                    "examples": [
                        {
                            "name": pkg.get("name"),
                            "version": pkg.get("version"),
                            "licenses": pkg.get("licenses", [])[:3],
                            "advisory_count": len(pkg.get("advisory_keys", [])),
                            "links": _normalized_links(pkg.get("links"))[:2],
                        }
                        for pkg in packages[:MAX_LLM_ITEMS]
                    ],
                }
            )
        elif item.provider == "github_api":
            facts.append(
                {
                    "provider": "github_api",
                    "status": item.status,
                    "repo": {
                        "full_name": item.data.get("full_name"),
                        "description": item.data.get("description"),
                        "default_branch": item.data.get("default_branch"),
                        "stars": item.data.get("stars"),
                        "forks": item.data.get("forks"),
                        "open_issues_count": item.data.get("open_issues_count"),
                        "updated_at": item.data.get("updated_at"),
                        "pushed_at": item.data.get("pushed_at"),
                        "language": item.data.get("language"),
                    },
                }
            )
        elif item.status not in {"planned", "not_implemented"}:
            facts.append({"provider": item.provider, "status": item.status})
    return facts[:MAX_LLM_ITEMS]


def _discovery_sources(inventory: DependencyInventory) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[str]] = {}
    for dep in inventory.dependencies:
        if dep.version_kind.value == "exact":
            continue
        key = dep.file_path or dep.source or dep.source_type.value
        grouped.setdefault(key, [])
        if dep.name and dep.name not in grouped[key]:
            grouped[key].append(dep.name)

    return [
        {
            "source": source,
            "packages": packages[:MAX_LLM_ITEMS],
            "package_count": len(packages),
        }
        for source, packages in list(grouped.items())[:MAX_LLM_ITEMS]
    ]


def _dependency_preview(dependencies: List[Any], limit: int = FAST_DEPENDENCY_LIST_LIMIT) -> Dict[str, Any]:
    preview = []
    for dep in dependencies[:limit]:
        label = dep.name
        if dep.version:
            version_text = dep.version if dep.version.startswith((">", "<", "~", "!", "=")) else f"=={dep.version}"
            label = f"{label}{version_text}"
        preview.append(label)
    return {
        "count": len(dependencies),
        "can_list_all": len(dependencies) <= limit,
        "preview": preview,
    }


def _provider_source_summary(report: Dict[str, Any], dependencies: List[Any]) -> Dict[str, Any]:
    source_types = [dep.source_type.value for dep in dependencies if getattr(dep, "source_type", None)]
    warning_details = list(report.get("warning_details", []) or [])
    if any(item.get("code") == "GITHUB_SBOM_FALLBACK" for item in warning_details):
        return {
            "source": "parser_fallback",
            "label": "parser fallback",
            "details": "GitHub SBOM was unavailable or not parseable, so file parser fallback was used.",
        }
    if "github_sbom" in source_types:
        return {
            "source": "github_sbom",
            "label": "GitHub SBOM",
            "details": "Dependencies were acquired from GitHub SBOM.",
        }
    if "github_file" in source_types:
        return {
            "source": "github_file",
            "label": "repository dependency files",
            "details": "Dependencies were acquired from repository dependency files.",
        }
    return {
        "source": "unknown",
        "label": "available dependency source",
        "details": "",
    }


def _severity_value(value: Any) -> int:
    if not isinstance(value, str):
        return 0
    return SEVERITY_RANK.get(value.strip().lower(), 0)


def _relationship_label(raw_value: Any) -> str:
    if not isinstance(raw_value, str) or not raw_value.strip():
        return "unknown"
    lowered = raw_value.strip().lower()
    if lowered in {"direct", "direct_dependency"}:
        return "direct"
    if lowered in {"transitive", "indirect", "transitive_dependency"}:
        return "transitive"
    return lowered


def _recommendation_for_finding(finding: Dict[str, Any]) -> str:
    if finding.get("match_confidence") == "exact":
        return "Upgrade this package to a non-vulnerable version and re-run the scan to confirm the advisory no longer matches."
    return "Resolve the exact version first, then re-run vulnerability matching before making a final risk call."


def _summarize_advisories(item: Any) -> List[Dict[str, Any]]:
    advisories = []
    for advisory in item.advisory_summaries[:3]:
        advisories.append(
            {
                "id": advisory.get("id"),
                "aliases": advisory.get("aliases", [])[:5],
                "severity": advisory.get("severity"),
                "summary": advisory.get("summary"),
                "details": advisory.get("details"),
                "fixed_version": advisory.get("fixed_version"),
                "references": list(advisory.get("references") or [])[:3],
                "primary_reference": advisory.get("primary_reference"),
            }
        )
    if item.nvd_details:
        for nvd in item.nvd_details[:3]:
            advisories.append(
                {
                    "id": nvd.cve_id,
                    "aliases": [nvd.cve_id],
                    "severity": nvd.severity,
                    "summary": nvd.description,
                    "details": None,
                    "base_score": nvd.base_score,
                }
            )
    return _dedupe_limited(advisories, 4)


def _finding_priority(item: Any) -> tuple[int, int, int]:
    relationship = _relationship_label(item.relationship)
    relationship_rank = 2 if relationship == "direct" else 1 if relationship == "transitive" else 0
    severity_rank = _severity_value(item.severity)
    confidence_rank = 2 if item.match_confidence == "exact" else 1
    return (severity_rank, confidence_rank, relationship_rank)


def _safe_version_sort_key(value: str) -> tuple[int, Any]:
    text = str(value or "").strip()
    if not text:
        return (0, "")
    try:
        return (1, Version(text))
    except InvalidVersion:
        return (0, text)


def _unique_fixed_versions(values: List[Any]) -> List[str]:
    cleaned = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return sorted(cleaned, key=_safe_version_sort_key)


def _developer_vulnerability_priority(entry: Dict[str, Any]) -> tuple[int, int, int, int]:
    severity_rank = _severity_value(entry.get("severity"))
    confidence_rank = 2 if entry.get("match_confidence") == "exact" else 1
    fix_rank = 1 if entry.get("fixed_version") else 0
    direct_rank = 1 if entry.get("relationship") == "direct" else 0
    return (severity_rank, confidence_rank, fix_rank, direct_rank)


def _top_vulnerability_rows(sorted_findings: List[Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in sorted_findings:
        advisories = _summarize_advisories(item) or []
        if advisories:
            for advisory in advisories:
                summary = str(advisory.get("summary") or advisory.get("details") or "").strip()
                rows.append(
                    {
                        "package": item.package_name,
                        "version": item.version_checked,
                        "severity": advisory.get("severity") or item.severity or "unknown",
                        "vulnerability_id": advisory.get("id") or next(iter(advisory.get("aliases") or []), None),
                        "summary": summary,
                        "fixed_version": advisory.get("fixed_version"),
                        "references": _dedupe_limited(list(advisory.get("references") or []), 3),
                        "match_confidence": item.match_confidence,
                        "relationship": _relationship_label(item.relationship),
                    }
                )
        else:
            identifiers = list(item.cve_ids or []) + list(item.vulnerability_ids or [])
            for identifier in identifiers[:1]:
                rows.append(
                    {
                        "package": item.package_name,
                        "version": item.version_checked,
                        "severity": item.severity or "unknown",
                        "vulnerability_id": identifier,
                        "summary": "",
                        "fixed_version": None,
                        "references": [],
                        "match_confidence": item.match_confidence,
                        "relationship": _relationship_label(item.relationship),
                    }
                )

    deduped: List[Dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (str(row.get("package") or ""), str(row.get("version") or ""), str(row.get("vulnerability_id") or ""))
        if key in seen or not key[2]:
            continue
        seen.add(key)
        deduped.append(row)

    ranked = sorted(
        deduped,
        key=lambda item: (
            _developer_vulnerability_priority(item),
            _safe_version_sort_key(item.get("fixed_version") or ""),
        ),
        reverse=True,
    )
    return [
        {
            "package": item.get("package"),
            "version": item.get("version"),
            "severity": item.get("severity"),
            "vulnerability_id": item.get("vulnerability_id"),
            "summary": item.get("summary"),
            "fixed_version": item.get("fixed_version"),
            "references": item.get("references", [])[:3],
        }
        for item in ranked[:TOP_VULN_LIMIT]
    ]


def _group_top_vulnerabilities(top_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: List[Dict[str, Any]] = []
    index_by_package: Dict[tuple[str, str], int] = {}
    for row in top_rows:
        key = (str(row.get("package") or ""), str(row.get("version") or ""))
        if key not in index_by_package:
            index_by_package[key] = len(grouped)
            grouped.append(
                {
                    "package": row.get("package"),
                    "version": row.get("version"),
                    "severity": row.get("severity"),
                    "vulnerabilities": [],
                }
            )
        bucket = grouped[index_by_package[key]]
        bucket["vulnerabilities"].append(
            {
                "id": row.get("vulnerability_id"),
                "summary": row.get("summary"),
                "fixed_version": row.get("fixed_version"),
                "references": row.get("references", [])[:3],
            }
        )
        if _severity_value(row.get("severity")) > _severity_value(bucket.get("severity")):
            bucket["severity"] = row.get("severity")
    return grouped


def _package_fixed_versions(sorted_findings: List[Any]) -> List[Dict[str, Any]]:
    package_map: Dict[str, List[str]] = {}
    for item in sorted_findings:
        fixed_values = [advisory.get("fixed_version") for advisory in _summarize_advisories(item)]
        valid_fixed = _unique_fixed_versions(fixed_values)
        if not valid_fixed:
            continue
        package_map.setdefault(item.package_name, [])
        for fixed in valid_fixed:
            if fixed not in package_map[item.package_name]:
                package_map[item.package_name].append(fixed)

    return [
        {"package": package, "fixed_versions": _unique_fixed_versions(values)}
        for package, values in package_map.items()
    ]


def _fix_analysis(top_vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    fixed_versions = _unique_fixed_versions([item.get("fixed_version") for item in top_vulnerabilities])
    all_fixed = bool(top_vulnerabilities) and all(item.get("fixed_version") for item in top_vulnerabilities)
    any_fixed = any(item.get("fixed_version") for item in top_vulnerabilities)
    if all_fixed:
        fix_status = "all_fixed"
    elif any_fixed:
        fix_status = "partial_fixed"
    else:
        fix_status = "no_fixed"
    return {
        "fix_status": fix_status,
        "highest_fixed_version": fixed_versions[-1] if fixed_versions else None,
        "all_fixed_versions": fixed_versions,
    }


def _deps_dev_package_map(metadata_enrichment: List[MetadataEnrichment]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    packages: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in metadata_enrichment:
        if item.provider != "deps.dev" or not isinstance(item.data, dict):
            continue
        for package in item.data.get("packages", []) or []:
            name = str(package.get("name") or "").strip()
            version = str(package.get("version") or "").strip()
            if name and version:
                packages[(name, version)] = package
    return packages


def _license_names(raw_licenses: Any) -> List[str]:
    names: List[str] = []
    for item in raw_licenses or []:
        if isinstance(item, str):
            value = item.strip()
        elif isinstance(item, dict):
            value = str(
                item.get("spdx")
                or item.get("name")
                or item.get("license")
                or item.get("identifier")
                or ""
            ).strip()
        else:
            value = str(item).strip()
        if value and value not in names:
            names.append(value)
    return names


def _license_profile(licenses: List[str]) -> Dict[str, Any]:
    if not licenses:
        return {
            "category": "unknown",
            "open_source_signal": "unclear",
            "license_interpretation": "No clear license metadata was returned for this package version.",
            "commercial_use_note": "I cannot safely summarize commercial-use implications without clearer license metadata.",
        }

    normalized = [license_name.lower() for license_name in licenses]
    permissive_markers = ("mit", "apache-2.0", "bsd", "isc", "zlib", "unlicense", "python-2.0")
    weak_copyleft_markers = ("lgpl", "mpl", "epl", "cddl")
    strong_copyleft_markers = ("gpl", "agpl")
    proprietary_markers = ("proprietary", "commercial", "restricted")

    has_permissive = any(any(marker in name for marker in permissive_markers) for name in normalized)
    has_weak_copyleft = any(any(marker in name for marker in weak_copyleft_markers) for name in normalized)
    has_strong_copyleft = any(any(marker in name for marker in strong_copyleft_markers) for name in normalized)
    has_proprietary = any(any(marker in name for marker in proprietary_markers) for name in normalized)
    has_non_standard = any("non-standard" in name or "custom" in name or "unknown" in name for name in normalized)

    if has_proprietary:
        return {
            "category": "restricted",
            "open_source_signal": "unclear",
            "license_interpretation": "The license metadata suggests restrictions or non-open terms, so it should be reviewed carefully.",
            "commercial_use_note": "I cannot treat this as generally commercial-friendly without a legal or compliance review.",
        }
    if has_strong_copyleft and not has_permissive and not has_weak_copyleft:
        return {
            "category": "copyleft",
            "open_source_signal": "yes",
            "license_interpretation": "This appears to be a strong copyleft open-source license, which can carry redistribution or source-sharing obligations.",
            "commercial_use_note": "Commercial use may still be possible, but the obligations matter enough that you should review them before relying on it.",
        }
    if has_weak_copyleft and not has_permissive:
        return {
            "category": "weak_copyleft",
            "open_source_signal": "yes",
            "license_interpretation": "This appears to be a weak copyleft open-source license, so use is often possible but some compliance obligations may still apply.",
            "commercial_use_note": "This may be usable in commercial software, but the exact obligations should be checked for your distribution model.",
        }
    if has_permissive and not has_strong_copyleft and not has_weak_copyleft:
        return {
            "category": "permissive",
            "open_source_signal": "yes",
            "license_interpretation": "This appears to be a permissive open-source license.",
            "commercial_use_note": "This license type is commonly used in commercial software, but you should still review your own legal and compliance requirements.",
        }
    if has_non_standard or len(licenses) > 1:
        return {
            "category": "mixed_or_unclear",
            "open_source_signal": "unclear",
            "license_interpretation": "The license metadata is mixed or non-standard, so I cannot reduce it to one clean interpretation.",
            "commercial_use_note": "I cannot safely summarize commercial-use implications from the current metadata alone.",
        }
    return {
        "category": "unclear",
        "open_source_signal": "unclear",
        "license_interpretation": "The package has license metadata, but it does not map cleanly to a standard interpretation here.",
        "commercial_use_note": "I cannot safely summarize commercial-use implications from the current metadata alone.",
    }


def _license_guidance(category: str) -> Dict[str, str]:
    if category == "permissive":
        return {
            "license_type": "permissive",
            "allows": "Modification, redistribution, and commercial use are generally allowed.",
            "requires": "Retain the license notice, attribution, and disclaimer text.",
            "advantages": "Flexible for internal and commercial use with low operational friction.",
            "limitations": "Attribution and notice retention still matter, and there is typically no warranty.",
        }
    if category == "copyleft":
        return {
            "license_type": "copyleft",
            "allows": "Use, modification, and redistribution are generally allowed.",
            "requires": "Copyleft obligations may require source disclosure or reciprocal licensing when distributing derivatives.",
            "advantages": "Strong open-source guarantees and clear sharing expectations.",
            "limitations": "Commercial use is possible, but distribution obligations can be significant.",
        }
    if category == "weak_copyleft":
        return {
            "license_type": "weak copyleft",
            "allows": "Use, modification, and commercial distribution are often possible.",
            "requires": "Some reciprocal obligations can apply, usually around modified covered components.",
            "advantages": "More flexible than strong copyleft while still preserving some open-source obligations.",
            "limitations": "Linking and redistribution rules should be checked carefully for your packaging model.",
        }
    return {
        "license_type": "unclear",
        "allows": "The current metadata is not strong enough to summarize usage rights confidently.",
        "requires": "Review the exact license text before making distribution or commercial assumptions.",
        "advantages": "No reliable advantages can be summarized from the current metadata alone.",
        "limitations": "Usage and compliance implications remain uncertain until the license is clarified.",
    }


def _normalized_links(raw_links: Any) -> List[Dict[str, str]]:
    links: List[Dict[str, str]] = []

    def add_link(label: Any, url: Any) -> None:
        label_text = str(label or "reference").strip() or "reference"
        url_text = str(url or "").strip()
        if not url_text:
            return
        entry = {"label": label_text, "url": url_text}
        if entry not in links:
            links.append(entry)

    if isinstance(raw_links, dict):
        for label, url in raw_links.items():
            if isinstance(url, list):
                for item in url:
                    if isinstance(item, dict):
                        add_link(item.get("label") or label, item.get("url") or item.get("href"))
                    else:
                        add_link(label, item)
            else:
                add_link(label, url)
        return links

    if isinstance(raw_links, list):
        for item in raw_links:
            if isinstance(item, dict):
                add_link(
                    item.get("label") or item.get("type") or item.get("name"),
                    item.get("url") or item.get("href"),
                )
            else:
                add_link("reference", item)
    return links


def _metadata_visibility(metadata_package: Optional[Dict[str, Any]]) -> str:
    if not metadata_package:
        return "none"
    score = 0
    if _license_names(metadata_package.get("licenses")):
        score += 1
    if _normalized_links(metadata_package.get("links")):
        score += 1
    if metadata_package.get("published_at"):
        score += 1
    if metadata_package.get("is_default") is not None:
        score += 1
    return "good" if score >= 3 else "limited" if score >= 1 else "sparse"


def _trust_notes(metadata_package: Optional[Dict[str, Any]]) -> List[str]:
    if not metadata_package:
        return ["deps.dev metadata was not available for this exact version."]
    notes: List[str] = []
    advisory_count = len(metadata_package.get("advisory_keys", []) or [])
    if advisory_count:
        notes.append(f"deps.dev lists {_count_label(advisory_count, 'advisory')} for this version.")
    else:
        notes.append("deps.dev did not list advisory metadata for this exact version.")
    links = _normalized_links(metadata_package.get("links"))
    if links:
        notes.append("Source or documentation links are available in the package metadata.")
    else:
        notes.append("Package metadata is present, but useful source or documentation links are limited.")
    if metadata_package.get("published_at"):
        notes.append(f"Published metadata is available for this version ({metadata_package.get('published_at')}).")
    if metadata_package.get("is_default") is True:
        notes.append("This exact version is marked as a default version in deps.dev.")
    elif metadata_package.get("is_default") is False:
        notes.append("This exact version is not marked as the default version in deps.dev.")
    return notes[:4]


def _package_explanations(advisories: List[Dict[str, Any]], limit: int = 2) -> List[str]:
    explanations: List[str] = []
    for advisory in advisories[:limit]:
        summary = str(advisory.get("summary") or "").strip()
        details = str(advisory.get("details") or "").strip()
        text = summary or details
        if text and text not in explanations:
            explanations.append(text)
    return explanations


def _package_analysis(
    *,
    dependencies: List[Any],
    sorted_findings: List[Any],
    metadata_enrichment: List[MetadataEnrichment],
) -> Dict[str, Any]:
    findings_map = {(item.package_name, item.version_checked): item for item in sorted_findings}
    deps_dev_map = _deps_dev_package_map(metadata_enrichment)
    exact_dependencies = [dep for dep in dependencies if dep.version_kind.value == "exact"]
    unresolved_dependencies = [dep for dep in dependencies if dep.version_kind.value != "exact"]
    vulnerable_keys = [(item.package_name, item.version_checked) for item in sorted_findings if item.vulnerability_count > 0]
    seen_keys = set(vulnerable_keys)

    ordered_exact_dependencies = []
    for package_name, version_checked in vulnerable_keys:
        dependency = next(
            (dep for dep in exact_dependencies if dep.name == package_name and dep.version == version_checked),
            None,
        )
        if dependency is not None:
            ordered_exact_dependencies.append(dependency)
    for dep in exact_dependencies:
        key = (dep.name, dep.version)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        ordered_exact_dependencies.append(dep)

    packages: List[Dict[str, Any]] = []
    for dep in ordered_exact_dependencies:
        key = (dep.name, dep.version)
        finding = findings_map.get(key)
        metadata_package = deps_dev_map.get(key)
        licenses = _license_names(metadata_package.get("licenses") if metadata_package else [])
        license_profile = _license_profile(licenses)
        advisories = _summarize_advisories(finding) if finding else []
        packages.append(
            {
                "name": dep.name,
                "version": dep.version,
                "ecosystem": dep.ecosystem,
                "relationship": _relationship_label(dep.relationship),
                "source_type": dep.source_type.value,
                "source": dep.source,
                "file_path": dep.file_path,
                "match_confidence": finding.match_confidence if finding else "exact",
                "vulnerability_count": finding.vulnerability_count if finding else 0,
                "severity": finding.severity if finding else None,
                "identifiers": (finding.cve_ids[:3] or finding.vulnerability_ids[:3]) if finding else [],
                "vulnerability_explanations": _package_explanations(advisories),
                "advisories": advisories[:3],
                "recommended_fix": _recommendation_for_finding(finding.model_dump()) if finding else None,
                "metadata_available": metadata_package is not None,
                "metadata_visibility": _metadata_visibility(metadata_package),
                "licenses": licenses[:3],
                "license_category": license_profile["category"],
                "open_source_signal": license_profile["open_source_signal"],
                "license_interpretation": license_profile["license_interpretation"],
                "commercial_use_note": license_profile["commercial_use_note"],
                "trust_notes": _trust_notes(metadata_package),
                "links": _normalized_links(metadata_package.get("links") if metadata_package else [])[:3],
                "published_at": metadata_package.get("published_at") if metadata_package else None,
                "is_default": metadata_package.get("is_default") if metadata_package else None,
                "advisory_history_count": len(metadata_package.get("advisory_keys", []) or []) if metadata_package else 0,
            }
        )

    unresolved = [
        {
            "name": dep.name,
            "version": dep.version,
            "version_kind": dep.version_kind.value,
            "ecosystem": dep.ecosystem,
            "source": dep.file_path or dep.source or dep.source_type.value,
            "reason": "missing_version" if not dep.version else "non_exact_version",
            "note": (
                "Exact-version vulnerability or metadata enrichment was skipped because the package version is unresolved."
                if dep.version_kind.value != "exact"
                else None
            ),
        }
        for dep in unresolved_dependencies[:MAX_LLM_ITEMS]
    ]

    return {
        "exact_packages_total": len(exact_dependencies),
        "packages_with_metadata": sum(1 for package in packages if package["metadata_available"]),
        "packages_with_vulnerabilities": sum(1 for package in packages if package["vulnerability_count"] > 0),
        "packages": packages,
        "unresolved_packages": unresolved,
    }


def _developer_license_entries(package_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for package in list(package_analysis.get("packages") or []):
        licenses = list(package.get("licenses") or [])
        links = list(package.get("links") or [])
        source_url = next(
            (
                item.get("url")
                for item in links
                if str(item.get("label") or "").strip().lower() in {"source", "repository", "repo", "homepage", "docs", "documentation"}
            ),
            None,
        )
        license_url = next(
            (
                item.get("url")
                for item in links
                if "license" in str(item.get("label") or "").strip().lower()
            ),
            None,
        )
        guidance = _license_guidance(str(package.get("license_category") or "unclear"))
        rows.append(
            {
                "package": package.get("name"),
                "version": package.get("version"),
                "license": licenses[0] if licenses else None,
                "license_type": guidance["license_type"],
                "allows": guidance["allows"],
                "requires": guidance["requires"],
                "commercial_use": package.get("commercial_use_note"),
                "advantages": guidance["advantages"],
                "limitations": guidance["limitations"],
                "license_url": license_url,
                "source_url": source_url,
            }
        )
    return rows[:MAX_LLM_ITEMS]


def build_license_analysis(
    *,
    inventory: DependencyInventory,
    metadata_enrichment: List[MetadataEnrichment],
) -> Dict[str, Any]:
    deps_dev_map = _deps_dev_package_map(metadata_enrichment)
    findings: List[Dict[str, Any]] = []

    for dep in inventory.exact_dependencies:
        package = deps_dev_map.get((dep.name, dep.version))
        if not package:
            continue
        licenses = _license_names(package.get("licenses"))
        if not licenses:
            continue
        profile = _license_profile(licenses)
        primary_license = licenses[0]
        if profile["category"] == "permissive":
            policy_status = "Allowed"
            reason = (
                f"{primary_license} is a permissive license. Permissive licenses can be used for commercial purposes "
                "with minimal restrictions, typically requiring attribution to the original authors."
            )
        elif profile["category"] == "copyleft":
            policy_status = "Review required"
            reason = (
                f"{primary_license} is a copyleft license. Copyleft licenses require derivative works to be "
                "distributed under the same license, which may impose restrictions on commercial use."
            )
        elif profile["category"] == "weak_copyleft":
            policy_status = "Review required"
            reason = (
                f"{primary_license} is a weak copyleft license. It allows linking with proprietary code, but "
                "modifications to the licensed components must be shared under the same license."
            )
        else:
            policy_status = "Review required"
            reason = (
                "The license for this package could not be clearly determined. Review is recommended before "
                "using it in a commercial or production environment."
            )

        links = _normalized_links(package.get("links"))
        license_url = next(
            (item.get("url") for item in links if "license" in str(item.get("label") or "").strip().lower()),
            None,
        )
        repository_url = next(
            (
                item.get("url")
                for item in links
                if str(item.get("label") or "").strip().lower() == "repository"
            ),
            None,
        )
        findings.append(
            {
                "package_name": dep.name,
                "version": dep.version,
                "ecosystem": dep.ecosystem,
                "license_expression": ", ".join(licenses[:3]),
                "license_ids": licenses[:3],
                "source": "deps.dev",
                "policy_status": policy_status,
                "reason": reason,
                "license_url": license_url,
                "repository_url": repository_url,
                "source_links": [
                    *[
                        {"label": str(item.get("label") or "").strip(), "url": str(item.get("url") or "").strip()}
                        for item in links
                        if str(item.get("url") or "").strip()
                    ],
                    *([{"label": "License", "url": license_url}] if license_url else []),
                ],
            }
        )

    for finding in findings:
        finding["source_links"] = [
            link for link in finding.get("source_links", [])
            if isinstance(link, dict) and str(link.get("url") or "").strip()
        ]

    allowed = sum(1 for item in findings if item["policy_status"] == "Allowed")
    review = sum(1 for item in findings if item["policy_status"] == "Review required")
    denied = sum(1 for item in findings if item["policy_status"] == "Denied")
    summary = {
        "total": len(inventory.exact_dependencies),
        "detected": len(findings),
        "allowed": allowed,
        "review": review,
        "denied": denied,
        "unknown": max(len(inventory.exact_dependencies) - len(findings), 0),
    }
    if denied:
        status = "blocked"
    elif review:
        status = "Review required"
    elif findings:
        status = "passed"
    else:
        status = "no_dependencies"

    return {
        "status": status,
        "summary": summary,
        "findings": findings,
        "policy": {
            "allowed": ["permissive"],
            "denied": [],
            "review": ["copyleft", "weak_copyleft", "mixed_or_unclear", "unclear", "restricted"],
            "disclaimer": "License signals are derived from provider metadata and should be reviewed for compliance decisions.",
        },
        "providers": {"deps.dev": next((item.status for item in metadata_enrichment if item.provider == "deps.dev"), "not_called")},
    }


def build_llm_context(
    *,
    report: Dict[str, Any],
    inventory: DependencyInventory,
    vulnerability_research: VulnerabilityResearch,
    metadata_enrichment: List[MetadataEnrichment],
) -> Dict[str, Any]:
    dependencies = inventory.dependencies
    version_counts = Counter(dep.version_kind.value for dep in dependencies)
    source_counts = Counter(dep.source_type.value for dep in dependencies)
    ecosystem_counts = Counter((dep.ecosystem or "unknown") for dep in dependencies)
    discovery_sources = _discovery_sources(inventory)

    sorted_findings = sorted(
        [item for item in vulnerability_research.packages_checked if item.vulnerability_count > 0],
        key=lambda finding: (_finding_priority(finding), finding.vulnerability_count, len(finding.cve_ids)),
        reverse=True,
    )
    vulnerable = [
        {
            "package": item.package_name,
            "version": item.version_checked,
            "ecosystem": item.ecosystem_used,
            "vulnerability_count": item.vulnerability_count,
            "cve_ids": item.cve_ids[:MAX_LLM_ITEMS],
            "vulnerability_ids": item.vulnerability_ids[:MAX_LLM_ITEMS],
            "match_confidence": item.match_confidence,
            "severity": item.severity,
            "relationship": _relationship_label(item.relationship),
        }
        for item in sorted_findings
    ][:MAX_LLM_ITEMS]

    vulnerability_details = [
        {
            "package": item.package_name,
            "version": item.version_checked,
            "ecosystem": item.ecosystem_used,
            "severity": item.severity,
            "match_confidence": item.match_confidence,
            "relationship": _relationship_label(item.relationship),
            "source_type": item.source_type,
            "file_path": item.file_path,
            "vulnerability_count": item.vulnerability_count,
            "cve_ids": item.cve_ids[:MAX_LLM_ITEMS],
            "vulnerability_ids": item.vulnerability_ids[:MAX_LLM_ITEMS],
            "advisories": _summarize_advisories(item),
            "recommended_fix": _recommendation_for_finding(item.model_dump()),
            "priority_reason": (
                "Prioritized because this is an exact-version vulnerable dependency."
                if item.match_confidence == "exact"
                else "Lower confidence because exact version evidence is incomplete."
            ),
            "dependent_impact_note": (
                "This is a direct dependency, so anything that imports or relies on it may inherit the risk until it is upgraded."
                if _relationship_label(item.relationship) == "direct"
                else None
            ),
        }
        for item in sorted_findings[:MAX_LLM_ITEMS]
    ]

    skipped = vulnerability_research.skipped_packages[:MAX_LLM_ITEMS]
    exact_dependencies = [dep for dep in dependencies if dep.version_kind.value == "exact"]
    uncertain_dependencies = [dep for dep in dependencies if dep.version_kind.value != "exact"]
    package_analysis = _package_analysis(
        dependencies=dependencies,
        sorted_findings=sorted_findings,
        metadata_enrichment=metadata_enrichment,
    )
    top_vulnerability_rows = _top_vulnerability_rows(sorted_findings)
    top_vulnerabilities_grouped = _group_top_vulnerabilities(top_vulnerability_rows)
    detailed_fix_analysis = _fix_analysis(top_vulnerability_rows)
    detailed_licenses = _developer_license_entries(package_analysis)
    skipped_count = len(vulnerability_research.skipped_packages)
    if report.get("result_type") == "discovery_only" and skipped_count == 0:
        skipped_count = len(uncertain_dependencies)
    top_uncertainties = [
        {
            "package": item.get("package_name"),
            "version": item.get("version"),
            "version_kind": item.get("version_kind"),
            "provider": item.get("provider"),
            "reason": item.get("reason"),
        }
        for item in skipped
    ]
    if not top_uncertainties:
        top_uncertainties = [
            {
                "package": dep.name,
                "version": dep.version,
                "version_kind": dep.version_kind.value,
                "provider": dep.source_type.value,
                "reason": "missing_version" if not dep.version else "non_exact_version",
            }
            for dep in uncertain_dependencies[:MAX_LLM_ITEMS]
        ]
    important_dependencies = [
        {
            "name": dep.name,
            "version": dep.version,
            "version_kind": dep.version_kind.value,
            "ecosystem": dep.ecosystem,
            "source_type": dep.source_type.value,
            "source": dep.source,
        }
        for dep in (exact_dependencies[:MAX_LLM_ITEMS] or dependencies[:MAX_LLM_ITEMS])
    ]
    vulnerable_package_names = []
    for item in sorted_findings:
        if item.package_name and item.package_name not in vulnerable_package_names:
            vulnerable_package_names.append(item.package_name)
        if len(vulnerable_package_names) >= MAX_LLM_ITEMS:
            break
    top_cves = []
    for item in sorted_findings[:MAX_LLM_ITEMS]:
        for advisory in _summarize_advisories(item):
            entry = {
                "package": item.package_name,
                "version": item.version_checked,
                "id": advisory.get("id"),
                "severity": advisory.get("severity"),
                "summary": advisory.get("summary"),
                "match_confidence": item.match_confidence,
                "relationship": _relationship_label(item.relationship),
            }
            if entry not in top_cves:
                top_cves.append(entry)
            if len(top_cves) >= 3:
                break
        if len(top_cves) >= 3:
            break

    sbom_notes = []
    if source_counts.get("github_sbom", 0):
        unknown_sbom = [
            dep for dep in dependencies
            if dep.source_type.value == "github_sbom" and (not dep.ecosystem or dep.version_kind.value == "unknown")
        ]
        action_like = [
            dep for dep in dependencies
            if dep.source_type.value == "github_sbom"
            and (dep.ecosystem.lower() in {"githubactions", "github_actions"} or dep.name.startswith("actions/"))
        ]
        if unknown_sbom:
            sbom_notes.append(f"{len(unknown_sbom)} SBOM dependencies had unknown ecosystem or version quality.")
        if action_like:
            sbom_notes.append(
                f"{len(action_like)} SBOM entries look like GitHub Actions/workflow packages and may not reflect runtime package risk."
            )

    warning_summary = _warning_summary(report.get("warning_details", []))
    top_warnings = _dedupe_limited(report.get("warnings", []), MAX_LLM_ITEMS)
    recommendations = []
    if vulnerable:
        recommendations.append("Prioritize exact-version vulnerable dependencies with CVE evidence.")
    if version_counts.get("range", 0) or version_counts.get("unknown", 0):
        recommendations.append("Generate or inspect a lockfile/SBOM with resolved exact versions for more precise matching.")
    if any(item.get("code") == "GITHUB_SBOM_FALLBACK" for item in report.get("warning_details", [])):
        recommendations.append("Review GitHub SBOM availability/quality; parser fallback was used.")
    if not vulnerable and skipped:
        recommendations.append("No exact vulnerable packages were confirmed; resolve skipped non-exact dependencies before concluding risk is low.")
    if report.get("result_type") == "discovery_only":
        recommendations = [
            "Provide pinned package versions, a lockfile, or a resolved SBOM so exact vulnerability matching can run.",
            "If this came from a GitHub repo scan, confirm the GitHub dependency graph or SBOM is enabled and accessible.",
        ]
    elif package_analysis["packages_with_metadata"] and not vulnerable:
        recommendations.append("Review license and package metadata for the exact-version dependencies, even when no CVEs were confirmed.")
    checked_examples = [
        {
            "name": dep.name,
            "version": dep.version,
            "ecosystem": dep.ecosystem,
        }
        for dep in exact_dependencies[:3]
    ]
    unresolved_examples = [
        {
            "name": dep.name,
            "version": dep.version,
            "version_kind": dep.version_kind.value,
            "ecosystem": dep.ecosystem,
        }
        for dep in uncertain_dependencies[:3]
    ]
    dependency_graphs = dict(report.get("dependency_graphs") or {})
    dependency_graph_summary = [
        {
            "package": graph.get("package"),
            "version": graph.get("version"),
            "dependency_count": int(graph.get("dependency_count") or len(graph.get("dependencies") or [])),
            "truncated": bool(graph.get("truncated")),
        }
        for graph in dependency_graphs.values()
        if isinstance(graph, dict)
    ][:MAX_LLM_ITEMS]

    return {
        "purpose": "compact_llm_reasoning_context",
        "input": {
            "input_type": report.get("input_type"),
            "mode": report.get("mode"),
            "result_type": report.get("result_type"),
            "repo_url": report.get("repo_url"),
            "language": report.get("language"),
            "dependency_summary": _dependency_preview(dependencies),
            "packages_scanned": [
                {
                    "package_name": dep.name,
                    "package_version": dep.version,
                    "ecosystem": dep.ecosystem,
                }
                for dep in dependencies[:MAX_LLM_ITEMS]
            ] if report.get("input_type") == "package" else [],
            "route": report.get("route", {}),
        },
        "provider_summary": {
            "scan_source": _provider_source_summary(report, dependencies),
            "dependency_sources": dict(source_counts),
            "ecosystems": dict(ecosystem_counts),
            "sbom_notes": sbom_notes[:MAX_LLM_ITEMS],
        },
        "scan_summary": {
            "total_dependencies": len(dependencies),
            "exact_versions": version_counts.get("exact", 0),
            "range_versions": version_counts.get("range", 0),
            "unknown_versions": version_counts.get("unknown", 0),
            "result_type": report.get("result_type"),
            "analysis_blocked_reason": report.get("analysis_blocked_reason"),
            "packages_checked_for_vulnerabilities": vulnerability_research.packages_checked_count,
            "packages_skipped_for_exact_matching": skipped_count,
            "cves_found": len(vulnerability_research.cves_found),
            "metadata_providers": [
                {"provider": item.provider, "status": item.status}
                for item in metadata_enrichment[:MAX_LLM_ITEMS]
            ],
        },
        "top_findings": vulnerable,
        "vulnerability_details": vulnerability_details,
        "top_cves": top_cves,
        "top_vulnerabilities_grouped": top_vulnerabilities_grouped,
        "vulnerable_package_summary": {
            "count": len(vulnerable_package_names),
            "packages": vulnerable_package_names[:MAX_LLM_ITEMS],
        },
        "package_analysis": package_analysis,
        "detailed": {
            "mode": "detailed",
            "top_vulnerabilities_grouped": top_vulnerabilities_grouped,
            "package_fixed_versions": _package_fixed_versions(sorted_findings),
            "fix_analysis": detailed_fix_analysis,
            "licenses": detailed_licenses,
        },
        "developer": {
            "mode": "developer",
            "dependency_quality": {
                "exact_versions": version_counts.get("exact", 0),
                "range_versions": version_counts.get("range", 0),
                "unknown_versions": version_counts.get("unknown", 0),
                "packages_checked_for_vulnerabilities": vulnerability_research.packages_checked_count,
            },
            "dependency_graphs": dependency_graph_summary,
            "upgrade_priority": [
                {
                    "package": item.package_name,
                    "version": item.version_checked,
                    "severity": item.severity,
                    "relationship": _relationship_label(item.relationship),
                    "vulnerability_count": item.vulnerability_count,
                }
                for item in sorted_findings[:MAX_LLM_ITEMS]
            ],
            "blockers": top_uncertainties,
            "recommended_next_steps": recommendations[:MAX_LLM_ITEMS],
            "package_fixed_versions": _package_fixed_versions(sorted_findings),
        },
        "top_uncertainties": top_uncertainties,
        "important_dependencies": important_dependencies,
        "dependency_discovery": {
            "sources": discovery_sources,
            "checked_examples": checked_examples,
            "unresolved_dependencies": [
                {
                    "name": dep.name,
                    "source": dep.file_path or dep.source or dep.source_type.value,
                    "version_kind": dep.version_kind.value,
                }
                for dep in uncertain_dependencies[:MAX_LLM_ITEMS]
            ],
            "unresolved_examples": unresolved_examples,
        },
        "important_metadata": _metadata_facts(metadata_enrichment),
        "warning_summary": warning_summary,
        "top_warnings": top_warnings,
        "finding_priority_rule": "Prioritize higher severity when available, then exact-version confidence, then direct dependency exposure.",
        "recommended_next_steps": recommendations[:MAX_LLM_ITEMS],
    }
