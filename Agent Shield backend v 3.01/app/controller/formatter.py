import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _context(result: Dict[str, Any]) -> Dict[str, Any]:
    report = result.get("json_report", {})
    return report.get("llm_context") or report


def _plural(count: int, word: str) -> str:
    if word.endswith("y") and not word.endswith(("ay", "ey", "iy", "oy", "uy")):
        suffix = word[:-1] + "ies"
        return f"{count} {word if count == 1 else suffix}"
    if word.endswith("entry"):
        suffix = word[:-1] + "ies"
        return f"{count} {word if count == 1 else suffix}"
    return f"{count} {word}{'' if count == 1 else 's'}"


def _bullet(items: List[str], limit: int = 4) -> str:
    return "\n".join(f"- {item}" for item in items[:limit] if item)


def _summary_numbers(context: Dict[str, Any]) -> Dict[str, int]:
    summary = context.get("scan_summary", {})
    return {
        "total": int(summary.get("total_dependencies") or 0),
        "exact": int(summary.get("exact_versions") or 0),
        "range": int(summary.get("range_versions") or 0),
        "unknown": int(summary.get("unknown_versions") or 0),
        "checked": int(summary.get("packages_checked_for_vulnerabilities") or 0),
        "skipped": int(summary.get("packages_skipped_for_exact_matching") or 0),
        "cves": int(summary.get("cves_found") or 0),
    }


def _result_type(context: Dict[str, Any]) -> str:
    summary = context.get("scan_summary", {})
    return str(summary.get("result_type") or context.get("input", {}).get("result_type") or "vulnerability_scan")


def _target_phrase(context: Dict[str, Any]) -> str:
    input_info = context.get("input", {})
    input_type = input_info.get("input_type")
    if input_type == "github_repo" and input_info.get("repo_url"):
        return f"the repository `{input_info.get('repo_url')}`"
    if input_type == "dependency_file":
        return "the dependency file"
    if input_type == "package":
        packages_scanned = input_info.get("packages_scanned", [])
        if len(packages_scanned) > 1:
            return "the requested packages"
        return "the package"
    return "the target"


def _package_entries(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(context.get("input", {}).get("packages_scanned", []) or [])


def _package_analysis_entries(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list((context.get("package_analysis") or {}).get("packages", []) or [])


def _package_label(name: Optional[str], version: Optional[str]) -> str:
    package_name = str(name or "").strip() or "package"
    package_version = str(version or "").strip()
    if not package_version:
        return f"`{package_name}`"
    if package_version.startswith((">", "<", "~", "!", "=")):
        return f"`{package_name}{package_version}`"
    return f"`{package_name}=={package_version}`"


def _dependency_summary(context: Dict[str, Any]) -> Dict[str, Any]:
    return dict(context.get("input", {}).get("dependency_summary", {}) or {})


def _dependency_preview_line(context: Dict[str, Any]) -> Optional[str]:
    summary = _dependency_summary(context)
    preview = summary.get("preview") or []
    if not summary.get("can_list_all") or not preview:
        return None
    return "Dependencies: " + ", ".join(f"`{item}`" for item in preview)


def _top_affected_summary(context: Dict[str, Any], limit: int = 3) -> Optional[str]:
    packages = list((context.get("vulnerable_package_summary") or {}).get("packages", []) or [])
    if not packages:
        return None
    return "Most affected packages: " + ", ".join(f"`{name}`" for name in packages[:limit])


def _repo_scan_source_label(context: Dict[str, Any]) -> Optional[str]:
    source = (context.get("provider_summary", {}) or {}).get("scan_source", {})
    label = str(source.get("label") or "").strip()
    return label or None


def _ecosystem_summary(context: Dict[str, Any]) -> Optional[str]:
    ecosystems = dict((context.get("provider_summary", {}) or {}).get("ecosystems", {}) or {})
    if not ecosystems:
        language = str((context.get("input", {}) or {}).get("language") or "").strip()
        return f"Language: {language}." if language else None
    ordered = sorted(ecosystems.items(), key=lambda item: item[1], reverse=True)
    labels = [f"{name} ({count})" for name, count in ordered[:3] if name]
    if labels:
        return "Ecosystems: " + ", ".join(labels) + "."
    return None


def _example_packages_line(items: List[Dict[str, Any]], heading: str, limit: int = 2) -> Optional[str]:
    if not items:
        return None
    labels = []
    for item in items[:limit]:
        labels.append(_package_label(item.get("name"), item.get("version")))
    if not labels:
        return None
    return f"{heading}: " + ", ".join(labels)


def _finding_lines(findings: List[Dict[str, Any]], limit: int = 3) -> List[str]:
    lines = []
    for item in findings[:limit]:
        cves = ", ".join(item.get("cve_ids", [])[:3])
        cve_text = f" ({cves})" if cves else ""
        lines.append(
            f"`{item.get('package')}` {item.get('version')}: "
            f"{_plural(int(item.get('vulnerability_count') or 0), 'finding')}{cve_text}"
        )
    return lines


def _fast_finding_lines(findings: List[Dict[str, Any]], limit: int = 3) -> List[str]:
    lines = []
    for item in findings[:limit]:
        severity = _severity_text(item.get("severity"))
        parts = [f"`{item.get('package')}` {item.get('version')}"]
        if severity:
            parts.append(f"severity {severity}")
        count = int(item.get("vulnerability_count") or 0)
        parts.append(f"{_plural(count, 'confirmed finding')}")
        lines.append(", ".join(parts) + ".")
    return lines


def _severity_text(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return str(value).strip().lower()


def _advisory_meaning(advisories: List[Dict[str, Any]]) -> Optional[str]:
    for advisory in advisories:
        summary = str(advisory.get("summary") or "").strip()
        if summary:
            return summary
        details = str(advisory.get("details") or "").strip()
        if details:
            return details
    return None


def _vulnerability_lines(details: List[Dict[str, Any]], limit: int = 3, include_meaning: bool = False) -> List[str]:
    lines = []
    for item in details[:limit]:
        identifiers = item.get("cve_ids") or item.get("vulnerability_ids") or []
        id_text = ", ".join(identifiers[:3]) if identifiers else "advisory IDs unavailable"
        severity = _severity_text(item.get("severity"))
        relationship = item.get("relationship")
        headline_bits = [f"`{item.get('package')}` {item.get('version')}"]
        if severity:
            headline_bits.append(f"severity {severity}")
        if relationship and relationship != "unknown":
            headline_bits.append(f"{relationship} dependency")
        line = f"{', '.join(headline_bits)}: {id_text}."
        if include_meaning:
            meaning = _advisory_meaning(item.get("advisories", []))
            if meaning:
                line += f" {meaning}"
        lines.append(line)
    return lines


def _top_cve_lines(context: Dict[str, Any], limit: int = 3) -> List[str]:
    lines = []
    for item in list(context.get("top_cves", []) or [])[:limit]:
        bits = [str(item.get("id") or "advisory").strip()]
        severity = _severity_text(item.get("severity"))
        if severity:
            bits.append(f"severity {severity}")
        package = _package_label(item.get("package"), item.get("version"))
        line = f"{package}: {', '.join(bits)}."
        summary = str(item.get("summary") or "").strip()
        if summary:
            line += f" {summary}"
        lines.append(line)
    return lines


def _remediation_lines(details: List[Dict[str, Any]], limit: int = 3) -> List[str]:
    lines = []
    for item in details[:limit]:
        fix = str(item.get("recommended_fix") or "").strip()
        if not fix:
            continue
        lines.append(f"`{item.get('package')}`: {fix}")
    return lines


def _no_vulnerability_message(numbers: Dict[str, int]) -> str:
    if numbers["cves"] == 0:
        return "I did not confirm any CVEs in the exact-version dependencies that could be checked."
    return f"I found {_plural(numbers['cves'], 'CVE')} in the dependencies that could be checked."


def _uncertainty_summary(context: Dict[str, Any]) -> str:
    numbers = _summary_numbers(context)
    provider_summary = context.get("provider_summary", {})
    sbom_notes = provider_summary.get("sbom_notes", [])
    parts = []
    if numbers["skipped"]:
        parts.append(
            f"{_plural(numbers['skipped'], 'package')} could not be checked precisely because exact versions were unavailable."
        )
    if numbers["range"] or numbers["unknown"]:
        parts.append(
            f"The dependency data included {_plural(numbers['range'], 'range-based version')} and "
            f"{_plural(numbers['unknown'], 'unknown-version entry')}."
        )
    for note in sbom_notes[:2]:
        parts.append(str(note))
    return " ".join(parts)


def _discovery_only_message(context: Dict[str, Any], target: str) -> str:
    discovery = context.get("dependency_discovery", {})
    sources = discovery.get("sources", [])
    summary = context.get("scan_summary", {})
    source_line = None
    if sources:
        first = sources[0]
        package_text = ", ".join(f"`{name}`" for name in first.get("packages", [])[:6])
        source_name = first.get("source") or "the dependency source"
        source_line = f"I found these packages in `{source_name}`: {package_text}"
    blocked_reason = str(summary.get("analysis_blocked_reason") or "no_exact_versions")
    limitation = "The dependency data did not include exact versions, so I could not run reliable vulnerability matching."
    if blocked_reason == "missing_versions_in_repo_fallback":
        limitation += " GitHub SBOM or dependency-graph data was unavailable or insufficient, so the repo fallback could only discover package names."
    next_step = "Provide pinned versions, a lockfile, or a resolved SBOM/dependency graph to get a real package-by-package vulnerability result."
    parts = [f"Dependency discovery for {target} completed, but a full vulnerability scan could not run."]
    if source_line:
        parts.append(source_line)
    parts.append(limitation)
    parts.append(next_step)
    return "\n\n".join(parts)


def _fast_intro(context: Dict[str, Any], target: str, numbers: Dict[str, int]) -> str:
    input_info = context.get("input", {})
    input_type = input_info.get("input_type")
    packages = _package_entries(context)
    if input_type == "package":
        if len(packages) == 1:
            package = packages[0]
            subject = _package_label(package.get("package_name"), package.get("package_version"))
            if numbers["cves"]:
                return f"For {subject}, I found {_plural(numbers['cves'], 'confirmed CVE')}."
            if numbers["exact"]:
                return f"For {subject}, I did not confirm any vulnerabilities in the exact version I could check."
            return f"For {subject}, I did not confirm any vulnerabilities in the packages I could check."
        if len(packages) > 1:
            if numbers["cves"]:
                return f"I checked {_plural(len(packages), 'package')} and found confirmed vulnerabilities in {_plural(len((context.get('vulnerable_package_summary') or {}).get('packages', [])), 'package')}."
            return f"I checked {_plural(len(packages), 'package')} and did not confirm any vulnerabilities in the exact versions I could check."
    if input_type == "dependency_file":
        sources = list(context.get("dependency_discovery", {}).get("sources", []) or [])
        file_name = (sources[0].get("source") if sources else None) or "the dependency file"
        if numbers["cves"]:
            return f"I scanned `{file_name}` and found {_plural(numbers['total'], 'dependency')}."
        return f"I scanned `{file_name}` and did not confirm any vulnerabilities in the exact-version dependencies I could check."
    if input_type == "github_repo":
        repo_url = input_info.get("repo_url") or target
        if numbers["cves"]:
            return f"I scanned `{repo_url}` and found {_plural(numbers['total'], 'dependency')}."
        return f"I scanned `{repo_url}` and did not confirm any vulnerabilities in the exact-version dependencies I could check."
    return f"Security check for {target}: {_no_vulnerability_message(numbers)}"


def _fast_limitation(context: Dict[str, Any]) -> Optional[str]:
    uncertainty = _uncertainty_summary(context)
    if uncertainty:
        return "Confidence note: " + uncertainty
    return None


def _fast_repo_no_vuln_summary(context: Dict[str, Any], numbers: Dict[str, int]) -> str:
    repo_url = str((context.get("input", {}) or {}).get("repo_url") or "the repository")
    scan_source = _repo_scan_source_label(context)
    checked_examples = list((context.get("dependency_discovery", {}) or {}).get("checked_examples", []) or [])
    unresolved_examples = list((context.get("dependency_discovery", {}) or {}).get("unresolved_examples", []) or [])
    lines = [
        f"I didn't confirm any vulnerable dependencies in `{repo_url}` from this fast scan."
    ]
    source_text = f" The scan used {scan_source}." if scan_source else ""
    lines[0] += (
        f" It found {_plural(numbers['total'], 'dependency')}, and "
        f"{_plural(numbers['checked'], 'exact-version dependency')} could be checked precisely.{source_text}"
    )
    ecosystem_line = _ecosystem_summary(context)
    checked_line = _example_packages_line(checked_examples, "Examples checked")
    unresolved_line = _example_packages_line(unresolved_examples, "Main unresolved packages")
    body_parts = [part for part in [ecosystem_line, checked_line, unresolved_line] if part]
    if body_parts:
        lines.append(" ".join(body_parts))
    limitation = _fast_limitation(context)
    if limitation:
        lines.append(limitation + " This should be treated as incomplete coverage, not proof the repo is clean.")
    else:
        lines.append("This should be treated as incomplete coverage, not proof the repo is clean.")
    next_steps = context.get("recommended_next_steps", []) or []
    if next_steps:
        lines.append("Next step: " + str(next_steps[0]))
    return "\n\n".join(lines)


def _metadata_sentence(metadata: List[Dict[str, Any]]) -> Optional[str]:
    for item in metadata:
        if item.get("provider") == "deps.dev":
            enriched = item.get("packages_enriched")
            skipped = item.get("packages_skipped")
            if enriched is not None:
                sentence = f"I was able to enrich {_plural(int(enriched or 0), 'package')} with deps.dev metadata"
                if skipped:
                    sentence += f"; {_plural(int(skipped), 'package')} were skipped because exact versions were unavailable"
                return sentence + "."
        if item.get("provider") == "github_api" and item.get("repo"):
            repo = item["repo"]
            bits = []
            if repo.get("stars") is not None:
                bits.append(f"{repo.get('stars')} stars")
            if repo.get("forks") is not None:
                bits.append(f"{repo.get('forks')} forks")
            if repo.get("language"):
                bits.append(f"primary language {repo.get('language')}")
            if bits:
                return "GitHub context: " + ", ".join(bits) + "."
    return None


def _detailed_summary_intro(context: Dict[str, Any], numbers: Dict[str, int], target: str) -> str:
    input_info = context.get("input", {})
    input_type = input_info.get("input_type")
    if input_type == "package":
        packages = _package_entries(context)
        if len(packages) == 1:
            package = packages[0]
            return (
                f"I reviewed {_package_label(package.get('package_name'), package.get('package_version'))}. "
                f"The scan checked {_plural(numbers['exact'], 'exact-version dependency')} and found {_plural(numbers['cves'], 'confirmed CVE')}."
            )
        if len(packages) > 1:
            return (
                f"I reviewed {_plural(len(packages), 'package')} and checked {_plural(numbers['exact'], 'exact-version dependency')}. "
                f"Confirmed vulnerability evidence was found for {_plural(len((context.get('vulnerable_package_summary') or {}).get('packages', [])), 'package')}."
            )
    if input_type == "dependency_file":
        sources = list((context.get("dependency_discovery", {}) or {}).get("sources", []) or [])
        file_name = (sources[0].get("source") if sources else None) or "the dependency file"
        return (
            f"I reviewed `{file_name}` and found {_plural(numbers['total'], 'dependency')}. "
            f"{_plural(numbers['exact'], 'dependency')} had exact versions available for deeper analysis."
        )
    if input_type == "github_repo":
        repo_url = input_info.get("repo_url") or target
        scan_source = _repo_scan_source_label(context)
        source_text = f" using {scan_source}" if scan_source else ""
        return (
            f"I reviewed `{repo_url}`{source_text} and found {_plural(numbers['total'], 'dependency')}. "
            f"{_plural(numbers['exact'], 'dependency')} had exact versions available for deeper analysis."
        )
    return (
        f"Detailed review for {target}. "
        f"The scan found {_plural(numbers['total'], 'dependency')} and {_plural(numbers['cves'], 'confirmed CVE')}."
    )


def _detailed_package_lines(package: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    header_bits = [_package_label(package.get("name"), package.get("version"))]
    severity = _severity_text(package.get("severity"))
    if severity:
        header_bits.append(f"severity {severity}")
    relationship = package.get("relationship")
    if relationship and relationship != "unknown":
        header_bits.append(f"{relationship} dependency")

    identifiers = list(package.get("identifiers") or [])
    if int(package.get("vulnerability_count") or 0) > 0:
        line = (
            f"{', '.join(header_bits)}: {_plural(int(package.get('vulnerability_count') or 0), 'confirmed finding')}"
        )
        if identifiers:
            line += f" ({', '.join(identifiers[:3])})"
        explanations = [text for text in list(package.get("vulnerability_explanations") or [])[:2] if text]
        if explanations:
            line += f". {' '.join(explanations)}"
        else:
            line += "."
        lines.append(line)
        fix = str(package.get("recommended_fix") or "").strip()
        if fix:
            lines.append(f"Remediation: {fix}")
    else:
        lines.append(
            f"{', '.join(header_bits)}: no confirmed vulnerability evidence was returned for this exact version."
        )

    licenses = list(package.get("licenses") or [])
    if licenses:
        lines.append(
            f"License: {', '.join(licenses[:3])}. {str(package.get('license_interpretation') or '').strip()} "
            f"{str(package.get('commercial_use_note') or '').strip()}".strip()
        )
    else:
        lines.append(str(package.get("commercial_use_note") or "License metadata was not available for this package version."))

    trust_notes = [note for note in list(package.get("trust_notes") or [])[:2] if note]
    if trust_notes:
        lines.append("Trust/metadata: " + " ".join(trust_notes))

    links = [item for item in list(package.get("links") or [])[:3] if item.get("url")]
    if links:
        lines.append(
            "Useful links: "
            + ", ".join(f"{item.get('label')}: {item.get('url')}" for item in links)
        )

    return lines


def _detailed_package_sections(context: Dict[str, Any], limit: int = 12) -> List[str]:
    sections = []
    for package in _package_analysis_entries(context)[:limit]:
        sections.append("\n".join(_detailed_package_lines(package)))
    return sections


def _detailed_unresolved_note(context: Dict[str, Any]) -> Optional[str]:
    unresolved = list((context.get("package_analysis") or {}).get("unresolved_packages", []) or [])
    if not unresolved:
        return None
    labels = []
    for item in unresolved[:3]:
        labels.append(_package_label(item.get("name"), item.get("version")))
    return (
        f"{_plural(len(unresolved), 'package')} could not get exact-version vulnerability or metadata enrichment. "
        f"Examples: {', '.join(labels)}."
    )


def build_response_meta(result: Dict[str, Any]) -> Dict[str, Any]:
    context = _context(result)
    numbers = _summary_numbers(context)
    return {
        "used_llm_context": "llm_context" in result.get("json_report", {}),
        "result_type": _result_type(context),
        "total_dependencies": numbers["total"],
        "confirmed_cves": numbers["cves"],
        "exact_versions": numbers["exact"],
        "non_exact_versions": numbers["range"] + numbers["unknown"],
        "skipped_exact_matching": numbers["skipped"],
        "top_finding_count": len(context.get("top_findings", [])),
        "top_uncertainty_count": len(context.get("top_uncertainties", [])),
    }


def _report(result: Dict[str, Any]) -> Dict[str, Any]:
    return dict(result.get("json_report") or {})


def _detailed_context(context: Dict[str, Any]) -> Dict[str, Any]:
    return dict(context.get("detailed") or {})


def _developer_context(context: Dict[str, Any]) -> Dict[str, Any]:
    return dict(context.get("developer") or {})


def _dedupe_strings(values: List[Any]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def build_fix_analysis(result: Dict[str, Any], mode: Optional[str]) -> Dict[str, Any]:
    effective_mode = str(mode or "").lower()
    if effective_mode != "detailed":
        return {}
    context = _context(result)
    detailed = _detailed_context(context)
    analysis = dict(detailed.get("fix_analysis") or {})
    return {
        "fix_status": analysis.get("fix_status", "no_fixed"),
        "highest_fixed_version": analysis.get("highest_fixed_version"),
        "all_fixed_versions": list(analysis.get("all_fixed_versions") or []),
    }


def build_license_sources(result: Dict[str, Any], mode: Optional[str]) -> List[Dict[str, Any]]:
    effective_mode = str(mode or "").lower()
    if effective_mode != "detailed":
        return []
    context = _context(result)
    detailed = _detailed_context(context)
    rows: List[Dict[str, Any]] = []
    for item in list(detailed.get("licenses") or []):
        rows.append(
            {
                "package": item.get("package"),
                "version": item.get("version"),
                "license": item.get("license"),
                "license_url": item.get("license_url"),
                "source_url": item.get("source_url"),
            }
        )
    return rows


def _direct_dependencies(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(report.get("direct_dependencies") or [])


def _has_registry_safe_version(version: str) -> bool:
    value = str(version or "").strip()
    if not value:
        return False
    return not any(token in value for token in ["<", ">", "=", "~", "!", ",", " ", "*"])


def build_registry_url(ecosystem: str, package: str, version: str) -> Optional[str]:
    ecosystem_value = str(ecosystem or "").strip().lower()
    package_value = str(package or "").strip()
    version_value = str(version or "").strip()
    safe_version = version_value if _has_registry_safe_version(version_value) else ""
    if not ecosystem_value or not package_value:
        return None

    try:
        if ecosystem_value == "pypi":
            return (
                f"https://pypi.org/project/{package_value}/{safe_version}/"
                if safe_version
                else f"https://pypi.org/project/{package_value}/"
            )
        if ecosystem_value == "npm":
            return (
                f"https://www.npmjs.com/package/{package_value}/v/{safe_version}"
                if safe_version
                else f"https://www.npmjs.com/package/{package_value}"
            )
        if ecosystem_value == "maven":
            if ":" not in package_value:
                return None
            group_id, artifact_id = package_value.split(":", 1)
            group_id = group_id.strip()
            artifact_id = artifact_id.strip()
            if not group_id or not artifact_id or not safe_version:
                return None
            return f"https://central.sonatype.com/artifact/{group_id}/{artifact_id}/{safe_version}"
        if ecosystem_value == "go":
            return (
                f"https://pkg.go.dev/{package_value}@{safe_version}"
                if safe_version
                else f"https://pkg.go.dev/{package_value}"
            )
        if ecosystem_value in {"crates.io", "cargo"}:
            return (
                f"https://crates.io/crates/{package_value}/{safe_version}"
                if safe_version
                else f"https://crates.io/crates/{package_value}"
            )
        if ecosystem_value == "rubygems":
            return (
                f"https://rubygems.org/gems/{package_value}/versions/{safe_version}"
                if safe_version
                else f"https://rubygems.org/gems/{package_value}"
            )
        if ecosystem_value == "nuget":
            return (
                f"https://www.nuget.org/packages/{package_value}/{safe_version}"
                if safe_version
                else f"https://www.nuget.org/packages/{package_value}"
            )
    except Exception:
        return None

    return None


def build_summary_cards(result: Dict[str, Any]) -> Dict[str, int]:
    report = _report(result)
    context = _context(result)
    summary = dict(context.get("scan_summary", {}) or {})
    vulnerability_research = dict(report.get("vulnerability_research", {}) or {})
    direct_dependencies = _direct_dependencies(report)
    cves_found = _dedupe_strings(list(vulnerability_research.get("cves_found") or []))

    exact_versions = int(
        summary.get("exact_versions")
        or sum(1 for item in direct_dependencies if str(item.get("version_kind") or "").lower() == "exact")
        or 0
    )

    return {
        "dependencies_discovered": int(report.get("total_packages") or summary.get("total_dependencies") or len(direct_dependencies) or 0),
        "exact_versions": exact_versions,
        "packages_checked": int(vulnerability_research.get("packages_checked_count") or summary.get("packages_checked_for_vulnerabilities") or 0),
        "unique_cves_found": len(cves_found),
    }


def build_dependencies_discovered_table(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    report = _report(result)
    rows: List[Dict[str, Any]] = []
    for item in _direct_dependencies(report):
        package = item.get("name")
        version = item.get("version")
        ecosystem = item.get("ecosystem")
        url = build_registry_url(str(ecosystem or ""), str(package or ""), str(version or ""))
        rows.append(
            {
                "package": package,
                "version": version,
                "version_kind": item.get("version_kind"),
                "ecosystem": ecosystem,
                "origin": {"label": "Registry", "url": url} if url else None,
                "source": item.get("source_type") or item.get("source"),
            }
        )
    return rows


def build_vulnerable_dependencies_table(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    report = _report(result)
    vulnerability_research = dict(report.get("vulnerability_research", {}) or {})
    rows: List[Dict[str, Any]] = []

    for item in list(vulnerability_research.get("packages_checked") or []):
        if int(item.get("vulnerability_count") or 0) <= 0:
            continue
        package_name = item.get("package_name") or item.get("package")
        version = item.get("version_checked") or item.get("version")
        default_severity = item.get("severity") or "unknown"
        advisories = list(item.get("advisory_summaries") or [])

        if advisories:
            for advisory in advisories:
                vulnerability_id = str(
                    advisory.get("id")
                    or next(iter(advisory.get("aliases") or []), "")
                ).strip()
                if not vulnerability_id:
                    continue
                references = [
                    ref for ref in list(advisory.get("references") or [])[:4]
                    if isinstance(ref, dict) and str(ref.get("url") or "").strip()
                ]
                summary = str(advisory.get("summary") or advisory.get("details") or "").strip()
                rows.append(
                    {
                        "package": package_name,
                        "version": version,
                        "severity": advisory.get("severity") or default_severity,
                        "vulnerability_id": vulnerability_id,
                        "alternate_ids": _dedupe_strings(list(advisory.get("alternate_ids") or [])),
                        "summary": summary,
                        "fixed_version": advisory.get("fixed_version"),
                        "references": references,
                        "primary_reference": advisory.get("primary_reference") or (references[0].get("url") if references else ""),
                    }
                )
            continue

        advisory_ids = _dedupe_strings(list(item.get("cve_ids") or []) + list(item.get("vulnerability_ids") or []))
        for vulnerability_id in advisory_ids:
            rows.append(
                {
                    "package": package_name,
                    "version": version,
                    "severity": default_severity,
                    "vulnerability_id": vulnerability_id,
                    "alternate_ids": [],
                    "summary": "",
                    "fixed_version": None,
                    "references": [],
                    "primary_reference": "",
                }
            )
    return rows


def build_license_compliance_table(result: Dict[str, Any], mode: Optional[str]) -> List[Dict[str, Any]]:
    effective_mode = str(mode or "").lower()
    if effective_mode not in {"detailed", "developer"}:
        return []

    report = _report(result)
    license_analysis = dict(report.get("license_analysis", {}) or {})
    rows: List[Dict[str, Any]] = []
    for item in list(license_analysis.get("findings") or []):
        rows.append(
            {
                "package": item.get("package_name"),
                "version": item.get("version"),
                "detected_license": item.get("license_expression") or ", ".join(item.get("license_ids") or []),
                "policy_status": item.get("policy_status"),
                "reason": item.get("reason"),
                "source_links": item.get("source_links") or [],
                "source": item.get("source"),
            }
        )
    logger.info("License compliance table rows: %s", len(rows))
    return rows


def build_dependency_graphs(result: Dict[str, Any], mode: Optional[str]) -> Dict[str, Any]:
    effective_mode = str(mode or "").lower()
    if effective_mode != "developer":
        return {}
    report = _report(result)
    dependency_graphs = report.get("dependency_graphs") or {}
    if not isinstance(dependency_graphs, dict):
        return {}
    return dependency_graphs


def _strip_backticks(text: str) -> str:
    return text.replace("`", "")


def _severity_title(value: Optional[str]) -> str:
    return str(value or "Unknown").strip().title()


def _detailed_grouped_vulnerabilities(context: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
    return list(_detailed_context(context).get("top_vulnerabilities_grouped") or [])[:limit]


def _developer_target_summary(context: Dict[str, Any], numbers: Dict[str, int], target: str) -> str:
    input_type = (context.get("input", {}) or {}).get("input_type")
    if input_type == "package":
        packages = _package_entries(context)
        if len(packages) == 1:
            package = packages[0]
            return (
                f"I analyzed {_package_label(package.get('package_name'), package.get('package_version'))}. "
                f"I found {_plural(numbers['cves'], 'confirmed vulnerability')} across the exact-version evidence returned."
            )
    if input_type == "dependency_file":
        source = (((context.get("dependency_discovery") or {}).get("sources") or [{}])[0]).get("source") or "the dependency file"
        return f"I analyzed `{source}` and found {_plural(numbers['cves'], 'confirmed vulnerability')} across {_plural(numbers['checked'], 'checked dependency')}."
    if input_type == "github_repo":
        repo_url = (context.get("input", {}) or {}).get("repo_url") or target
        return f"I analyzed `{repo_url}` and found {_plural(numbers['cves'], 'confirmed vulnerability')} across {_plural(numbers['checked'], 'checked dependency')}."
    return f"I analyzed {target} and found {_plural(numbers['cves'], 'confirmed vulnerability')}."


def _detailed_recommended_upgrade(context: Dict[str, Any]) -> Optional[str]:
    analysis = dict(_detailed_context(context).get("fix_analysis") or {})
    highest = analysis.get("highest_fixed_version")
    status = analysis.get("fix_status")
    if status == "all_fixed" and highest:
        return (
            f"Recommended upgrade: Upgrade to >= {highest}.\n"
            "This version includes fixes for all identified vulnerabilities, including those fixed in earlier versions."
        )
    if status == "partial_fixed" and highest:
        return (
            f"Recommended upgrade: Upgrade to >= {highest}.\n"
            "This upgrade should reduce risk and includes the known fixes, but some identified vulnerabilities do not yet have confirmed fixed versions."
        )
    if status == "no_fixed":
        return (
            "No fixed versions are currently available.\n"
            "Monitor the relevant advisories and apply temporary mitigations or dependency constraints until a fixed release is published."
        )
    return None


def _detailed_license_sections(context: Dict[str, Any], limit: int = 10) -> List[str]:
    rows: List[str] = []
    for item in list(_detailed_context(context).get("licenses") or [])[:limit]:
        header = f"{_package_label(item.get('package'), item.get('version'))}: {item.get('license') or 'Unknown'} ({item.get('license_type') or 'unclear'})"
        body = [
            f"Allows: {item.get('allows')}",
            f"Requires: {item.get('requires')}",
            f"Commercial use: {item.get('commercial_use')}",
            f"Advantages: {item.get('advantages')}",
            f"Limitations: {item.get('limitations')}",
        ]
        links = []
        if item.get("license_url"):
            links.append(f"license source: {item.get('license_url')}")
        if item.get("source_url"):
            links.append(f"repo/docs: {item.get('source_url')}")
        if links:
            body.append("Links: " + ", ".join(links))
        rows.append(header + "\n" + "\n".join(body))
    return rows


def _detailed_summary(context: Dict[str, Any], numbers: Dict[str, int], target: str) -> str:
    input_type = (context.get("input", {}) or {}).get("input_type")
    if input_type == "package":
        packages = _package_entries(context)
        if len(packages) == 1:
            package = packages[0]
            risk = _severity_title((((_detailed_grouped_vulnerabilities(context) or [{}])[0]).get("severity")))
            return f"Package: {package.get('package_name')} {package.get('package_version')} ({risk} risk). { _plural(numbers['cves'], 'confirmed vulnerability') } found."
    if input_type == "github_repo":
        repo_url = (context.get("input", {}) or {}).get("repo_url") or target
        return f"Repository scan: {repo_url}. { _plural(numbers['cves'], 'confirmed vulnerability') } found across { _plural(numbers['checked'], 'checked dependency') }."
    if input_type == "dependency_file":
        source = (((context.get('dependency_discovery') or {}).get('sources') or [{}])[0]).get("source") or "dependency file"
        return f"Dependency file scan: {source}. { _plural(numbers['cves'], 'confirmed vulnerability') } found across { _plural(numbers['checked'], 'checked dependency') }."
    return f"Detailed analysis for {target}. { _plural(numbers['cves'], 'confirmed vulnerability') } found."


def _detailed_vulnerability_sections(context: Dict[str, Any], limit: int = 5) -> List[str]:
    grouped = _detailed_grouped_vulnerabilities(context, limit)
    if not grouped:
        return []
    sections: List[str] = []
    single_package = len(grouped) == 1
    for item in grouped:
        package = str(item.get("package") or "package").strip()
        version = str(item.get("version") or "").strip()
        severity = _severity_title(item.get("severity"))
        vulnerabilities = list(item.get("vulnerabilities") or [])
        if single_package:
            lines = [f"Package: {package}{f' {version}' if version else ''} ({severity} risk)", "", "Top vulnerabilities:"]
        else:
            lines = [f"{package}{f' {version}' if version else ''} ({severity}):"]
        for vuln in vulnerabilities:
            summary = str(vuln.get("summary") or "").strip()
            line = f"- {vuln.get('id')}"
            if summary:
                line += f" -> {summary}"
            lines.append(line)
        sections.append("\n".join(lines))
    return sections


def _developer_engineering_sections(context: Dict[str, Any], limit: int = 5) -> List[str]:
    developer = _developer_context(context)
    sections: List[str] = []
    for item in list(developer.get("upgrade_priority") or [])[:limit]:
        relationship = str(item.get("relationship") or "unknown").lower()
        line = (
            f"{item.get('package')} {item.get('version')}: "
            f"{_plural(int(item.get('vulnerability_count') or 0), 'confirmed finding')}, "
            f"severity {_severity_text(item.get('severity')) or 'unknown'}, "
            f"{relationship} dependency."
        )
        sections.append(line)
    return sections


def format_chat_response(result: Dict[str, Any], mode: Optional[str]) -> str:
    context = _context(result)
    numbers = _summary_numbers(context)
    target = _target_phrase(context)
    result_type = _result_type(context)
    findings = context.get("top_findings", [])
    vulnerability_details = context.get("vulnerability_details", [])
    metadata = context.get("important_metadata", [])
    next_steps = context.get("recommended_next_steps", [])
    effective_mode = (mode or context.get("input", {}).get("mode") or "fast").lower()
    no_confirmed = _no_vulnerability_message(numbers)
    uncertainty = _uncertainty_summary(context)
    finding_lines = _finding_lines(findings)
    metadata_sentence = _metadata_sentence(metadata)
    vulnerability_lines = _vulnerability_lines(vulnerability_details, include_meaning=effective_mode != "fast")
    remediation_lines = _remediation_lines(vulnerability_details)

    if result_type == "discovery_only":
        return _discovery_only_message(context, target)

    if effective_mode == "fast":
        if (
            (context.get("input", {}) or {}).get("input_type") == "github_repo"
            and numbers["cves"] == 0
        ):
            return _fast_repo_no_vuln_summary(context, numbers)
        parts = [_fast_intro(context, target, numbers)]
        dependency_preview = _dependency_preview_line(context)
        top_affected = _top_affected_summary(context)
        cve_lines = _top_cve_lines(context, 3)
        if dependency_preview:
            parts.append(dependency_preview)
        elif numbers["total"] > 15 and top_affected:
            parts.append(top_affected)
        fast_findings = _fast_finding_lines(findings, 3)
        if fast_findings:
            parts.append("Top findings:\n" + _bullet(fast_findings, 3))
        if cve_lines:
            parts.append("Top CVEs:\n" + _bullet(cve_lines, 3))
        limitation = _fast_limitation(context)
        if limitation:
            parts.append(limitation)
        if next_steps:
            parts.append("Next step: " + str(next_steps[0]))
        return "\n\n".join(parts)

    if effective_mode == "detailed":
        grouped_sections = _detailed_vulnerability_sections(context, 5)
        detailed_upgrade = _detailed_recommended_upgrade(context)
        detailed_license = _detailed_license_sections(context, 10)
        parts = [
            f"Detailed review for {target}.",
            "Summary:\n" + _detailed_summary(context, numbers, target),
            "Security:\n"
            + f"{no_confirmed} {_plural(numbers['checked'], 'exact-version dependency')} were checked with exact-version vulnerability evidence.",
        ]
        if grouped_sections:
            parts.append("Top Vulnerabilities:\n" + "\n\n".join(grouped_sections))
        elif vulnerability_lines:
            parts.append("Top Vulnerabilities:\n" + _bullet(vulnerability_lines, 4))
        if detailed_upgrade:
            parts.append("Recommended Upgrade:\n" + detailed_upgrade)
        if detailed_license:
            parts.append("License Analysis:\n" + "\n\n".join(f"- {section}" for section in detailed_license))
        unresolved_note = _detailed_unresolved_note(context)
        if next_steps:
            parts.append("Developer Guidance:\n" + _bullet([str(item) for item in next_steps], 4))
        if uncertainty or unresolved_note:
            parts.append("Confidence / Limitations:\n" + " ".join(part for part in [uncertainty, unresolved_note] if part))
        message = "\n\n".join(parts)
        return _strip_backticks(message)

    engineering_sections = _developer_engineering_sections(context, 5)
    parts = [
        f"Developer analysis for {target}.",
        "Summary:\n" + _developer_target_summary(context, numbers, target),
        (
            "Dependency quality:\n"
            f"{_plural(numbers['exact'], 'exact-version dependency')}, "
            f"{_plural(numbers['range'], 'range-based dependency')}, and "
            f"{_plural(numbers['unknown'], 'unknown-version dependency')}."
        ),
        "Security status:\n" + no_confirmed,
    ]
    if engineering_sections:
        parts.append("Upgrade priority:\n" + _bullet(engineering_sections, 5))
    if remediation_lines:
        parts.append("Remediation order:\n" + _bullet(remediation_lines, 5))
    if uncertainty:
        parts.append("Confidence / Limitations:\n" + uncertainty)
    if metadata_sentence:
        parts.append("Package context:\n" + metadata_sentence)
    if next_steps:
        parts.append("Developer Guidance:\n" + _bullet([str(item) for item in next_steps], 5))
    message = "\n\n".join(parts)
    return _strip_backticks(message)
