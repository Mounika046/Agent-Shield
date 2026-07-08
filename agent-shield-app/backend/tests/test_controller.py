import unittest
import json
from unittest.mock import patch

from app.controller import handle_chat_request


class FakeLLM:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def complete(self, *, system_prompt, user_payload):
        self.calls.append({"system_prompt": system_prompt, "user_payload": user_payload})
        value = self.outputs.pop(0)
        if isinstance(value, dict):
            return json.dumps(value)
        return value


def fake_scan_executor(**payload):
    mode = payload.get("mode") or "fast"
    input_type = "github_repo" if payload.get("repo_url") else "dependency_file" if payload.get("file_name") else "package"
    packages_scanned = []
    dependency_preview = {"count": 3, "can_list_all": True, "preview": ["requests==2.31.0", "urllib3>=1.26,<3", "idna==3.7"]}
    if input_type == "package":
        package_items = payload.get("packages") or []
        packages_scanned = [
            {
                "package_name": item.get("package_name"),
                "package_version": item.get("package_version"),
                "ecosystem": item.get("ecosystem"),
            }
            for item in package_items
        ] or [{
            "package_name": payload.get("package_name"),
            "package_version": payload.get("package_version"),
            "ecosystem": payload.get("ecosystem"),
        }]
    return {
        "summary": "fake summary",
        "json_report": {
            "total_packages": 3,
            "direct_dependencies": [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "version_kind": "exact",
                    "ecosystem": "PyPI",
                    "source_type": "direct_package",
                },
                {
                    "name": "urllib3",
                    "version": ">=1.26,<3",
                    "version_kind": "range",
                    "ecosystem": "PyPI",
                    "source_type": "direct_package",
                },
                {
                    "name": "idna",
                    "version": "3.7",
                    "version_kind": "exact",
                    "ecosystem": "PyPI",
                    "source_type": "direct_package",
                },
            ],
            "vulnerability_research": {
                "packages_checked_count": 2,
                "packages_checked": [
                    {
                        "package_name": "requests",
                        "version_checked": "2.31.0",
                        "vulnerability_count": 1,
                        "cve_ids": ["CVE-TEST-1"],
                        "vulnerability_ids": ["GHSA-test-1"],
                        "severity": "high",
                        "warnings": [],
                    },
                    {
                        "package_name": "idna",
                        "version_checked": "3.7",
                        "vulnerability_count": 0,
                        "cve_ids": [],
                        "vulnerability_ids": [],
                        "severity": None,
                        "warnings": [],
                    },
                ],
                "cves_found": ["CVE-TEST-1"],
                "skipped_packages": [],
                "warnings": [],
                "errors": [],
            },
            "license_analysis": {
                "findings": [
                    {
                        "package_name": "requests",
                        "version": "2.31.0",
                        "ecosystem": "PyPI",
                        "license_expression": "Apache-2.0",
                        "license_ids": ["Apache-2.0"],
                        "source": "deps.dev",
                        "policy_status": "allowed",
                        "reason": "permissive",
                    }
                ]
            },
            "dependency_graphs": {
                "requests@2.31.0": {
                    "package": "requests",
                    "version": "2.31.0",
                    "ecosystem": "PyPI",
                    "dependencies": [
                        {"name": "urllib3", "version": "1.26.18"},
                        {"name": "charset-normalizer", "version": "3.3.2"},
                    ],
                    "dependency_count": 2,
                    "truncated": False,
                    "source": "deps.dev",
                }
            },
            "llm_context": {
                "input": {
                    "input_type": input_type,
                    "mode": mode,
                    "repo_url": payload.get("repo_url"),
                    "language": "python",
                    "dependency_summary": dependency_preview,
                    "packages_scanned": packages_scanned,
                    "route": {"mode_source": "explicit" if payload.get("mode") else "inferred"},
                },
                "scan_summary": {
                    "total_dependencies": 3,
                    "exact_versions": 2,
                    "range_versions": 1,
                    "unknown_versions": 0,
                    "packages_checked_for_vulnerabilities": 2,
                    "packages_skipped_for_exact_matching": 1,
                    "cves_found": 1,
                },
                "top_findings": [
                    {
                        "package": "requests",
                        "version": "2.31.0",
                        "vulnerability_count": 1,
                        "cve_ids": ["CVE-TEST-1"],
                        "severity": "high",
                        "relationship": "direct",
                    }
                ],
                "vulnerability_details": [
                    {
                        "package": "requests",
                        "version": "2.31.0",
                        "ecosystem": "PyPI",
                        "severity": "high",
                        "match_confidence": "exact",
                        "relationship": "direct",
                        "source_type": "direct_package",
                        "file_path": "requirements.txt",
                        "vulnerability_count": 1,
                        "cve_ids": ["CVE-TEST-1"],
                        "vulnerability_ids": ["GHSA-test-1"],
                        "advisories": [
                            {
                                "id": "GHSA-test-1",
                                "aliases": ["CVE-TEST-1"],
                                "severity": "high",
                                "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                                "details": None,
                            }
                        ],
                        "recommended_fix": "Upgrade this package to a non-vulnerable version and re-run the scan to confirm the advisory no longer matches.",
                        "priority_reason": "Prioritized because this is an exact-version vulnerable dependency.",
                        "dependent_impact_note": "This is a direct dependency, so anything that imports or relies on it may inherit the risk until it is upgraded.",
                    }
                ],
                "top_cves": [
                    {
                        "package": "requests",
                        "version": "2.31.0",
                        "id": "CVE-TEST-1",
                        "severity": "high",
                        "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                        "match_confidence": "exact",
                        "relationship": "direct",
                    }
                ],
                "vulnerable_package_summary": {"count": 1, "packages": ["requests"]},
                "package_analysis": {
                    "exact_packages_total": 2,
                    "packages_with_metadata": 1,
                    "packages_with_vulnerabilities": 1,
                    "packages": [
                        {
                            "name": "requests",
                            "version": "2.31.0",
                            "ecosystem": "PyPI",
                            "relationship": "direct",
                            "source_type": "direct_package",
                            "source": "requirements.txt",
                            "file_path": "requirements.txt",
                            "match_confidence": "exact",
                            "vulnerability_count": 1,
                            "severity": "high",
                            "identifiers": ["CVE-TEST-1"],
                            "vulnerability_explanations": [
                                "Improper certificate verification could allow a man-in-the-middle attack."
                            ],
                            "recommended_fix": "Upgrade this package to a non-vulnerable version and re-run the scan to confirm the advisory no longer matches.",
                            "metadata_available": True,
                            "metadata_visibility": "good",
                            "licenses": ["Apache-2.0"],
                            "license_category": "permissive",
                            "open_source_signal": "yes",
                            "license_interpretation": "This appears to be a permissive open-source license.",
                            "commercial_use_note": "This license type is commonly used in commercial software, but you should still review your own legal and compliance requirements.",
                            "trust_notes": [
                                "deps.dev lists 1 advisory for this version.",
                                "Source or documentation links are available in the package metadata.",
                            ],
                            "links": [
                                {"label": "source", "url": "https://github.com/psf/requests"},
                                {"label": "homepage", "url": "https://requests.readthedocs.io/"},
                            ],
                        }
                    ],
                    "unresolved_packages": [
                        {
                            "name": "urllib3",
                            "version": ">=1.26,<3",
                            "version_kind": "range",
                            "ecosystem": "PyPI",
                            "source": "requirements.txt",
                            "reason": "non_exact_version",
                            "note": "Exact-version vulnerability or metadata enrichment was skipped because the package version is unresolved.",
                        }
                    ],
                },
                "top_uncertainties": [
                    {
                        "package": "urllib3",
                        "version": ">=1.26,<3",
                        "reason": "non_exact_version",
                    }
                    for _ in range(12)
                ],
                "important_metadata": [{
                    "provider": "deps.dev",
                    "status": "success",
                    "packages_enriched": 1,
                    "packages_skipped": 1,
                    "packages_with_links": 1,
                    "packages_with_license_data": 1,
                }],
                "top_vulnerabilities_grouped": [
                    {
                        "package": "requests",
                        "version": "2.31.0",
                        "severity": "high",
                        "vulnerabilities": [
                            {
                                "id": "CVE-TEST-1",
                                "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                                "fixed_version": "2.32.0",
                                "references": ["https://osv.dev/vulnerability/GHSA-test-1"],
                            }
                        ],
                    }
                ],
                "developer": {
                    "mode": "developer",
                    "dependency_graphs": [
                        {
                            "package": "requests",
                            "version": "2.31.0",
                            "dependency_count": 2,
                            "truncated": False,
                        }
                    ],
                    "dependency_quality": {
                        "exact_versions": 2,
                        "range_versions": 1,
                        "unknown_versions": 0,
                        "packages_checked_for_vulnerabilities": 2,
                    },
                    "upgrade_priority": [
                        {
                            "package": "requests",
                            "version": "2.31.0",
                            "severity": "high",
                            "relationship": "direct",
                            "vulnerability_count": 1,
                        }
                    ],
                    "blockers": [{"package": "urllib3", "version": ">=1.26,<3", "reason": "non_exact_version"}],
                    "recommended_next_steps": ["Pin dependencies with exact versions."],
                    "package_fixed_versions": [{"package": "requests", "fixed_versions": ["2.32.0"]}],
                },
                "detailed": {
                    "mode": "detailed",
                    "top_vulnerabilities_grouped": [
                        {
                            "package": "requests",
                            "version": "2.31.0",
                            "severity": "high",
                            "vulnerabilities": [
                                {
                                    "id": "CVE-TEST-1",
                                    "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                                    "fixed_version": "2.32.0",
                                    "references": ["https://osv.dev/vulnerability/GHSA-test-1"],
                                }
                            ],
                        }
                    ],
                    "package_fixed_versions": [{"package": "requests", "fixed_versions": ["2.32.0"]}],
                    "fix_analysis": {
                        "fix_status": "all_fixed",
                        "highest_fixed_version": "2.32.0",
                        "all_fixed_versions": ["2.32.0"],
                    },
                    "licenses": [
                        {
                            "package": "requests",
                            "version": "2.31.0",
                            "license": "Apache-2.0",
                            "license_type": "permissive",
                            "allows": "Modification, redistribution, and commercial use are generally allowed.",
                            "requires": "Retain the license notice, attribution, and disclaimer text.",
                            "commercial_use": "This license type is commonly used in commercial software, but you should still review your own legal and compliance requirements.",
                            "advantages": "Flexible for internal and commercial use with low operational friction.",
                            "limitations": "Attribution and notice retention still matter, and there is typically no warranty.",
                            "license_url": None,
                            "source_url": "https://github.com/psf/requests",
                        }
                    ],
                },
                "recommended_next_steps": ["Pin dependencies with exact versions."],
            }
        },
    }


def fake_file_scan_executor(**payload):
    mode = payload.get("mode") or "fast"
    preview = [
        "requests==2.31.0",
        "flask==2.3.3",
        "jinja2==3.1.4",
    ]
    return {
        "summary": "file summary",
        "json_report": {
            "total_packages": 3,
            "direct_dependencies": [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "version_kind": "exact",
                    "ecosystem": "PyPI",
                    "source_type": "uploaded_file",
                },
                {
                    "name": "flask",
                    "version": "2.3.3",
                    "version_kind": "exact",
                    "ecosystem": "PyPI",
                    "source_type": "uploaded_file",
                },
                {
                    "name": "jinja2",
                    "version": "3.1.4",
                    "version_kind": "exact",
                    "ecosystem": "PyPI",
                    "source_type": "uploaded_file",
                },
            ],
            "vulnerability_research": {
                "packages_checked_count": 3,
                "packages_checked": [
                    {
                        "package_name": "requests",
                        "version_checked": "2.31.0",
                        "vulnerability_count": 1,
                        "cve_ids": ["CVE-TEST-1"],
                        "vulnerability_ids": ["GHSA-test-1"],
                        "severity": "high",
                        "warnings": [],
                    }
                ],
                "cves_found": ["CVE-TEST-1"],
                "skipped_packages": [],
                "warnings": [],
                "errors": [],
            },
            "license_analysis": {
                "findings": [
                    {
                        "package_name": "requests",
                        "version": "2.31.0",
                        "ecosystem": "PyPI",
                        "license_expression": "Apache-2.0",
                        "license_ids": ["Apache-2.0"],
                        "source": "deps.dev",
                        "policy_status": "allowed",
                        "reason": "permissive",
                    }
                ]
            },
            "llm_context": {
                "input": {
                    "input_type": "dependency_file",
                    "mode": mode,
                    "repo_url": None,
                    "language": "python",
                    "dependency_summary": {"count": 3, "can_list_all": True, "preview": preview},
                    "packages_scanned": [],
                    "route": {"mode_source": "explicit" if payload.get("mode") else "inferred"},
                },
                "scan_summary": {
                    "total_dependencies": 3,
                    "exact_versions": 3,
                    "range_versions": 0,
                    "unknown_versions": 0,
                    "packages_checked_for_vulnerabilities": 3,
                    "packages_skipped_for_exact_matching": 0,
                    "cves_found": 1,
                },
                "dependency_discovery": {"sources": [{"source": "requirements.txt", "packages": ["requests", "flask", "jinja2"], "package_count": 3}]},
                "top_findings": [{"package": "requests", "version": "2.31.0", "vulnerability_count": 1, "cve_ids": ["CVE-TEST-1"], "severity": "high", "relationship": "direct"}],
                "vulnerability_details": [{
                    "package": "requests",
                    "version": "2.31.0",
                    "ecosystem": "PyPI",
                    "severity": "high",
                    "match_confidence": "exact",
                    "relationship": "direct",
                    "source_type": "uploaded_file",
                    "file_path": "requirements.txt",
                    "vulnerability_count": 1,
                    "cve_ids": ["CVE-TEST-1"],
                    "vulnerability_ids": ["GHSA-test-1"],
                    "advisories": [{"id": "GHSA-test-1", "aliases": ["CVE-TEST-1"], "severity": "high", "summary": "Improper certificate verification could allow a man-in-the-middle attack.", "details": None}],
                    "recommended_fix": "Upgrade this package to a non-vulnerable version and re-run the scan to confirm the advisory no longer matches.",
                    "priority_reason": "Prioritized because this is an exact-version vulnerable dependency.",
                    "dependent_impact_note": None,
                }],
                "top_cves": [{"package": "requests", "version": "2.31.0", "id": "CVE-TEST-1", "severity": "high", "summary": "Improper certificate verification could allow a man-in-the-middle attack.", "match_confidence": "exact", "relationship": "direct"}],
                "vulnerable_package_summary": {"count": 1, "packages": ["requests"]},
                "package_analysis": {
                    "exact_packages_total": 3,
                    "packages_with_metadata": 2,
                    "packages_with_vulnerabilities": 1,
                    "packages": [
                        {
                            "name": "requests",
                            "version": "2.31.0",
                            "ecosystem": "PyPI",
                            "relationship": "direct",
                            "source_type": "uploaded_file",
                            "source": "requirements.txt",
                            "file_path": "requirements.txt",
                            "match_confidence": "exact",
                            "vulnerability_count": 1,
                            "severity": "high",
                            "identifiers": ["CVE-TEST-1"],
                            "vulnerability_explanations": ["Improper certificate verification could allow a man-in-the-middle attack."],
                            "recommended_fix": "Upgrade this package to a non-vulnerable version and re-run the scan to confirm the advisory no longer matches.",
                            "metadata_available": True,
                            "metadata_visibility": "good",
                            "licenses": ["Apache-2.0"],
                            "license_category": "permissive",
                            "open_source_signal": "yes",
                            "license_interpretation": "This appears to be a permissive open-source license.",
                            "commercial_use_note": "This license type is commonly used in commercial software, but you should still review your own legal and compliance requirements.",
                            "trust_notes": ["Source or documentation links are available in the package metadata."],
                            "links": [{"label": "source", "url": "https://github.com/psf/requests"}],
                        },
                        {
                            "name": "flask",
                            "version": "2.3.3",
                            "ecosystem": "PyPI",
                            "relationship": "direct",
                            "source_type": "uploaded_file",
                            "source": "requirements.txt",
                            "file_path": "requirements.txt",
                            "match_confidence": "exact",
                            "vulnerability_count": 0,
                            "severity": None,
                            "identifiers": [],
                            "vulnerability_explanations": [],
                            "recommended_fix": None,
                            "metadata_available": True,
                            "metadata_visibility": "limited",
                            "licenses": ["BSD-3-Clause"],
                            "license_category": "permissive",
                            "open_source_signal": "yes",
                            "license_interpretation": "This appears to be a permissive open-source license.",
                            "commercial_use_note": "This license type is commonly used in commercial software, but you should still review your own legal and compliance requirements.",
                            "trust_notes": ["Package metadata is present, but useful source or documentation links are limited."],
                            "links": [],
                        },
                    ],
                    "unresolved_packages": [],
                },
                "top_uncertainties": [],
                "important_metadata": [],
                "recommended_next_steps": ["Upgrade requests and re-run the scan."],
            }
        },
    }


def fake_large_repo_scan_executor(**payload):
    mode = payload.get("mode") or "fast"
    return {
        "summary": "repo summary",
        "json_report": {
            "llm_context": {
                "input": {
                    "input_type": "github_repo",
                    "mode": mode,
                    "repo_url": payload.get("repo_url") or "https://github.com/example/repo",
                    "language": "python",
                    "dependency_summary": {"count": 26, "can_list_all": False, "preview": []},
                    "packages_scanned": [],
                    "route": {"mode_source": "explicit" if payload.get("mode") else "inferred"},
                },
                "scan_summary": {
                    "total_dependencies": 26,
                    "exact_versions": 20,
                    "range_versions": 4,
                    "unknown_versions": 2,
                    "packages_checked_for_vulnerabilities": 20,
                    "packages_skipped_for_exact_matching": 6,
                    "cves_found": 5,
                },
                "top_findings": [
                    {"package": "requests", "version": "2.31.0", "vulnerability_count": 3, "cve_ids": ["CVE-1", "CVE-2", "CVE-3"], "severity": "high", "relationship": "direct"},
                    {"package": "urllib3", "version": "1.26.18", "vulnerability_count": 2, "cve_ids": ["CVE-4", "CVE-5"], "severity": "medium", "relationship": "direct"},
                ],
                "vulnerability_details": [
                    {"package": "requests", "version": "2.31.0", "ecosystem": "PyPI", "severity": "high", "match_confidence": "exact", "relationship": "direct", "source_type": "github_file", "file_path": "requirements.txt", "vulnerability_count": 3, "cve_ids": ["CVE-1", "CVE-2", "CVE-3"], "vulnerability_ids": ["GHSA-1"], "advisories": [{"id": "CVE-1", "aliases": ["CVE-1"], "severity": "high", "summary": "Credential leak risk.", "details": None}], "recommended_fix": "Upgrade this package to a non-vulnerable version and re-run the scan to confirm the advisory no longer matches.", "priority_reason": "", "dependent_impact_note": None},
                    {"package": "urllib3", "version": "1.26.18", "ecosystem": "PyPI", "severity": "medium", "match_confidence": "exact", "relationship": "direct", "source_type": "github_file", "file_path": "requirements.txt", "vulnerability_count": 2, "cve_ids": ["CVE-4", "CVE-5"], "vulnerability_ids": ["GHSA-2"], "advisories": [{"id": "CVE-4", "aliases": ["CVE-4"], "severity": "medium", "summary": "Request smuggling risk.", "details": None}], "recommended_fix": "Upgrade this package to a non-vulnerable version and re-run the scan to confirm the advisory no longer matches.", "priority_reason": "", "dependent_impact_note": None},
                ],
                "top_cves": [
                    {"package": "requests", "version": "2.31.0", "id": "CVE-1", "severity": "high", "summary": "Credential leak risk.", "match_confidence": "exact", "relationship": "direct"},
                    {"package": "requests", "version": "2.31.0", "id": "CVE-2", "severity": "high", "summary": "Header injection risk.", "match_confidence": "exact", "relationship": "direct"},
                    {"package": "urllib3", "version": "1.26.18", "id": "CVE-4", "severity": "medium", "summary": "Request smuggling risk.", "match_confidence": "exact", "relationship": "direct"},
                ],
                "vulnerable_package_summary": {"count": 2, "packages": ["requests", "urllib3"]},
                "package_analysis": {
                    "exact_packages_total": 20,
                    "packages_with_metadata": 2,
                    "packages_with_vulnerabilities": 2,
                    "packages": [
                        {
                            "name": "requests",
                            "version": "2.31.0",
                            "ecosystem": "PyPI",
                            "relationship": "direct",
                            "source_type": "github_file",
                            "source": "requirements.txt",
                            "file_path": "requirements.txt",
                            "match_confidence": "exact",
                            "vulnerability_count": 3,
                            "severity": "high",
                            "identifiers": ["CVE-1", "CVE-2", "CVE-3"],
                            "vulnerability_explanations": ["Credential leak risk."],
                            "recommended_fix": "Upgrade this package to a non-vulnerable version and re-run the scan to confirm the advisory no longer matches.",
                            "metadata_available": True,
                            "metadata_visibility": "good",
                            "licenses": ["Apache-2.0"],
                            "license_category": "permissive",
                            "open_source_signal": "yes",
                            "license_interpretation": "This appears to be a permissive open-source license.",
                            "commercial_use_note": "This license type is commonly used in commercial software, but you should still review your own legal and compliance requirements.",
                            "trust_notes": ["Source or documentation links are available in the package metadata."],
                            "links": [{"label": "source", "url": "https://github.com/psf/requests"}],
                        },
                        {
                            "name": "urllib3",
                            "version": "1.26.18",
                            "ecosystem": "PyPI",
                            "relationship": "direct",
                            "source_type": "github_file",
                            "source": "requirements.txt",
                            "file_path": "requirements.txt",
                            "match_confidence": "exact",
                            "vulnerability_count": 2,
                            "severity": "medium",
                            "identifiers": ["CVE-4", "CVE-5"],
                            "vulnerability_explanations": ["Request smuggling risk."],
                            "recommended_fix": "Upgrade this package to a non-vulnerable version and re-run the scan to confirm the advisory no longer matches.",
                            "metadata_available": True,
                            "metadata_visibility": "limited",
                            "licenses": ["MIT"],
                            "license_category": "permissive",
                            "open_source_signal": "yes",
                            "license_interpretation": "This appears to be a permissive open-source license.",
                            "commercial_use_note": "This license type is commonly used in commercial software, but you should still review your own legal and compliance requirements.",
                            "trust_notes": ["Package metadata is present, but useful source or documentation links are limited."],
                            "links": [],
                        },
                    ],
                    "unresolved_packages": [
                        {
                            "name": "fastapi",
                            "version": ">=0.100,<1",
                            "version_kind": "range",
                            "ecosystem": "PyPI",
                            "source": "requirements.txt",
                            "reason": "non_exact_version",
                            "note": "Exact-version vulnerability or metadata enrichment was skipped because the package version is unresolved.",
                        }
                    ],
                },
                "top_uncertainties": [{"package": "fastapi", "version": ">=0.100,<1", "reason": "non_exact_version"}],
                "important_metadata": [],
                "recommended_next_steps": ["Upgrade the vulnerable packages and regenerate the lockfile."],
            }
        },
    }


def fake_repo_no_vuln_partial_executor(**payload):
    mode = payload.get("mode") or "fast"
    return {
        "summary": "repo no-vuln summary",
        "json_report": {
            "llm_context": {
                "input": {
                    "input_type": "github_repo",
                    "mode": mode,
                    "repo_url": payload.get("repo_url") or "https://github.com/hashicorp/terraform",
                    "language": "go",
                    "dependency_summary": {"count": 332, "can_list_all": False, "preview": []},
                    "packages_scanned": [],
                    "route": {"mode_source": "explicit" if payload.get("mode") else "inferred"},
                },
                "provider_summary": {
                    "scan_source": {
                        "source": "github_sbom",
                        "label": "GitHub SBOM",
                        "details": "Dependencies were acquired from GitHub SBOM.",
                    },
                    "dependency_sources": {"github_sbom": 332},
                    "ecosystems": {"Go": 260, "unknown": 72},
                    "sbom_notes": ["72 SBOM dependencies had unknown ecosystem or version quality."],
                },
                "scan_summary": {
                    "total_dependencies": 332,
                    "exact_versions": 19,
                    "range_versions": 41,
                    "unknown_versions": 272,
                    "packages_checked_for_vulnerabilities": 19,
                    "packages_skipped_for_exact_matching": 313,
                    "cves_found": 0,
                },
                "top_findings": [],
                "vulnerability_details": [],
                "top_cves": [],
                "vulnerable_package_summary": {"count": 0, "packages": []},
                "dependency_discovery": {
                    "checked_examples": [
                        {"name": "github.com/hashicorp/go-version", "version": "1.6.0", "ecosystem": "Go"},
                        {"name": "github.com/hashicorp/hcl", "version": "1.0.0", "ecosystem": "Go"},
                    ],
                    "unresolved_examples": [
                        {"name": "github.com/modern-go/concurrent", "version": "", "version_kind": "unknown", "ecosystem": "Go"},
                        {"name": "github.com/zclconf/go-cty", "version": ">=1.0", "version_kind": "range", "ecosystem": "Go"},
                    ],
                    "unresolved_dependencies": [],
                    "sources": [],
                },
                "top_uncertainties": [
                    {"package": "github.com/modern-go/concurrent", "version": "", "version_kind": "unknown", "provider": "github_sbom", "reason": "missing_version"},
                    {"package": "github.com/zclconf/go-cty", "version": ">=1.0", "version_kind": "range", "provider": "github_sbom", "reason": "non_exact_version"},
                ],
                "important_metadata": [],
                "recommended_next_steps": ["Re-scan using a fully resolved dependency source such as go.sum or a more precise SBOM."],
            }
        },
    }


def fake_discovery_only_scan_executor(**payload):
    return {
        "summary": "discovery-only summary",
        "json_report": {
            "llm_context": {
                "input": {
                    "input_type": "dependency_file",
                    "mode": payload.get("mode") or "fast",
                    "result_type": "discovery_only",
                    "repo_url": None,
                    "language": "python",
                    "route": {"mode_source": "explicit" if payload.get("mode") else "inferred"},
                },
                "scan_summary": {
                    "total_dependencies": 4,
                    "exact_versions": 0,
                    "range_versions": 0,
                    "unknown_versions": 4,
                    "result_type": "discovery_only",
                    "analysis_blocked_reason": "missing_versions_in_file",
                    "packages_checked_for_vulnerabilities": 0,
                    "packages_skipped_for_exact_matching": 0,
                    "cves_found": 0,
                },
                "dependency_discovery": {
                    "sources": [
                        {
                            "source": "requirements.txt",
                            "packages": ["oci-openai", "python-dotenv", "fastapi", "uvicorn"],
                            "package_count": 4,
                        }
                    ],
                    "unresolved_dependencies": [
                        {"name": "oci-openai", "source": "requirements.txt", "version_kind": "unknown"}
                    ],
                },
                "top_findings": [],
                "vulnerability_details": [],
                "top_uncertainties": [
                    {"package": "oci-openai", "version": "", "version_kind": "unknown", "provider": "uploaded_file", "reason": "missing_version"}
                ],
                "important_metadata": [],
                "recommended_next_steps": ["Provide pinned versions or a lockfile."],
            }
        },
    }


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.llm_patcher = patch(
            "app.controller.chat_controller.get_default_llm_with_status",
            return_value=(
                None,
                {
                    "llm_available": False,
                    "llm_fallback_reason": None,
                },
            ),
        )
        self.llm_patcher.start()

    def tearDown(self):
        self.llm_patcher.stop()

    def test_explicit_mode_respected_and_token_passed(self):
        response = handle_chat_request(
            message="developer scan this private repo",
            repo_url="https://github.com/example/repo",
            token="ghp_secret",
            mode="developer",
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(response["mode"], "developer")
        self.assertEqual(response["mode_source"], "explicit")
        self.assertEqual(response["backend_payload"]["token"], "***redacted***")

    def test_inferred_mode_for_repo_security_request(self):
        response = handle_chat_request(
            message="scan this repo for vulnerabilities https://github.com/example/repo",
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(response["backend_payload"]["mode"], "fast")
        self.assertEqual(response["mode_source"], "inferred")

    def test_single_package_direct_input_still_works(self):
        response = handle_chat_request(
            message="scan requests 2.31.0 on PyPI",
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(len(response["backend_payload"]["packages"]), 1)
        self.assertEqual(response["backend_payload"]["package_name"], "requests")
        self.assertEqual(response["backend_payload"]["ecosystem"], "PyPI")

    def test_clarifies_package_without_version(self):
        response = handle_chat_request(
            message="check requests",
            scan_executor=fake_scan_executor,
        )

        self.assertFalse(response["backend_called"])
        self.assertEqual(response["status"], "needs_clarification")
        self.assertIn("exact version", response["message"])
        self.assertIsNone(response["backend_payload"])
        self.assertIsNone(response["mode"])
        self.assertIsNone(response["mode_source"])
        self.assertEqual(response["response_meta"]["clarification_builder"], "shared")
        self.assertFalse(response["response_meta"]["llm_input_stage"])
        self.assertFalse(response["response_meta"]["llm_output_stage"])

    def test_clarifies_package_without_ecosystem(self):
        response = handle_chat_request(
            message="check requests vulnerabilities",
            package_name="requests",
            package_version="2.31.0",
            scan_executor=fake_scan_executor,
        )

        self.assertFalse(response["backend_called"])
        self.assertIn("ecosystem", response["message"].lower())

    def test_multi_package_structured_request_executes(self):
        response = handle_chat_request(
            message="scan these packages",
            packages=[
                {"package_name": "transformers", "package_version": "4.35.2", "ecosystem": "PyPI"},
                {"package_name": "compromise", "package_version": "14.12.0", "ecosystem": "npm"},
            ],
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(len(response["backend_payload"]["packages"]), 2)
        self.assertIsNone(response["backend_payload"]["package_name"])
        self.assertEqual(response["mode"], "fast")

    def test_multi_package_natural_language_request_executes(self):
        response = handle_chat_request(
            message="check transformers 4.35.2 python package and compromise 14.12.0 javascript package",
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(response["input_type"], "package")
        self.assertEqual(len(response["backend_payload"]["packages"]), 2)
        self.assertEqual(response["backend_payload"]["packages"][0]["ecosystem"], "PyPI")
        self.assertEqual(response["backend_payload"]["packages"][1]["ecosystem"], "npm")
        self.assertEqual(response["mode"], "fast")
        self.assertEqual(response["mode_source"], "inferred")

    def test_multi_package_request_supports_global_ecosystem_inference(self):
        response = handle_chat_request(
            message="scan requests 2.31.0 and flask 2.3.3 on PyPI",
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(len(response["backend_payload"]["packages"]), 2)
        self.assertEqual(
            [item["ecosystem"] for item in response["backend_payload"]["packages"]],
            ["PyPI", "PyPI"],
        )

    def test_invalid_multi_package_request_clarifies_instead_of_guessing(self):
        response = handle_chat_request(
            message="check requests 2.31.0 and flask on PyPI",
            scan_executor=fake_scan_executor,
        )

        self.assertFalse(response["backend_called"])
        self.assertEqual(response["status"], "needs_clarification")
        self.assertIn("exact version", response["message"].lower())

    def test_clarifies_file_without_content(self):
        response = handle_chat_request(
            message="analyze this dependency file",
            file_name="requirements.txt",
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertFalse(response["backend_called"])
        self.assertIn("contents", response["message"])

    def test_payload_contract_has_all_fields(self):
        response = handle_chat_request(
            message="fast scan",
            repo_url="https://github.com/example/repo",
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        expected_keys = {
            "repo_url",
            "token",
            "packages",
            "package_name",
            "package_version",
            "ecosystem",
            "file_name",
            "file_content",
            "mode",
            "raw_text",
        }
        self.assertEqual(set(response["backend_payload"].keys()), expected_keys)

    def test_structured_repo_url_is_normalized_before_execution(self):
        response = handle_chat_request(
            message="fast",
            repo_url="https://github.com/example/repo/tree/main",
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(response["backend_payload"]["repo_url"], "https://github.com/example/repo")

    def test_response_style_differs_by_mode_and_uses_llm_context(self):
        fast = handle_chat_request(
            message="fast scan",
            repo_url="https://github.com/example/repo",
            mode="fast",
            scan_executor=fake_scan_executor,
        )
        detailed = handle_chat_request(
            message="scan with license risk",
            repo_url="https://github.com/example/repo",
            mode="detailed",
            scan_executor=fake_scan_executor,
        )
        developer = handle_chat_request(
            message="developer scan",
            repo_url="https://github.com/example/repo",
            mode="developer",
            scan_executor=fake_scan_executor,
        )

        self.assertIn("I scanned `https://github.com/example/repo` and found 3 dependencies.", fast["message"])
        self.assertIn("Top findings:", fast["message"])
        self.assertIn("severity high", fast["message"])
        self.assertIn("Detailed review for", detailed["message"])
        self.assertIn("Top Vulnerabilities:", detailed["message"])
        self.assertIn("Improper certificate verification", detailed["message"])
        self.assertIn("Recommended Upgrade:", detailed["message"])
        self.assertIn("Apache-2.0", detailed["message"])
        self.assertIn("License Analysis:", detailed["message"])
        self.assertNotIn("`", detailed["message"])
        self.assertIn("Developer analysis for", developer["message"])
        self.assertIn("Dependency quality:\n", developer["message"])
        self.assertIn("Upgrade priority:", developer["message"])
        self.assertIn("Remediation order:", developer["message"])
        self.assertNotIn("License Analysis:", developer["message"])
        self.assertNotIn("`", developer["message"])
        self.assertIn("`requests` 2.31.0", fast["message"])
        self.assertTrue(fast["response_meta"]["used_llm_context"])

    def test_detailed_single_package_vulnerable_case_includes_license_and_links(self):
        response = handle_chat_request(
            message="scan requests 2.31.0 on PyPI",
            packages=[{"package_name": "requests", "package_version": "2.31.0", "ecosystem": "PyPI"}],
            mode="detailed",
            scan_executor=fake_scan_executor,
        )

        self.assertIn("Improper certificate verification", response["message"])
        self.assertIn("Apache-2.0", response["message"])
        self.assertIn("commonly used in commercial software", response["message"])
        self.assertIn("https://github.com/psf/requests", response["message"])

    def test_detailed_single_package_without_vulns_still_mentions_metadata_without_claiming_safety(self):
        def no_vuln_detailed_executor(**payload):
            result = fake_scan_executor(**payload)
            context = result["json_report"]["llm_context"]
            context["scan_summary"]["cves_found"] = 0
            context["top_findings"] = []
            context["vulnerability_details"] = []
            context["top_cves"] = []
            context["top_vulnerabilities_grouped"] = []
            context["vulnerable_package_summary"] = {"count": 0, "packages": []}
            context["detailed"]["top_vulnerabilities_grouped"] = []
            context["detailed"]["fix_analysis"] = {
                "fix_status": "no_fixed",
                "highest_fixed_version": None,
                "all_fixed_versions": [],
            }
            context["package_analysis"]["packages"][0]["vulnerability_count"] = 0
            context["package_analysis"]["packages"][0]["severity"] = None
            context["package_analysis"]["packages"][0]["identifiers"] = []
            context["package_analysis"]["packages"][0]["vulnerability_explanations"] = []
            context["package_analysis"]["packages"][0]["recommended_fix"] = None
            return result

        response = handle_chat_request(
            message="scan requests 2.31.0 on PyPI",
            packages=[{"package_name": "requests", "package_version": "2.31.0", "ecosystem": "PyPI"}],
            mode="detailed",
            scan_executor=no_vuln_detailed_executor,
        )

        self.assertIn("I did not confirm any CVEs", response["message"])
        self.assertIn("Apache-2.0", response["message"])
        self.assertNotIn("safe", response["message"].lower())

    def test_detailed_multi_package_prioritizes_vulnerable_package_first(self):
        response = handle_chat_request(
            message="scan these packages",
            packages=[
                {"package_name": "requests", "package_version": "2.31.0", "ecosystem": "PyPI"},
                {"package_name": "flask", "package_version": "2.3.3", "ecosystem": "PyPI"},
            ],
            mode="detailed",
            scan_executor=fake_file_scan_executor,
        )

        self.assertIn("Top Vulnerabilities:", response["message"])
        self.assertIn("requests 2.31.0", response["message"])
        self.assertNotIn("`", response["message"])

    def test_detailed_file_input_summarizes_file_and_exact_packages(self):
        response = handle_chat_request(
            message="scan this file",
            file_name="requirements.txt",
            file_content="requests==2.31.0\nflask==2.3.3\njinja2==3.1.4\n",
            mode="detailed",
            scan_executor=fake_file_scan_executor,
        )

        self.assertIn("Dependency file scan: requirements.txt.", response["message"])
        self.assertIn("requests 2.31.0", response["message"])
        self.assertNotIn("`", response["message"])

    def test_detailed_repo_input_mentions_source_and_package_metadata(self):
        response = handle_chat_request(
            message="scan this repository for vulnerabilities",
            repo_url="https://github.com/example/repo",
            mode="detailed",
            scan_executor=fake_large_repo_scan_executor,
        )

        self.assertIn("Repository scan: https://github.com/example/repo.", response["message"])
        self.assertIn("requests 2.31.0", response["message"])
        self.assertIn("urllib3 1.26.18", response["message"])

    def test_detailed_non_exact_packages_are_called_out_as_coverage_limits(self):
        response = handle_chat_request(
            message="scan requests 2.31.0 on PyPI",
            packages=[{"package_name": "requests", "package_version": "2.31.0", "ecosystem": "PyPI"}],
            mode="detailed",
            scan_executor=fake_scan_executor,
        )

        self.assertIn("Confidence / Limitations:", response["message"])
        self.assertIn("urllib3", response["message"])

    def test_detailed_links_only_use_backend_metadata(self):
        response = handle_chat_request(
            message="scan this repository for vulnerabilities",
            repo_url="https://github.com/example/repo",
            mode="detailed",
            scan_executor=fake_large_repo_scan_executor,
        )

        self.assertIn("Confidence / Limitations:", response["message"])
        self.assertNotIn("https://pypi.org/project/urllib3", response["message"])

    def test_fast_mode_vulnerability_answer_mentions_package_cve_and_next_step(self):
        response = handle_chat_request(
            message="fast scan",
            repo_url="https://github.com/example/repo",
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertIn("`requests` 2.31.0", response["message"])
        self.assertIn("CVE-TEST-1", response["message"])
        self.assertIn("Next step:", response["message"])

    def test_fast_mode_single_package_mentions_exact_package_and_short_cve_explanation(self):
        response = handle_chat_request(
            message="scan requests 2.31.0 on PyPI",
            packages=[{"package_name": "requests", "package_version": "2.31.0", "ecosystem": "PyPI"}],
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertIn("For `requests==2.31.0`, I found 1 confirmed CVE.", response["message"])
        self.assertIn("Top CVEs:", response["message"])
        self.assertIn("Improper certificate verification", response["message"])

    def test_fast_mode_multi_package_summarizes_scope_and_affected_packages(self):
        response = handle_chat_request(
            message="scan these packages",
            packages=[
                {"package_name": "requests", "package_version": "2.31.0", "ecosystem": "PyPI"},
                {"package_name": "flask", "package_version": "2.3.3", "ecosystem": "PyPI"},
            ],
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertIn("I checked 2 packages", response["message"])
        self.assertIn("Top findings:", response["message"])

    def test_fast_mode_file_with_small_dependency_count_lists_all_dependencies(self):
        response = handle_chat_request(
            message="scan this file",
            file_name="requirements.txt",
            file_content="requests==2.31.0\nflask==2.3.3\njinja2==3.1.4\n",
            mode="fast",
            scan_executor=fake_file_scan_executor,
        )

        self.assertIn("I scanned `requirements.txt` and found 3 dependencies.", response["message"])
        self.assertIn("Dependencies: `requests==2.31.0`, `flask==2.3.3`, `jinja2==3.1.4`", response["message"])

    def test_fast_mode_large_repo_summarizes_count_and_top_affected_only(self):
        response = handle_chat_request(
            message="scan this repository for vulnerabilities",
            repo_url="https://github.com/example/repo",
            mode="fast",
            scan_executor=fake_large_repo_scan_executor,
        )

        self.assertIn("I scanned `https://github.com/example/repo` and found 26 dependencies.", response["message"])
        self.assertIn("Most affected packages: `requests`, `urllib3`", response["message"])
        self.assertNotIn("Dependencies:", response["message"])

    def test_fast_mode_many_cves_explains_only_top_three(self):
        response = handle_chat_request(
            message="scan this repository for vulnerabilities",
            repo_url="https://github.com/example/repo",
            mode="fast",
            scan_executor=fake_large_repo_scan_executor,
        )

        self.assertIn("Top CVEs:", response["message"])
        self.assertIn("CVE-1", response["message"])
        self.assertIn("CVE-2", response["message"])
        self.assertIn("CVE-4", response["message"])
        self.assertNotIn("CVE-5", response["message"])

    def test_discovery_only_response_is_user_friendly(self):
        response = handle_chat_request(
            message="analyze this dependency file",
            file_name="requirements.txt",
            file_content="oci-openai\npython-dotenv\nfastapi\nuvicorn\n",
            mode="fast",
            scan_executor=fake_discovery_only_scan_executor,
        )

        self.assertIn("Dependency discovery for the dependency file completed", response["message"])
        self.assertIn("`oci-openai`", response["message"])
        self.assertIn("Provide pinned versions", response["message"])
        self.assertEqual(response["response_meta"]["result_type"], "discovery_only")

    def test_no_vulnerability_case_does_not_claim_safety(self):
        def no_vuln_scan_executor(**payload):
            result = fake_scan_executor(**payload)
            context = result["json_report"]["llm_context"]
            context["scan_summary"]["cves_found"] = 0
            context["top_findings"] = []
            context["vulnerability_details"] = []
            context["top_cves"] = []
            context["vulnerable_package_summary"] = {"count": 0, "packages": []}
            return result

        response = handle_chat_request(
            message="fast scan",
            repo_url="https://github.com/example/repo",
            mode="fast",
            scan_executor=no_vuln_scan_executor,
        )

        self.assertIn("I didn't confirm any vulnerable dependencies", response["message"])
        self.assertNotIn("safe", response["message"].lower())

    def test_fast_mode_repo_no_vuln_partial_coverage_is_informative(self):
        response = handle_chat_request(
            message="fast scan this repository",
            repo_url="https://github.com/hashicorp/terraform",
            mode="fast",
            scan_executor=fake_repo_no_vuln_partial_executor,
        )

        self.assertIn("I didn't confirm any vulnerable dependencies in `https://github.com/hashicorp/terraform`", response["message"])
        self.assertIn("GitHub SBOM", response["message"])
        self.assertIn("332 dependencies", response["message"])
        self.assertIn("19 exact-version dependencies could be checked precisely", response["message"])
        self.assertIn("Examples checked:", response["message"])
        self.assertIn("Main unresolved packages:", response["message"])
        self.assertIn("not proof the repo is clean", response["message"])
        self.assertLess(len(response["message"]), 900)

    def test_scan_result_not_returned_by_default(self):
        response = handle_chat_request(
            message="fast scan",
            repo_url="https://github.com/example/repo",
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertNotIn("scan_result", response)
        self.assertIn("response_meta", response)
        self.assertEqual(response["response_meta"]["confirmed_cves"], 1)

    def test_fast_mode_returns_frontend_friendly_tables_and_cards(self):
        response = handle_chat_request(
            message="fast scan",
            repo_url="https://github.com/example/repo",
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["response_type"], "scan_result")
        self.assertEqual(response["llm_response"], response["message"])
        self.assertEqual(response["cards"]["dependencies_discovered"], 3)
        self.assertEqual(response["cards"]["exact_versions"], 2)
        self.assertEqual(response["cards"]["packages_checked"], 2)
        self.assertEqual(response["cards"]["unique_cves_found"], 1)
        self.assertEqual(response["dependencies_discovered_table"][0]["package"], "requests")
        self.assertEqual(response["dependencies_discovered_table"][0]["origin"]["label"], "Registry")
        self.assertEqual(
            response["dependencies_discovered_table"][0]["origin"]["url"],
            "https://pypi.org/project/requests/2.31.0/",
        )
        self.assertEqual(response["vulnerable_dependencies_table"][0]["vulnerability_id"], "CVE-TEST-1")
        self.assertEqual(response["vulnerable_dependencies_table"][0]["summary"], "")
        self.assertEqual(response["license_compliance_table"], [])
        self.assertNotIn("json_report", str(response))

    def test_vulnerable_dependencies_table_expands_multiple_advisories_into_rows(self):
        def multi_advisory_scan_executor(**payload):
            result = fake_scan_executor(**payload)
            result["json_report"]["vulnerability_research"]["packages_checked"][0]["advisory_summaries"] = [
                {
                    "id": "CVE-TEST-1",
                    "aliases": ["CVE-TEST-1", "GHSA-test-1", "PYSEC-test-1"],
                    "alternate_ids": ["GHSA-test-1", "PYSEC-test-1"],
                    "severity": "high",
                    "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                    "details": None,
                    "fixed_version": "2.32.0",
                    "references": [
                        {"type": "FIX", "label": "Fix", "url": "https://osv.dev/vulnerability/GHSA-test-1"},
                        {"type": "ARTICLE", "label": "Article", "url": "https://github.com/advisories/GHSA-test-1"},
                    ],
                    "primary_reference": "https://osv.dev/vulnerability/GHSA-test-1",
                },
                {
                    "id": "GHSA-test-2",
                    "aliases": ["GHSA-test-2"],
                    "alternate_ids": [],
                    "severity": "moderate",
                    "summary": "Session verification may stay disabled across later requests.",
                    "details": None,
                    "fixed_version": None,
                    "references": [
                        {"type": "REPORT", "label": "Report", "url": "https://osv.dev/vulnerability/GHSA-test-2"},
                        {"type": "ARTICLE", "label": "Article", "url": "https://github.com/advisories/GHSA-test-2"},
                    ],
                    "primary_reference": "https://osv.dev/vulnerability/GHSA-test-2",
                },
            ]
            result["json_report"]["vulnerability_research"]["packages_checked"][0]["vulnerability_count"] = 2
            result["json_report"]["vulnerability_research"]["packages_checked"][0]["vulnerability_ids"] = [
                "GHSA-test-1",
                "GHSA-test-2",
            ]
            result["json_report"]["vulnerability_research"]["packages_checked"][0]["cve_ids"] = [
                "CVE-TEST-1",
                "CVE-TEST-2",
            ]
            result["json_report"]["vulnerability_research"]["cves_found"] = ["CVE-TEST-1", "CVE-TEST-2"]
            return result

        response = handle_chat_request(
            message="fast scan",
            repo_url="https://github.com/example/repo",
            mode="fast",
            scan_executor=multi_advisory_scan_executor,
        )

        rows = response["vulnerable_dependencies_table"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["package"], "requests")
        self.assertEqual(rows[0]["version"], "2.31.0")
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["vulnerability_id"], "CVE-TEST-1")
        self.assertEqual(rows[0]["alternate_ids"], ["GHSA-test-1", "PYSEC-test-1"])
        self.assertEqual(rows[0]["fixed_version"], "2.32.0")
        self.assertEqual(rows[0]["references"][0]["label"], "Fix")
        self.assertEqual(rows[1]["vulnerability_id"], "GHSA-test-2")
        self.assertEqual(rows[1]["fixed_version"], None)
        self.assertEqual(rows[1]["references"][0]["label"], "Report")
        self.assertIn("Session verification", rows[1]["summary"])

    def test_detailed_mode_additionally_returns_license_table(self):
        response = handle_chat_request(
            message="detailed scan",
            repo_url="https://github.com/example/repo",
            mode="detailed",
            scan_executor=fake_scan_executor,
        )

        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["license_compliance_table"][0]["package"], "requests")
        self.assertEqual(response["license_compliance_table"][0]["detected_license"], "Apache-2.0")

    def test_developer_mode_additionally_returns_license_table(self):
        response = handle_chat_request(
            message="developer scan",
            repo_url="https://github.com/example/repo",
            mode="developer",
            scan_executor=fake_scan_executor,
        )

        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["license_compliance_table"][0]["policy_status"], "allowed")
        self.assertEqual(response["fix_analysis"], {})
        self.assertEqual(response["license_sources"], [])
        self.assertNotIn("Recommended Upgrade:", response["message"])

    def test_developer_mode_returns_dependency_graphs(self):
        response = handle_chat_request(
            message="developer scan",
            repo_url="https://github.com/example/repo",
            mode="developer",
            scan_executor=fake_scan_executor,
        )

        self.assertIn("dependency_graphs", response)
        self.assertIn("requests@2.31.0", response["dependency_graphs"])
        self.assertEqual(
            response["dependency_graphs"]["requests@2.31.0"]["dependencies"][0]["name"],
            "urllib3",
        )

    def test_detailed_mode_returns_fix_analysis_and_license_sources(self):
        response = handle_chat_request(
            message="detailed scan",
            repo_url="https://github.com/example/repo",
            mode="detailed",
            scan_executor=fake_scan_executor,
        )

        self.assertEqual(response["fix_analysis"]["fix_status"], "all_fixed")
        self.assertEqual(response["fix_analysis"]["highest_fixed_version"], "2.32.0")
        self.assertEqual(response["license_sources"][0]["source_url"], "https://github.com/psf/requests")
        self.assertIn("Recommended Upgrade:", response["message"])

    def test_detailed_mode_debug_payload_includes_grouped_top_vulnerabilities(self):
        response = handle_chat_request(
            message="detailed scan",
            repo_url="https://github.com/example/repo",
            mode="detailed",
            include_debug=True,
            scan_executor=fake_scan_executor,
        )

        grouped = response["scan_result"]["json_report"]["llm_context"]["top_vulnerabilities_grouped"]
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["package"], "requests")
        self.assertEqual(grouped[0]["vulnerabilities"][0]["id"], "CVE-TEST-1")

    def test_detailed_mode_partial_fixes_use_conditional_upgrade_language(self):
        def partial_fix_scan_executor(**payload):
            result = fake_scan_executor(**payload)
            context = result["json_report"]["llm_context"]
            grouped = [
                {
                    "package": "requests",
                    "version": "2.31.0",
                    "severity": "high",
                    "vulnerabilities": [
                        {
                            "id": "CVE-TEST-1",
                            "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                            "fixed_version": "2.32.0",
                            "references": ["https://osv.dev/vulnerability/GHSA-test-1"],
                        },
                        {
                            "id": "GHSA-test-2",
                            "summary": "Another issue without a confirmed fix yet.",
                            "fixed_version": None,
                            "references": [],
                        },
                    ],
                }
            ]
            fix_analysis = {
                "fix_status": "partial_fixed",
                "highest_fixed_version": "2.32.0",
                "all_fixed_versions": ["2.32.0"],
            }
            context["top_vulnerabilities_grouped"] = grouped
            context["detailed"]["top_vulnerabilities_grouped"] = grouped
            context["detailed"]["fix_analysis"] = fix_analysis
            result["json_report"]["vulnerability_research"]["packages_checked"][0]["advisory_summaries"] = [
                {
                    "id": "CVE-TEST-1",
                    "aliases": ["CVE-TEST-1"],
                    "severity": "high",
                    "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                    "details": None,
                    "fixed_version": "2.32.0",
                    "references": ["https://osv.dev/vulnerability/GHSA-test-1"],
                    "primary_reference": "https://osv.dev/vulnerability/GHSA-test-1",
                },
                {
                    "id": "GHSA-test-2",
                    "aliases": ["GHSA-test-2"],
                    "severity": "moderate",
                    "summary": "Another issue without a confirmed fix yet.",
                    "details": None,
                    "fixed_version": None,
                    "references": [],
                    "primary_reference": None,
                },
            ]
            return result

        response = handle_chat_request(
            message="detailed scan",
            repo_url="https://github.com/example/repo",
            mode="detailed",
            scan_executor=partial_fix_scan_executor,
        )

        self.assertEqual(response["fix_analysis"]["fix_status"], "partial_fixed")
        self.assertIn("some identified vulnerabilities do not yet have confirmed fixed versions", response["message"].lower())

    def test_detailed_mode_no_fixes_avoids_upgrade_recommendation(self):
        def no_fix_scan_executor(**payload):
            result = fake_scan_executor(**payload)
            context = result["json_report"]["llm_context"]
            grouped = [
                {
                    "package": "requests",
                    "version": "2.31.0",
                    "severity": "high",
                    "vulnerabilities": [
                        {
                            "id": "CVE-TEST-1",
                            "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                            "fixed_version": None,
                            "references": [],
                        }
                    ],
                }
            ]
            fix_analysis = {
                "fix_status": "no_fixed",
                "highest_fixed_version": None,
                "all_fixed_versions": [],
            }
            context["top_vulnerabilities_grouped"] = grouped
            context["detailed"]["top_vulnerabilities_grouped"] = grouped
            context["detailed"]["fix_analysis"] = fix_analysis
            return result

        response = handle_chat_request(
            message="detailed scan",
            repo_url="https://github.com/example/repo",
            mode="detailed",
            scan_executor=no_fix_scan_executor,
        )

        self.assertEqual(response["fix_analysis"]["fix_status"], "no_fixed")
        self.assertIn("No fixed versions are currently available.", response["message"])

    def test_scan_result_returned_when_debug_requested(self):
        response = handle_chat_request(
            message="fast scan",
            repo_url="https://github.com/example/repo",
            token="ghp_secret",
            mode="fast",
            include_debug=True,
            scan_executor=fake_scan_executor,
        )

        self.assertIn("scan_result", response)
        self.assertEqual(response["backend_payload"]["token"], "***redacted***")

    def test_include_debug_never_exposes_raw_token(self):
        def token_echo_scan_executor(**payload):
            return {
                "summary": "debug summary",
                "token": payload.get("token"),
                "json_report": {
                    "debug": {
                        "token": payload.get("token"),
                    },
                    "llm_context": {
                        "input": {
                            "input_type": "github_repo",
                            "mode": "fast",
                            "repo_url": payload.get("repo_url"),
                            "language": "python",
                            "dependency_summary": {"count": 0, "can_list_all": True, "preview": []},
                            "packages_scanned": [],
                            "route": {"mode_source": "explicit"},
                        },
                        "scan_summary": {
                            "total_dependencies": 0,
                            "exact_versions": 0,
                            "range_versions": 0,
                            "unknown_versions": 0,
                            "packages_checked_for_vulnerabilities": 0,
                            "packages_skipped_for_exact_matching": 0,
                            "cves_found": 0,
                        },
                        "top_findings": [],
                        "vulnerability_details": [],
                        "top_cves": [],
                        "vulnerable_package_summary": {"count": 0, "packages": []},
                        "top_uncertainties": [],
                        "important_metadata": [],
                        "recommended_next_steps": [],
                    },
                },
            }

        response = handle_chat_request(
            message="scan this private repo",
            repo_url="https://github.com/example/repo",
            token="github_pat_secret_value",
            mode="fast",
            include_debug=True,
            scan_executor=token_echo_scan_executor,
        )

        self.assertEqual(response["backend_payload"]["token"], "***redacted***")
        self.assertEqual(response["scan_result"]["token"], "***redacted***")
        self.assertEqual(response["scan_result"]["json_report"]["debug"]["token"], "***redacted***")

    def test_repo_structured_input_outranks_file_wording_in_response(self):
        response = handle_chat_request(
            message="analyze this dependency file",
            repo_url="https://github.com/example/repo",
            token="ghp_secret",
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(response["input_type"], "github_repo")
        self.assertIn("I scanned `https://github.com/example/repo`", response["message"])

    def test_real_file_input_still_reports_file_target(self):
        response = handle_chat_request(
            message="analyze this dependency file",
            file_name="requirements.txt",
            file_content="requests==2.31.0\nflask==2.3.3\n",
            mode="fast",
            scan_executor=fake_file_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(response["input_type"], "dependency_file")
        self.assertIn("I scanned `requirements.txt`", response["message"])

    def test_package_input_still_reports_package_target(self):
        response = handle_chat_request(
            message="scan requests 2.31.0 on PyPI",
            packages=[{"package_name": "requests", "package_version": "2.31.0", "ecosystem": "PyPI"}],
            mode="fast",
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(response["input_type"], "package")
        self.assertIn("For `requests==2.31.0`", response["message"])

    def test_natural_language_package_with_version_keyword_still_targets_real_package(self):
        captured = {}

        def capturing_scan_executor(**payload):
            captured.update(payload)
            return fake_scan_executor(**payload)

        response = handle_chat_request(
            message="check requests version 2.31.0 it is a python package",
            mode="fast",
            scan_executor=capturing_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(captured["package_name"], "requests")
        self.assertEqual(captured["package_version"], "2.31.0")
        self.assertEqual(captured["ecosystem"], "PyPI")
        self.assertEqual(response["cards"]["packages_checked"], 2)
        self.assertEqual(response["vulnerable_dependencies_table"][0]["package"], "requests")

    def test_repeated_uncertainty_is_grouped(self):
        response = handle_chat_request(
            message="developer scan",
            repo_url="https://github.com/example/repo",
            mode="developer",
            scan_executor=fake_scan_executor,
        )

        self.assertIn("1 package could not be checked precisely", response["message"])
        self.assertLess(response["message"].count("urllib3"), 2)

    def test_llm_input_stage_clarifies_without_backend_call(self):
        llm = FakeLLM(
            [
                {
                    "action": "clarify",
                    "question": "What exact version of requests should I analyze?",
                }
            ]
        )
        response = handle_chat_request(
            message="check requests",
            input_llm_client=llm,
            output_llm_client=llm,
            scan_executor=fake_scan_executor,
        )

        self.assertFalse(response["backend_called"])
        self.assertIn("exact version", response["message"])
        self.assertEqual(len(llm.calls), 1)
        self.assertIsNone(response["backend_payload"])
        self.assertIsNone(response["mode"])
        self.assertIsNone(response["mode_source"])
        self.assertTrue(response["response_meta"]["llm_input_stage"])
        self.assertFalse(response["response_meta"]["llm_output_stage"])
        self.assertEqual(response["response_meta"]["clarification_builder"], "shared")

    def test_llm_input_stage_executes_and_output_stage_generates_answer(self):
        input_llm = FakeLLM(
            [
                {
                    "action": "execute",
                    "backend_payload": {
                        "repo_url": "https://github.com/example/repo",
                        "token": "tok_exact",
                        "package_name": None,
                        "package_version": None,
                        "ecosystem": None,
                        "file_name": None,
                        "file_content": None,
                        "mode": "developer",
                        "raw_text": "developer scan this repo",
                    },
                }
            ]
        )
        output_llm = FakeLLM(["This is the LLM-written developer answer."])
        response = handle_chat_request(
            message="developer scan this repo",
            input_llm_client=input_llm,
            output_llm_client=output_llm,
            scan_executor=fake_scan_executor,
        )

        self.assertTrue(response["backend_called"])
        self.assertEqual(response["backend_payload"]["token"], "***redacted***")
        self.assertEqual(response["mode"], "developer")
        self.assertEqual(response["message"], "This is the LLM-written developer answer.")
        self.assertTrue(response["response_meta"]["llm_input_stage"])
        self.assertTrue(response["response_meta"]["llm_output_stage"])
        self.assertIn("llm_context", output_llm.calls[0]["user_payload"])
        self.assertIn("vulnerability_details", output_llm.calls[0]["user_payload"])

    def test_detailed_mode_llm_output_strips_backticks(self):
        input_llm = FakeLLM(
            [
                {
                    "action": "execute",
                    "backend_payload": {
                        "repo_url": "https://github.com/example/repo",
                        "token": None,
                        "package_name": None,
                        "package_version": None,
                        "ecosystem": None,
                        "file_name": None,
                        "file_content": None,
                        "mode": "detailed",
                        "raw_text": "detailed scan this repo",
                    },
                }
            ]
        )
        output_llm = FakeLLM(["Package: `requests` version `2.31.0`"])
        response = handle_chat_request(
            message="detailed scan this repo",
            input_llm_client=input_llm,
            output_llm_client=output_llm,
            scan_executor=fake_scan_executor,
        )

        self.assertEqual(response["message"], "Package: requests version 2.31.0")
        self.assertNotIn("`", response["message"])

    def test_invalid_llm_payload_fails_safe_without_backend_call(self):
        llm = FakeLLM(
            [
                {
                    "action": "execute",
                    "backend_payload": {
                        "repo_url": None,
                        "token": None,
                        "package_name": "requests",
                        "package_version": None,
                        "ecosystem": None,
                        "file_name": None,
                        "file_content": None,
                        "mode": "fast",
                        "raw_text": "check requests",
                    },
                }
            ]
        )
        response = handle_chat_request(
            message="check requests",
            input_llm_client=llm,
            output_llm_client=llm,
            scan_executor=fake_scan_executor,
        )

        self.assertFalse(response["backend_called"])
        self.assertEqual(response["status"], "needs_clarification")
        self.assertIn("validation_error", response["response_meta"])
        self.assertIsNone(response["backend_payload"])
        self.assertIsNone(response["mode_source"])
        self.assertTrue(response["response_meta"]["llm_input_stage"])
        self.assertFalse(response["response_meta"]["llm_output_stage"])
        self.assertEqual(response["response_meta"]["clarification_builder"], "shared")


if __name__ == "__main__":
    unittest.main()
