import unittest
from unittest.mock import patch

from app.schemas import (
    CVEEnrichment,
    DependencyInventory,
    DependencySourceType,
    MetadataEnrichment,
    NormalizedDependency,
    PackageCoordinate,
    ScanResultType,
    VersionKind,
    VulnerabilityFinding,
    VulnerabilityResearch,
)
from app.services.dependency_inputs import acquire_direct_package_inventory, acquire_file_dependency_inventory
from app.services.enrichment.deps_dev import _extract_deps_dev_source_links, enrich_with_deps_dev
from app.services.github import acquisition
from app.services.github.client import GitHubClient
from app.controller.formatter import build_registry_url
from app.services.reporting import build_llm_context
from app.services.vulnerability.osv import query_osv
from app.services.vulnerability.research import enrich_vulnerabilities


class FakeSbomClient:
    def __init__(self, repo_url, token=None):
        self.repo_url = repo_url

    def fetch_sbom(self):
        return {
            "sbom": {
                "packages": [
                    {
                        "name": "requests",
                        "versionInfo": "2.31.0",
                        "externalRefs": [
                            {"referenceLocator": "pkg:pypi/requests@2.31.0"}
                        ],
                    }
                ]
            }
        }


class EmptySbomClient:
    def __init__(self, repo_url, token=None):
        self.repo_url = repo_url

    def fetch_sbom(self):
        return {"sbom": {"packages": []}}


class DuplicateFileClient:
    def __init__(self, repo_url, token=None):
        self.repo_url = repo_url
        self.token = token

    def get_structure(self):
        return {
            "service-a": {"requirements.txt": {}},
            "service-b": {"requirements.txt": {}},
        }

    def fetch_file(self, path):
        if path == "service-a/requirements.txt":
            return "requests==2.31.0\n"
        if path == "service-b/requirements.txt":
            return "requests==2.32.0\n"
        return None


class VersionlessRepoClient:
    def __init__(self, repo_url, token=None):
        self.repo_url = repo_url
        self.token = token

    def get_structure(self):
        return {
            "requirements.txt": {},
        }

    def fetch_file(self, path):
        if path == "requirements.txt":
            return "oci-openai\npython-dotenv\nfastapi\nuvicorn\n"
        return None


class HardeningTests(unittest.TestCase):
    def test_build_registry_url_for_pypi_with_version(self):
        self.assertEqual(
            build_registry_url("PyPI", "requests", "2.31.0"),
            "https://pypi.org/project/requests/2.31.0/",
        )

    def test_build_registry_url_for_npm_scoped_package_preserves_scope(self):
        self.assertEqual(
            build_registry_url("npm", "@types/node", "22.10.1"),
            "https://www.npmjs.com/package/@types/node/v/22.10.1",
        )

    def test_build_registry_url_for_maven_splits_group_and_artifact(self):
        self.assertEqual(
            build_registry_url("Maven", "org.springframework:spring-core", "6.1.11"),
            "https://central.sonatype.com/artifact/org.springframework/spring-core/6.1.11",
        )

    def test_build_registry_url_without_version_returns_base_url_when_supported(self):
        self.assertEqual(
            build_registry_url("crates.io", "serde", ""),
            "https://crates.io/crates/serde",
        )

    def test_build_registry_url_with_range_version_falls_back_to_base_url(self):
        self.assertEqual(
            build_registry_url("PyPI", "urllib3", ">=1.26,<3"),
            "https://pypi.org/project/urllib3/",
        )

    def test_build_registry_url_returns_none_for_malformed_maven_string(self):
        self.assertIsNone(build_registry_url("Maven", "spring-core", "6.1.11"))

    def test_deps_dev_source_links_map_labels_without_duplicate_urls(self):
        links = [
            {"label": "SOURCE_REPO", "url": "https://github.com/psf/requests"},
            {"label": "DOCUMENTATION", "url": "https://docs.python-requests.org"},
            {"label": "ORIGIN", "url": "https://pypi.org/project/requests"},
            {"label": "HOMEPAGE", "url": "https://requests.readthedocs.io"},
            {"label": "DOCUMENTATION", "url": "https://docs.python-requests.org"},
        ]

        mapped = _extract_deps_dev_source_links(links)

        self.assertEqual(
            mapped,
            [
                {"label": "Repository", "url": "https://github.com/psf/requests"},
                {"label": "Documentation", "url": "https://docs.python-requests.org"},
                {"label": "Package", "url": "https://pypi.org/project/requests"},
            ],
        )

    def test_osv_primary_id_prefers_cve_and_collects_fixed_version(self):
        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "vulns": [
                        {
                            "id": "GHSA-test-1",
                            "aliases": ["CVE-2024-35195", "PYSEC-2024-1"],
                            "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/CRITICAL"}],
                            "references": [
                                {"type": "ARTICLE", "url": "https://example.com/article"},
                                {"type": "EVIDENCE", "url": "https://example.com/poc"},
                                {"type": "REPORT", "url": "https://github.com/org/repo/issues/1"},
                                {"type": "FIX", "url": "https://github.com/org/repo/commit/fix"},
                                {"type": "WEB", "url": "https://ignored.example.com"},
                            ],
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "2.31.1"},
                                                {"fixed": "2.32.0"},
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                }

        with patch("app.services.vulnerability.osv.requests.post", return_value=FakeResponse()):
            result = query_osv("requests", "PyPI", "2.31.0")

        advisory = result["advisory_summaries"][0]
        self.assertEqual(advisory["id"], "CVE-2024-35195")
        self.assertEqual(advisory["alternate_ids"], ["GHSA-test-1", "PYSEC-2024-1"])
        self.assertEqual(advisory["fixed_version"], "2.32.0")
        self.assertEqual(
            advisory["references"],
            [
                {"type": "FIX", "label": "Fix", "url": "https://github.com/org/repo/commit/fix"},
                {"type": "REPORT", "label": "Report", "url": "https://github.com/org/repo/issues/1"},
                {"type": "EVIDENCE", "label": "Evidence", "url": "https://example.com/poc"},
                {"type": "ARTICLE", "label": "Article", "url": "https://example.com/article"},
            ],
        )
        self.assertEqual(advisory["primary_reference"], "https://github.com/org/repo/commit/fix")

    def test_osv_primary_id_falls_back_to_ghsa_when_no_cve_exists(self):
        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "vulns": [
                        {
                            "id": "GHSA-test-2",
                            "aliases": ["PYSEC-2024-2"],
                            "summary": "Session verification may stay disabled across later requests.",
                            "references": [{"url": "https://osv.dev/vulnerability/GHSA-test-2"}],
                            "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}],
                        }
                    ]
                }

        with patch("app.services.vulnerability.osv.requests.post", return_value=FakeResponse()):
            result = query_osv("requests", "PyPI", "2.31.0")

        advisory = result["advisory_summaries"][0]
        self.assertEqual(advisory["id"], "GHSA-test-2")
        self.assertEqual(advisory["alternate_ids"], ["PYSEC-2024-2"])
        self.assertEqual(advisory["fixed_version"], None)

    def test_osv_references_fall_back_to_web_and_package_when_preferred_types_missing(self):
        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "vulns": [
                        {
                            "id": "GHSA-test-3",
                            "aliases": ["CVE-2026-99999"],
                            "summary": "Fallback reference behavior test.",
                            "references": [
                                {"type": "PACKAGE", "url": "https://pypi.org/project/requests"},
                                {"type": "WEB", "url": "https://osv.dev/vulnerability/GHSA-test-3"},
                                {"type": "ADVISORY", "url": "https://ignored.example.com/advisory"},
                            ],
                            "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}],
                        }
                    ]
                }

        with patch("app.services.vulnerability.osv.requests.post", return_value=FakeResponse()):
            result = query_osv("requests", "PyPI", "2.31.0")

        advisory = result["advisory_summaries"][0]
        self.assertEqual(
            advisory["references"],
            [
                {"type": "WEB", "label": "Web", "url": "https://osv.dev/vulnerability/GHSA-test-3"},
                {"type": "PACKAGE", "label": "Package", "url": "https://pypi.org/project/requests"},
            ],
        )
        self.assertEqual(advisory["primary_reference"], "https://osv.dev/vulnerability/GHSA-test-3")

    def test_direct_package_inventory_accepts_multiple_packages(self):
        inventory = acquire_direct_package_inventory(
            packages=[
                PackageCoordinate(package_name="transformers", package_version="4.35.2", ecosystem="PyPI"),
                PackageCoordinate(package_name="compromise", package_version="14.12.0", ecosystem="npm"),
            ]
        )

        self.assertEqual(inventory.input_type.value, "package")
        self.assertEqual(len(inventory.dependencies), 2)
        self.assertEqual(inventory.dependencies[0].name, "transformers")
        self.assertEqual(inventory.dependencies[1].ecosystem, "npm")

    def test_github_sbom_parseable_spdx_package(self):
        with patch.object(acquisition, "GitHubClient", FakeSbomClient):
            inventory = acquisition.acquire_github_sbom_inventory("https://github.com/psf/requests")

        self.assertEqual(inventory.dependencies[0].name, "requests")
        self.assertEqual(inventory.dependencies[0].version, "2.31.0")
        self.assertEqual(inventory.dependencies[0].version_kind, VersionKind.EXACT)

    def test_github_sbom_empty_response_has_clear_error(self):
        with patch.object(acquisition, "GitHubClient", EmptySbomClient):
            with self.assertRaisesRegex(RuntimeError, "contained no package/component entries"):
                acquisition.acquire_github_sbom_inventory("https://github.com/psf/requests")

    def test_public_repo_fetch_uses_discovered_default_branch(self):
        class FakeResponse:
            def __init__(self, status_code, payload=None, text=""):
                self.status_code = status_code
                self._payload = payload or {}
                self.text = text

            def json(self):
                return self._payload

        calls = []

        def fake_get(url, headers=None, params=None):
            calls.append((url, params))
            if url == "https://api.github.com/repos/example/repo":
                return FakeResponse(200, {"default_branch": "develop"})
            if url == "https://api.github.com/repos/example/repo/git/trees/develop?recursive=1":
                return FakeResponse(200, {"tree": [{"path": "requirements.txt", "type": "blob"}]})
            if url == "https://raw.githubusercontent.com/example/repo/develop/requirements.txt":
                return FakeResponse(200, text="requests==2.31.0\n")
            return FakeResponse(404)

        with patch("app.utils.repo_utils.requests.get", side_effect=fake_get):
            client = GitHubClient("https://github.com/example/repo")
            client.get_structure()
            content = client.fetch_file("requirements.txt")

        self.assertEqual(content, "requests==2.31.0\n")
        self.assertIn(("https://raw.githubusercontent.com/example/repo/develop/requirements.txt", None), calls)

    def test_github_file_inventory_preserves_duplicate_names_with_different_versions(self):
        with patch.object(acquisition, "GitHubClient", DuplicateFileClient):
            inventory = acquisition.acquire_github_file_inventory("https://github.com/example/repo")

        versions = sorted(dep.version for dep in inventory.dependencies if dep.name == "requests")
        self.assertEqual(versions, ["2.31.0", "2.32.0"])

    def test_versionless_file_inventory_becomes_discovery_only(self):
        inventory = acquire_file_dependency_inventory(
            "requirements.txt",
            "oci-openai\npython-dotenv\nfastapi\nuvicorn\n",
        )

        self.assertEqual(inventory.result_type, ScanResultType.DISCOVERY_ONLY)
        self.assertEqual([dep.name for dep in inventory.dependencies], ["oci-openai", "python-dotenv", "fastapi", "uvicorn"])
        self.assertTrue(all(dep.version_kind == VersionKind.UNKNOWN for dep in inventory.dependencies))

    def test_repo_fallback_with_name_only_requirements_surfaces_discovery(self):
        with patch.object(acquisition, "GitHubClient", VersionlessRepoClient):
            inventory = acquisition.acquire_github_file_inventory("https://github.com/example/repo")

        self.assertEqual(inventory.result_type, ScanResultType.DISCOVERY_ONLY)
        self.assertEqual(len(inventory.dependencies), 4)
        self.assertIn("missing_versions_in_repo_fallback", inventory.analysis_blocked_reason or "")

    def test_mixed_file_scan_keeps_exact_dependencies_and_reports_missing_versions(self):
        inventory = acquire_file_dependency_inventory(
            "requirements.txt",
            "requests==2.31.0\nfastapi\nuvicorn\n",
        )
        with patch("app.services.vulnerability.research.query_osv") as query_osv:
            query_osv.return_value = {
                "package_name": "requests",
                "version_checked": "2.31.0",
                "vulnerability_count": 0,
                "cve_ids": [],
                "vulnerability_ids": [],
                "severity": None,
                "advisory_summaries": [],
            }
            research = enrich_vulnerabilities(
                github_report={"language": "python", "dependency_files": {"lockfiles": ["requirements.txt"], "manifests": []}},
                package_version_map=inventory.package_version_map,
                package_metadata_map=inventory.package_metadata_map,
                dependencies=[dep.model_dump() for dep in inventory.dependencies],
            )

        self.assertEqual(inventory.result_type, ScanResultType.PARTIAL_DISCOVERY)
        self.assertEqual(research.packages_checked_count, 1)
        self.assertTrue(any(item["reason"] == "missing_version" for item in research.skipped_packages))

    def test_deps_dev_skips_non_exact_versions(self):
        inventory = DependencyInventory(
            dependencies=[
                NormalizedDependency(
                    name="urllib3",
                    version=">=1.26,<3",
                    version_kind=VersionKind.RANGE,
                    version_specifier=">=1.26,<3",
                    ecosystem="PyPI",
                    source_type=DependencySourceType.GITHUB_FILE,
                )
            ]
        )

        with patch("app.services.enrichment.deps_dev.requests.get") as request_get:
            enrichment = enrich_with_deps_dev(inventory)

        request_get.assert_not_called()
        self.assertEqual(enrichment.data["skipped_count"], 1)
        self.assertEqual(enrichment.data["skipped"][0]["reason"], "non_exact_version")

    def test_deps_dev_can_check_all_exact_versions_when_limit_is_unset(self):
        inventory = DependencyInventory(
            dependencies=[
                NormalizedDependency(
                    name=f"package-{index}",
                    version=f"1.{index}.0",
                    version_kind=VersionKind.EXACT,
                    ecosystem="PyPI",
                    source_type=DependencySourceType.GITHUB_FILE,
                )
                for index in range(21)
            ]
        )

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {"licenses": [{"spdx": "MIT"}], "advisoryKeys": [], "links": {}}

        with patch("app.services.enrichment.deps_dev.requests.get", return_value=FakeResponse()) as request_get:
            enrichment = enrich_with_deps_dev(inventory, max_packages=None)

        self.assertEqual(request_get.call_count, 21)
        self.assertEqual(enrichment.data["packages_checked_count"], 21)

    def test_vulnerability_research_skips_non_exact_versions(self):
        research = enrich_vulnerabilities(
            github_report={"language": "python", "dependency_files": {"lockfiles": [], "manifests": []}},
            package_version_map={"urllib3": ">=1.26,<3"},
            package_metadata_map={
                "urllib3": {
                    "ecosystem": "PyPI",
                    "source": "poetry",
                    "version_kind": "range",
                    "version_specifier": ">=1.26,<3",
                }
            },
        )

        self.assertEqual(research.packages_checked_count, 0)
        self.assertEqual(research.skipped_packages[0]["reason"], "non_exact_version")

    def test_direct_package_exact_version_is_not_skipped(self):
        inventory = acquire_direct_package_inventory(
            packages=[
                PackageCoordinate(package_name="pandas", package_version="2.2.1", ecosystem="PyPI"),
            ]
        )

        with patch("app.services.vulnerability.research.query_osv") as query_osv:
            query_osv.return_value = {
                "package_name": "pandas",
                "version_checked": "2.2.1",
                "vulnerability_count": 0,
                "cve_ids": [],
                "vulnerability_ids": [],
                "severity": None,
                "advisory_summaries": [],
            }
            research = enrich_vulnerabilities(
                github_report={"language": "python", "dependency_files": {"lockfiles": [], "manifests": []}},
                package_version_map=inventory.package_version_map,
                package_metadata_map=inventory.package_metadata_map,
                dependencies=[dep.model_dump() for dep in inventory.dependencies],
            )

        query_osv.assert_called_once_with("pandas", "PyPI", "2.2.1", unittest.mock.ANY)
        self.assertEqual(research.packages_checked_count, 1)
        self.assertEqual(len(research.skipped_packages), 0)

    def test_multi_direct_package_exact_versions_are_not_skipped(self):
        inventory = acquire_direct_package_inventory(
            packages=[
                PackageCoordinate(package_name="transformers", package_version="4.35.2", ecosystem="PyPI"),
                PackageCoordinate(package_name="compromise", package_version="14.12.0", ecosystem="npm"),
            ]
        )

        with patch("app.services.vulnerability.research.query_osv") as query_osv:
            query_osv.side_effect = [
                {
                    "package_name": "transformers",
                    "version_checked": "4.35.2",
                    "vulnerability_count": 0,
                    "cve_ids": [],
                    "vulnerability_ids": [],
                    "severity": None,
                    "advisory_summaries": [],
                },
                {
                    "package_name": "compromise",
                    "version_checked": "14.12.0",
                    "vulnerability_count": 0,
                    "cve_ids": [],
                    "vulnerability_ids": [],
                    "severity": None,
                    "advisory_summaries": [],
                },
            ]
            research = enrich_vulnerabilities(
                github_report={"language": "unknown", "dependency_files": {"lockfiles": [], "manifests": []}},
                package_version_map=inventory.package_version_map,
                package_metadata_map=inventory.package_metadata_map,
                dependencies=[dep.model_dump() for dep in inventory.dependencies],
            )

        self.assertEqual(query_osv.call_count, 2)
        called = {(call.args[0], call.args[1], call.args[2]) for call in query_osv.call_args_list}
        self.assertEqual(
            called,
            {
                ("transformers", "PyPI", "4.35.2"),
                ("compromise", "npm", "14.12.0"),
            },
        )
        self.assertEqual(research.packages_checked_count, 2)
        self.assertEqual(len(research.skipped_packages), 0)

    def test_llm_context_is_compact_and_summarized(self):
        inventory = DependencyInventory(
            repo_url="https://github.com/example/repo",
            dependencies=[
                NormalizedDependency(
                    name=f"package-{index}",
                    version=">=1,<2",
                    version_kind=VersionKind.RANGE,
                    version_specifier=">=1,<2",
                    ecosystem="PyPI",
                    source_type=DependencySourceType.GITHUB_SBOM,
                )
                for index in range(25)
            ],
            warning_details=[
                {
                    "code": "NON_EXACT_VERSION",
                    "package": f"package-{index}",
                    "message": "Dependency version is not exact.",
                }
                for index in range(25)
            ],
        )
        research = VulnerabilityResearch(
            skipped_packages=[
                {
                    "package_name": f"package-{index}",
                    "version": ">=1,<2",
                    "version_kind": "range",
                    "provider": "OSV",
                    "reason": "non_exact_version",
                }
                for index in range(25)
            ]
        )
        context = build_llm_context(
            report={
                "input_type": "github_repo",
                "mode": "detailed",
                "repo_url": inventory.repo_url,
                "language": "python",
                "route": {"mode_source": "explicit"},
                "warning_details": inventory.warning_details,
                "warnings": [],
            },
            inventory=inventory,
            vulnerability_research=research,
            metadata_enrichment=[],
        )

        self.assertEqual(context["scan_summary"]["total_dependencies"], 25)
        self.assertEqual(context["scan_summary"]["range_versions"], 25)
        self.assertLessEqual(len(context["top_uncertainties"]), 10)
        self.assertLessEqual(len(context["important_dependencies"]), 10)
        self.assertEqual(context["warning_summary"][0]["count"], 25)

    def test_llm_context_includes_richer_vulnerability_details(self):
        inventory = DependencyInventory(
            repo_url="https://github.com/example/repo",
            dependencies=[
                NormalizedDependency(
                    name="requests",
                    version="2.31.0",
                    version_kind=VersionKind.EXACT,
                    ecosystem="PyPI",
                    source_type=DependencySourceType.GITHUB_FILE,
                    relationship="direct",
                    file_path="requirements.txt",
                )
            ],
        )
        research = VulnerabilityResearch(
            packages_checked_count=1,
            packages_checked=[
                VulnerabilityFinding(
                    package_name="requests",
                    version_checked="2.31.0",
                    vulnerability_count=1,
                    cve_ids=["CVE-TEST-1"],
                    vulnerability_ids=["GHSA-test-1"],
                    ecosystem_used="PyPI",
                    match_confidence="exact",
                    severity="high",
                    relationship="direct",
                    source_type="github_file",
                    file_path="requirements.txt",
                    advisory_summaries=[
                        {
                            "id": "GHSA-test-1",
                            "aliases": ["CVE-TEST-1"],
                            "severity": "high",
                            "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                            "details": None,
                        }
                    ],
                    nvd_details=[
                        CVEEnrichment(
                            cve_id="CVE-TEST-1",
                            severity="high",
                            description="Improper certificate verification could allow a man-in-the-middle attack.",
                        )
                    ],
                )
            ],
            cves_found=["CVE-TEST-1"],
        )
        context = build_llm_context(
            report={
                "input_type": "github_repo",
                "mode": "developer",
                "repo_url": inventory.repo_url,
                "language": "python",
                "route": {"mode_source": "explicit"},
                "warning_details": [],
                "warnings": [],
            },
            inventory=inventory,
            vulnerability_research=research,
            metadata_enrichment=[],
        )

        self.assertEqual(context["vulnerability_details"][0]["package"], "requests")
        self.assertEqual(context["vulnerability_details"][0]["severity"], "high")
        self.assertEqual(context["vulnerability_details"][0]["relationship"], "direct")
        self.assertTrue(context["vulnerability_details"][0]["advisories"])
        self.assertIn("exact-version vulnerable dependency", context["vulnerability_details"][0]["priority_reason"])

    def test_llm_context_builds_package_analysis_with_license_and_links(self):
        inventory = DependencyInventory(
            repo_url="https://github.com/example/repo",
            dependencies=[
                NormalizedDependency(
                    name="requests",
                    version="2.31.0",
                    version_kind=VersionKind.EXACT,
                    ecosystem="PyPI",
                    source_type=DependencySourceType.GITHUB_FILE,
                    relationship="direct",
                    file_path="requirements.txt",
                ),
                NormalizedDependency(
                    name="urllib3",
                    version=">=1.26,<3",
                    version_kind=VersionKind.RANGE,
                    version_specifier=">=1.26,<3",
                    ecosystem="PyPI",
                    source_type=DependencySourceType.GITHUB_FILE,
                    file_path="requirements.txt",
                ),
            ],
        )
        research = VulnerabilityResearch(
            packages_checked_count=1,
            packages_checked=[
                VulnerabilityFinding(
                    package_name="requests",
                    version_checked="2.31.0",
                    vulnerability_count=1,
                    cve_ids=["CVE-TEST-1"],
                    vulnerability_ids=["GHSA-test-1"],
                    ecosystem_used="PyPI",
                    match_confidence="exact",
                    severity="high",
                    relationship="direct",
                    source_type="github_file",
                    file_path="requirements.txt",
                    advisory_summaries=[
                        {
                            "id": "GHSA-test-1",
                            "aliases": ["CVE-TEST-1"],
                            "severity": "high",
                            "summary": "Improper certificate verification could allow a man-in-the-middle attack.",
                            "details": None,
                        }
                    ],
                )
            ],
            cves_found=["CVE-TEST-1"],
        )
        metadata = [
            MetadataEnrichment(
                provider="deps.dev",
                status="success",
                data={
                    "packages": [
                        {
                            "name": "requests",
                            "version": "2.31.0",
                            "licenses": [{"spdx": "Apache-2.0"}],
                            "advisory_keys": ["GHSA-test-1"],
                            "links": {"source": "https://github.com/psf/requests"},
                            "published_at": "2024-01-01T00:00:00Z",
                            "is_default": True,
                        }
                    ],
                    "packages_checked_count": 1,
                    "skipped": [],
                    "skipped_count": 0,
                },
            )
        ]

        context = build_llm_context(
            report={
                "input_type": "github_repo",
                "mode": "detailed",
                "repo_url": inventory.repo_url,
                "language": "python",
                "route": {"mode_source": "explicit"},
                "warning_details": [],
                "warnings": [],
            },
            inventory=inventory,
            vulnerability_research=research,
            metadata_enrichment=metadata,
        )

        package = context["package_analysis"]["packages"][0]
        self.assertEqual(package["name"], "requests")
        self.assertEqual(package["licenses"], ["Apache-2.0"])
        self.assertEqual(package["license_category"], "permissive")
        self.assertTrue(package["links"])
        self.assertEqual(context["package_analysis"]["unresolved_packages"][0]["name"], "urllib3")


if __name__ == "__main__":
    unittest.main()
