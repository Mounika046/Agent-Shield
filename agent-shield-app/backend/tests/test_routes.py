import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import DependencyInventory, DependencySourceType, InputType, MetadataEnrichment, NormalizedDependency, VersionKind


def fake_osv(package_name, ecosystem, version, config=None):
    return {
        "package_name": package_name,
        "version_checked": version,
        "vulnerability_count": 0,
        "cve_ids": [],
        "vulnerability_ids": [],
        "severity": None,
        "advisory_summaries": [],
    }


class RouteIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.llm_patcher = patch(
            "app.controller.chat_controller.get_default_llm_with_status",
            return_value=(None, {"llm_available": False, "llm_fallback_reason": None}),
        )
        self.osv_patcher = patch("app.services.vulnerability.research.query_osv", side_effect=fake_osv)
        self.graph_patcher = patch(
            "app.agents.unified_scan_agent.fetch_dependency_graphs_for_inventory",
            return_value={
                "pandas@2.2.1": {
                    "package": "pandas",
                    "version": "2.2.1",
                    "ecosystem": "PyPI",
                    "dependencies": [{"name": "numpy", "version": "1.26.4"}],
                    "dependency_count": 1,
                    "truncated": False,
                    "source": "deps.dev",
                }
            },
        )
        self.llm_patcher.start()
        self.osv_patcher.start()
        self.graph_patcher.start()

    def tearDown(self):
        self.osv_patcher.stop()
        self.llm_patcher.stop()
        self.graph_patcher.stop()

    def test_scan_single_direct_package_route(self):
        response = self.client.post(
            "/scan",
            json={"package_name": "pandas", "package_version": "2.2.1", "ecosystem": "PyPI", "mode": "fast"},
        )

        self.assertEqual(response.status_code, 200)
        report = response.json()["json_report"]
        self.assertEqual(report["llm_context"]["scan_summary"]["exact_versions"], 1)
        self.assertEqual(report["llm_context"]["scan_summary"]["packages_skipped_for_exact_matching"], 0)

    def test_scan_multi_direct_package_route(self):
        response = self.client.post(
            "/scan",
            json={
                "packages": [
                    {"package_name": "transformers", "package_version": "4.35.2", "ecosystem": "PyPI"},
                    {"package_name": "compromise", "package_version": "14.12.0", "ecosystem": "npm"},
                ],
                "mode": "fast",
            },
        )

        self.assertEqual(response.status_code, 200)
        report = response.json()["json_report"]
        self.assertEqual(report["total_packages"], 2)
        self.assertEqual(report["llm_context"]["scan_summary"]["exact_versions"], 2)
        self.assertEqual(report["llm_context"]["scan_summary"]["packages_skipped_for_exact_matching"], 0)

    def test_scan_dependency_file_route(self):
        response = self.client.post(
            "/scan",
            json={
                "file_name": "requirements.txt",
                "file_content": "requests==2.31.0\nflask>=2.3.0\n",
                "mode": "fast",
            },
        )

        self.assertEqual(response.status_code, 200)
        summary = response.json()["json_report"]["llm_context"]["scan_summary"]
        self.assertEqual(summary["exact_versions"], 1)
        self.assertEqual(summary["range_versions"], 1)
        self.assertEqual(summary["packages_skipped_for_exact_matching"], 1)

    def test_scan_versionless_dependency_file_route_reports_discovery_only(self):
        response = self.client.post(
            "/scan",
            json={
                "file_name": "requirements.txt",
                "file_content": "oci-openai\npython-dotenv\nfastapi\nuvicorn\n",
                "mode": "fast",
            },
        )

        self.assertEqual(response.status_code, 200)
        report = response.json()["json_report"]
        summary = report["llm_context"]["scan_summary"]
        self.assertEqual(report["result_type"], "discovery_only")
        self.assertEqual(report["total_packages"], 4)
        self.assertEqual(summary["exact_versions"], 0)
        self.assertEqual(summary["unknown_versions"], 4)

    def test_scan_raw_dependency_list_route(self):
        response = self.client.post(
            "/scan",
            json={
                "raw_text": "requests==2.31.0\nflask==2.3.3\n",
                "mode": "fast",
            },
        )

        self.assertEqual(response.status_code, 200)
        report = response.json()["json_report"]
        self.assertEqual(report["input_type"], "dependency_file")
        self.assertEqual(report["total_packages"], 2)

    def test_scan_raw_name_only_dependency_list_route(self):
        response = self.client.post(
            "/scan",
            json={
                "raw_text": "oci-openai\npython-dotenv\nfastapi\nuvicorn\n",
                "mode": "fast",
            },
        )

        self.assertEqual(response.status_code, 200)
        report = response.json()["json_report"]
        self.assertEqual(report["input_type"], "dependency_file")
        self.assertEqual(report["result_type"], "discovery_only")
        self.assertEqual(report["total_packages"], 4)

    def test_scan_repo_route_with_token(self):
        captured = {}

        def fake_repo_inventory(repo_url, token=None):
            captured["repo_url"] = repo_url
            captured["token"] = token
            return DependencyInventory(
                repo_url=repo_url,
                input_type=InputType.GITHUB_REPO,
                language="python",
                has_lockfile=True,
                dependencies=[
                    NormalizedDependency(
                        name="requests",
                        version="2.31.0",
                        version_kind=VersionKind.EXACT,
                        ecosystem="PyPI",
                        source_type=DependencySourceType.GITHUB_FILE,
                        relationship="direct",
                    )
                ],
            )

        with patch("app.agents.unified_scan_agent.acquire_github_dependency_inventory", side_effect=fake_repo_inventory):
            response = self.client.post(
                "/scan",
                json={"repo_url": "https://github.com/example/repo", "token": "ghp_test", "mode": "fast"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(captured, {"repo_url": "https://github.com/example/repo", "token": "ghp_test"})
        self.assertEqual(response.json()["json_report"]["input_type"], "github_repo")

    def test_agent_chat_clarification_route(self):
        response = self.client.post("/agent/chat", json={"message": "check requests"})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "needs_clarification")
        self.assertFalse(payload["backend_called"])
        self.assertFalse(payload["response_meta"]["llm_output_stage"])

    def test_agent_chat_deterministic_fallback_route(self):
        response = self.client.post(
            "/agent/chat",
            json={"message": "check pandas 2.2.1 python package"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "completed")
        self.assertTrue(payload["backend_called"])
        self.assertFalse(payload["response_meta"]["llm_available"])
        self.assertIn("llm_response", payload)
        self.assertIn("cards", payload)
        self.assertIn("dependencies_discovered_table", payload)
        self.assertIn("vulnerable_dependencies_table", payload)

    def test_agent_chat_detailed_mode_includes_fix_analysis_fields(self):
        response = self.client.post(
            "/agent/chat",
            json={"message": "check pandas 2.2.1 python package", "mode": "detailed"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "completed")
        self.assertIn("fix_analysis", payload)
        self.assertIn("license_sources", payload)

    def test_agent_chat_developer_mode_includes_dependency_graphs(self):
        response = self.client.post(
            "/agent/chat",
            json={"message": "check pandas 2.2.1 python package", "mode": "developer"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("dependency_graphs", payload)
        self.assertIn("pandas@2.2.1", payload["dependency_graphs"])

    def test_agent_chat_detailed_mode_returns_license_table_when_deps_dev_enrichment_exists(self):
        fake_enrichment = MetadataEnrichment(
            provider="deps.dev",
            status="success",
            data={
                "packages": [
                    {
                        "name": "pandas",
                        "version": "2.2.1",
                        "licenses": ["BSD-3-Clause"],
                        "advisory_keys": [],
                        "links": {
                            "source": "https://github.com/pandas-dev/pandas",
                        },
                        "published_at": "2024-01-01T00:00:00Z",
                        "is_default": True,
                    }
                ],
                "packages_checked_count": 1,
                "skipped": [],
                "skipped_count": 0,
            },
            errors=[],
        )
        with patch("app.agents.unified_scan_agent.enrich_with_deps_dev", return_value=fake_enrichment):
            response = self.client.post(
                "/agent/chat",
                json={"message": "check pandas 2.2.1 python package", "mode": "detailed"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["license_compliance_table"])
        self.assertEqual(payload["license_compliance_table"][0]["package"], "pandas")
        self.assertEqual(payload["license_compliance_table"][0]["detected_license"], "BSD-3-Clause")
        self.assertEqual(payload["license_compliance_table"][0]["source"], "deps.dev")
        self.assertEqual(payload["license_compliance_table"][0]["policy_status"], "Allowed")
        self.assertIn("permissive license", payload["license_compliance_table"][0]["reason"])
        self.assertTrue(payload["license_compliance_table"][0]["source_links"])

    def test_agent_chat_package_phrase_with_version_keyword_still_returns_findings(self):
        response = self.client.post(
            "/agent/chat",
            json={"message": "check requests version 2.31.0 it is a python package", "mode": "fast"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "completed")
        self.assertTrue(payload["backend_called"])
        self.assertGreaterEqual(payload["cards"]["packages_checked"], 1)
        self.assertEqual(payload["dependencies_discovered_table"][0]["package"], "requests")

    def test_agent_chat_repo_token_is_redacted_in_response(self):
        with patch("app.agents.unified_scan_agent.acquire_github_dependency_inventory") as fake_repo_inventory:
            fake_repo_inventory.return_value = DependencyInventory(
                repo_url="https://github.com/example/repo",
                input_type=InputType.GITHUB_REPO,
                language="python",
                has_lockfile=True,
                dependencies=[
                    NormalizedDependency(
                        name="requests",
                        version="2.31.0",
                        version_kind=VersionKind.EXACT,
                        ecosystem="PyPI",
                        source_type=DependencySourceType.GITHUB_FILE,
                        relationship="direct",
                    )
                ],
            )
            response = self.client.post(
                "/agent/chat",
                json={
                    "message": "scan this private repo",
                    "repo_url": "https://github.com/example/repo",
                    "token": "github_pat_secret_value",
                    "mode": "fast",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["backend_payload"]["token"], "***redacted***")

    def test_agent_chat_include_debug_still_redacts_token(self):
        with patch("app.agents.unified_scan_agent.acquire_github_dependency_inventory") as fake_repo_inventory:
            fake_repo_inventory.return_value = DependencyInventory(
                repo_url="https://github.com/example/repo",
                input_type=InputType.GITHUB_REPO,
                language="python",
                has_lockfile=True,
                dependencies=[
                    NormalizedDependency(
                        name="requests",
                        version="2.31.0",
                        version_kind=VersionKind.EXACT,
                        ecosystem="PyPI",
                        source_type=DependencySourceType.GITHUB_FILE,
                        relationship="direct",
                    )
                ],
            )
            response = self.client.post(
                "/agent/chat",
                json={
                    "message": "scan this private repo",
                    "repo_url": "https://github.com/example/repo",
                    "token": "github_pat_secret_value",
                    "mode": "fast",
                    "include_debug": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["backend_payload"]["token"], "***redacted***")
        self.assertNotIn("github_pat_secret_value", str(payload))

    def test_agent_chat_repo_wording_wins_when_message_mentions_file(self):
        with patch("app.agents.unified_scan_agent.acquire_github_dependency_inventory") as fake_repo_inventory:
            fake_repo_inventory.return_value = DependencyInventory(
                repo_url="https://github.com/example/repo",
                input_type=InputType.GITHUB_REPO,
                language="python",
                has_lockfile=True,
                dependencies=[
                    NormalizedDependency(
                        name="requests",
                        version="2.31.0",
                        version_kind=VersionKind.EXACT,
                        ecosystem="PyPI",
                        source_type=DependencySourceType.GITHUB_FILE,
                        relationship="direct",
                    )
                ],
            )
            response = self.client.post(
                "/agent/chat",
                json={
                    "message": "analyze this dependency file",
                    "repo_url": "https://github.com/example/repo",
                    "mode": "fast",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["input_type"], "github_repo")
        self.assertIn("`https://github.com/example/repo`", payload["message"])

    def test_agent_chat_versionless_file_explains_discovery_only_limitation(self):
        response = self.client.post(
            "/agent/chat",
            json={
                "message": "analyze this dependency file",
                "file_name": "requirements.txt",
                "file_content": "oci-openai\npython-dotenv\nfastapi\nuvicorn\n",
                "mode": "fast",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["response_meta"]["result_type"], "discovery_only")
        self.assertIn("I found these packages in `requirements.txt`", payload["message"])
        self.assertIn("could not run reliable vulnerability matching", payload["message"])

    def test_agent_chat_uploaded_file_is_forwarded_as_file_input(self):
        response = self.client.post(
            "/agent/chat",
            json={
                "message": "analyze this dependency file",
                "file_name": "requirements.txt",
                "file_content": "requests==2.31.0\nflask==2.3.3\n",
                "mode": "fast",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["input_type"], "dependency_file")
        self.assertTrue(payload["backend_called"])
        self.assertEqual(payload["backend_payload"]["file_name"], "requirements.txt")
        self.assertEqual(payload["backend_payload"]["file_content"], "requests==2.31.0\nflask==2.3.3\n")

    def test_agent_chat_empty_file_content_requests_clarification(self):
        response = self.client.post(
            "/agent/chat",
            json={
                "message": "analyze this dependency file",
                "file_name": "requirements.txt",
                "file_content": "",
                "mode": "fast",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "needs_clarification")
        self.assertFalse(payload["backend_called"])
        self.assertIn("provide the contents", payload["message"].lower())

    def test_agent_chat_mocked_llm_route(self):
        class FakeLLM:
            def __init__(self):
                self.calls = []

            def complete(self, *, system_prompt, user_payload):
                self.calls.append(user_payload)
                if "provided_fields" in user_payload:
                    return (
                        '{"action":"execute","backend_payload":{"repo_url":null,"token":null,'
                        '"packages":[{"package_name":"pandas","package_version":"2.2.1","ecosystem":"PyPI"}],'
                        '"package_name":"pandas","package_version":"2.2.1","ecosystem":"PyPI",'
                        '"file_name":null,"file_content":null,"mode":"fast","raw_text":"check pandas"}}'
                    )
                return "LLM final answer"

        fake_llm = FakeLLM()
        with patch("app.controller.chat_controller.get_default_llm_with_status", return_value=(fake_llm, {"llm_available": True, "llm_fallback_reason": None})):
            response = self.client.post("/agent/chat", json={"message": "check pandas"})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["message"], "LLM final answer")
        self.assertEqual(payload["llm_response"], "LLM final answer")
        self.assertTrue(payload["response_meta"]["llm_input_stage"])
        self.assertTrue(payload["response_meta"]["llm_output_stage"])


if __name__ == "__main__":
    unittest.main()
