import asyncio
import unittest
from unittest.mock import patch

import httpx

from app.schemas import (
    DependencyInventory,
    DependencySourceType,
    InputType,
    NormalizedDependency,
    VersionKind,
    VulnerabilityFinding,
    VulnerabilityResearch,
)
from app.services.dependency_graph import deps_graph


class FakeJsonResponse:
    def __init__(self, *, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.request = httpx.Request("GET", "https://example.test")

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=self.request, response=httpx.Response(self.status_code, request=self.request))

    def json(self):
        return self._payload


class DependencyGraphTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        deps_graph._GRAPH_CACHE.clear()

    def tearDown(self):
        deps_graph._GRAPH_CACHE.clear()

    async def test_fetch_with_retry_retries_on_429(self):
        class FakeClient:
            def __init__(self):
                self.calls = 0

            async def get(self, url):
                self.calls += 1
                if self.calls == 1:
                    return FakeJsonResponse(status_code=429)
                return FakeJsonResponse(payload={"nodes": [], "edges": []})

        client = FakeClient()
        payload = await deps_graph._fetch_with_retry(
            client=client,
            url="https://example.test",
            semaphore=asyncio.Semaphore(5),
        )
        self.assertEqual(client.calls, 2)
        self.assertEqual(payload, {"nodes": [], "edges": []})

    async def test_normalize_graph_keeps_only_direct_dependencies(self):
        dependency = NormalizedDependency(
            name="requests",
            version="2.31.0",
            version_kind=VersionKind.EXACT,
            ecosystem="PyPI",
            source_type=DependencySourceType.DIRECT_PACKAGE,
        )
        payload = {
            "nodes": [
                {"relation": "SELF", "versionKey": {"name": "requests", "version": "2.31.0"}},
                {"relation": "DIRECT", "versionKey": {"name": "urllib3", "version": "1.26.18"}},
                {"relation": "DIRECT", "versionKey": {"name": "charset-normalizer", "version": "3.3.2"}},
                {"relation": "INDIRECT", "versionKey": {"name": "certifi", "version": "2024.2.2"}},
            ],
            "edges": [],
        }
        graph = deps_graph._normalize_graph_payload(
            dependency=dependency,
            payload=payload,
            max_dependencies=10,
        )
        self.assertEqual(
            graph["dependencies"],
            [
                {"name": "urllib3", "version": "1.26.18"},
                {"name": "charset-normalizer", "version": "3.3.2"},
            ],
        )
        self.assertEqual(graph["dependency_count"], 2)

    async def test_collect_dependency_graphs_respects_semaphore_limit(self):
        original = deps_graph._fetch_graph_for_dependency
        max_active = 0
        active = 0

        async def fake_fetch_graph_for_dependency(*, dependency, client, semaphore, max_dependencies):
            nonlocal active, max_active
            async with semaphore:
                active += 1
                max_active = max(max_active, active)
                await asyncio.sleep(0.01)
                active -= 1
            return (
                f"{dependency.name}@{dependency.version}",
                {
                    "package": dependency.name,
                    "version": dependency.version,
                    "dependencies": [],
                    "dependency_count": 0,
                    "truncated": False,
                    "source": "deps.dev",
                },
            )

        dependencies = [
            NormalizedDependency(
                name=f"pkg{i}",
                version="1.0.0",
                version_kind=VersionKind.EXACT,
                ecosystem="PyPI",
                source_type=DependencySourceType.DIRECT_PACKAGE,
            )
            for i in range(8)
        ]

        with patch.object(deps_graph, "_fetch_graph_for_dependency", side_effect=fake_fetch_graph_for_dependency):
            graphs = await deps_graph._collect_dependency_graphs_async(
                dependencies=dependencies,
                max_dependencies=10,
            )

        self.assertEqual(len(graphs), 8)
        self.assertLessEqual(max_active, 5)
        self.assertIsNotNone(original)

    def test_fetch_dependency_graphs_uses_cache(self):
        inventory = DependencyInventory(
            input_type=InputType.PACKAGE,
            dependencies=[
                NormalizedDependency(
                    name="requests",
                    version="2.31.0",
                    version_kind=VersionKind.EXACT,
                    ecosystem="PyPI",
                    source_type=DependencySourceType.DIRECT_PACKAGE,
                )
            ],
        )
        vulnerability_research = VulnerabilityResearch(
            packages_checked=[
                VulnerabilityFinding(
                    package_name="requests",
                    version_checked="2.31.0",
                    vulnerability_count=1,
                    cve_ids=["CVE-TEST-1"],
                    vulnerability_ids=["GHSA-test-1"],
                    ecosystem_used="PyPI",
                    version_kind=VersionKind.EXACT,
                    match_confidence="exact",
                    severity="high",
                    relationship="direct",
                )
            ]
        )

        class FakeAsyncClient:
            call_count = 0

            def __init__(self, *args, **kwargs):
                return None

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def get(self, url):
                FakeAsyncClient.call_count += 1
                return FakeJsonResponse(
                    payload={
                        "nodes": [
                            {"relation": "SELF", "versionKey": {"name": "requests", "version": "2.31.0"}},
                            {"relation": "DIRECT", "versionKey": {"name": "urllib3", "version": "1.26.18"}},
                        ],
                        "edges": [],
                    }
                )

        with patch("app.services.dependency_graph.deps_graph.httpx.AsyncClient", FakeAsyncClient):
            first = deps_graph.fetch_dependency_graphs_for_inventory(
                inventory=inventory,
                vulnerability_research=vulnerability_research,
            )
            second = deps_graph.fetch_dependency_graphs_for_inventory(
                inventory=inventory,
                vulnerability_research=vulnerability_research,
            )

        self.assertIn("requests@2.31.0", first)
        self.assertEqual(first, second)
        self.assertEqual(FakeAsyncClient.call_count, 1)


if __name__ == "__main__":
    unittest.main()
