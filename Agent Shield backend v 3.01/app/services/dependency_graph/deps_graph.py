import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

try:
    from app.config import get_config
    from app.schemas import DependencyInventory, NormalizedDependency, VulnerabilityResearch, VersionKind
except ModuleNotFoundError:
    from config import get_config
    from schemas import DependencyInventory, NormalizedDependency, VulnerabilityResearch, VersionKind


_GRAPH_CACHE: Dict[str, Dict[str, Any]] = {}
_MAX_GRAPH_PACKAGES = 5
_MAX_GRAPH_DEPENDENCIES = 10
_GRAPH_CONCURRENCY = 5
_GRAPH_RETRIES = 3
_GRAPH_BACKOFF_SECONDS = 0.5


def _system_from_ecosystem(ecosystem: str) -> str:
    normalized = str(ecosystem or "").strip().lower()
    if normalized in {"pypi", "python"}:
        return "pypi"
    if normalized in {"npm", "javascript", "node"}:
        return "npm"
    if normalized == "maven":
        return "maven"
    if normalized in {"go", "golang"}:
        return "go"
    if normalized in {"crates.io", "cargo"}:
        return "cargo"
    return normalized


def _severity_value(value: Optional[str]) -> int:
    ranking = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1}
    return ranking.get(str(value or "").strip().lower(), 0)


def _graph_cache_key(name: str, version: str, ecosystem: str) -> str:
    return f"{_system_from_ecosystem(ecosystem)}:{name}@{version}"


def _graph_response_key(name: str, version: str) -> str:
    return f"{name}@{version}"


def _is_valid_graph_dependency(dep: Optional[NormalizedDependency]) -> bool:
    return bool(
        dep
        and dep.name
        and dep.version
        and dep.ecosystem
        and dep.version_kind == VersionKind.EXACT
    )


def _select_graph_packages(
    *,
    inventory: DependencyInventory,
    vulnerability_research: VulnerabilityResearch,
    limit: int = _MAX_GRAPH_PACKAGES,
) -> List[NormalizedDependency]:
    dependency_map = {
        (dep.name, dep.version): dep
        for dep in inventory.exact_dependencies
        if _is_valid_graph_dependency(dep)
    }
    ranked: List[Tuple[Tuple[int, int, int, str, str], NormalizedDependency]] = []
    for finding in vulnerability_research.packages_checked:
        if int(finding.vulnerability_count or 0) <= 0:
            continue
        key = (finding.package_name, finding.version_checked)
        dep = dependency_map.get(key)
        if not dep:
            continue
        ranked.append(
            (
                (
                    _severity_value(finding.severity),
                    1 if finding.match_confidence == "exact" else 0,
                    1 if str(finding.relationship or "").strip().lower() == "direct" else 0,
                    dep.name,
                    dep.version,
                ),
                dep,
            )
        )
    ranked.sort(key=lambda item: item[0], reverse=True)
    selected: List[NormalizedDependency] = []
    seen = set()
    for _, dep in ranked:
        cache_key = _graph_cache_key(dep.name, dep.version, dep.ecosystem)
        if cache_key in seen:
            continue
        seen.add(cache_key)
        selected.append(dep)
        if len(selected) >= limit:
            break
    return selected


def _extract_name_and_version(version_key: Dict[str, Any]) -> Tuple[str, str]:
    name = str(version_key.get("name") or version_key.get("package") or "").strip()
    version = str(version_key.get("version") or "").strip()
    return name, version


def _build_direct_dependencies_from_nodes(
    payload: Dict[str, Any],
    *,
    max_dependencies: int,
) -> List[Dict[str, str]]:
    nodes = list(payload.get("nodes") or [])
    dependencies: List[Dict[str, str]] = []
    seen = set()

    for node in nodes:
        if not isinstance(node, dict):
            continue
        relation = str(node.get("relation") or "").strip().upper()
        if relation != "DIRECT":
            continue
        version_key = node.get("versionKey") or node.get("version_key") or {}
        if not isinstance(version_key, dict):
            continue
        name, version = _extract_name_and_version(version_key)
        if not name:
            continue
        identifier = (name, version)
        if identifier in seen:
            continue
        seen.add(identifier)
        dependencies.append({"name": name, "version": version})
        if len(dependencies) >= max_dependencies:
            break
    return dependencies


def _build_direct_dependencies_from_edges(
    payload: Dict[str, Any],
    *,
    max_dependencies: int,
) -> List[Dict[str, str]]:
    nodes = list(payload.get("nodes") or [])
    if not nodes:
        return []

    root_index = None
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        relation = str(node.get("relation") or "").strip().upper()
        if relation == "SELF":
            root_index = index
            break
    if root_index is None:
        root_index = 0

    dependencies: List[Dict[str, str]] = []
    seen = set()
    for edge in list(payload.get("edges") or []):
        if not isinstance(edge, dict):
            continue
        from_index = edge.get("fromNode") if edge.get("fromNode") is not None else edge.get("from")
        to_index = edge.get("toNode") if edge.get("toNode") is not None else edge.get("to")
        if from_index != root_index:
            continue
        if not isinstance(to_index, int) or to_index < 0 or to_index >= len(nodes):
            continue
        node = nodes[to_index]
        if not isinstance(node, dict):
            continue
        version_key = node.get("versionKey") or node.get("version_key") or {}
        if not isinstance(version_key, dict):
            continue
        name, version = _extract_name_and_version(version_key)
        if not name:
            continue
        identifier = (name, version)
        if identifier in seen:
            continue
        seen.add(identifier)
        dependencies.append({"name": name, "version": version})
        if len(dependencies) >= max_dependencies:
            break
    return dependencies


def _normalize_graph_payload(
    *,
    dependency: NormalizedDependency,
    payload: Dict[str, Any],
    max_dependencies: int,
) -> Dict[str, Any]:
    direct_dependencies = _build_direct_dependencies_from_nodes(payload, max_dependencies=max_dependencies)
    if not direct_dependencies:
        direct_dependencies = _build_direct_dependencies_from_edges(payload, max_dependencies=max_dependencies)

    total_direct = len(_build_direct_dependencies_from_nodes(payload, max_dependencies=10_000)) or len(
        _build_direct_dependencies_from_edges(payload, max_dependencies=10_000)
    )
    return {
        "package": dependency.name,
        "version": dependency.version,
        "ecosystem": dependency.ecosystem,
        "dependencies": direct_dependencies,
        "dependency_count": total_direct,
        "truncated": total_direct > len(direct_dependencies),
        "source": "deps.dev",
    }


async def _fetch_with_retry(
    *,
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
) -> Optional[Dict[str, Any]]:
    delay = _GRAPH_BACKOFF_SECONDS
    last_error: Optional[Exception] = None
    for attempt in range(_GRAPH_RETRIES):
        try:
            async with semaphore:
                response = await client.get(url)
            if response.status_code == 429:
                if attempt == _GRAPH_RETRIES - 1:
                    return None
                await asyncio.sleep(delay)
                delay *= 2
                continue
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            last_error = exc
            if exc.response.status_code == 429 and attempt < _GRAPH_RETRIES - 1:
                await asyncio.sleep(delay)
                delay *= 2
                continue
            return None
        except httpx.HTTPError as exc:
            last_error = exc
            if attempt < _GRAPH_RETRIES - 1:
                await asyncio.sleep(delay)
                delay *= 2
                continue
            return None
    if last_error:
        return None
    return None


async def _fetch_graph_for_dependency(
    *,
    dependency: NormalizedDependency,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    max_dependencies: int,
) -> Optional[Tuple[str, Dict[str, Any]]]:
    cache_key = _graph_cache_key(dependency.name, dependency.version, dependency.ecosystem)
    cached = _GRAPH_CACHE.get(cache_key)
    if cached is not None:
        return _graph_response_key(dependency.name, dependency.version), cached

    system = _system_from_ecosystem(dependency.ecosystem)
    if not system:
        return None
    url = (
        f"https://api.deps.dev/v3/systems/{quote(system, safe='')}"
        f"/packages/{quote(dependency.name, safe='')}/versions/{quote(dependency.version, safe='')}:dependencies"
    )
    payload = await _fetch_with_retry(client=client, url=url, semaphore=semaphore)
    if not isinstance(payload, dict):
        return None
    graph = _normalize_graph_payload(dependency=dependency, payload=payload, max_dependencies=max_dependencies)
    _GRAPH_CACHE[cache_key] = graph
    return _graph_response_key(dependency.name, dependency.version), graph


async def _collect_dependency_graphs_async(
    *,
    dependencies: List[NormalizedDependency],
    max_dependencies: int,
) -> Dict[str, Dict[str, Any]]:
    settings = get_config()
    semaphore = asyncio.Semaphore(_GRAPH_CONCURRENCY)
    timeout = httpx.Timeout(settings.request_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [
            _fetch_graph_for_dependency(
                dependency=dependency,
                client=client,
                semaphore=semaphore,
                max_dependencies=max_dependencies,
            )
            for dependency in dependencies
        ]
        results = await asyncio.gather(*tasks)
    graphs: Dict[str, Dict[str, Any]] = {}
    for item in results:
        if not item:
            continue
        key, graph = item
        graphs[key] = graph
    return graphs


def fetch_dependency_graphs_for_inventory(
    *,
    inventory: DependencyInventory,
    vulnerability_research: VulnerabilityResearch,
    limit: int = _MAX_GRAPH_PACKAGES,
    max_dependencies: int = _MAX_GRAPH_DEPENDENCIES,
) -> Dict[str, Dict[str, Any]]:
    selected = _select_graph_packages(
        inventory=inventory,
        vulnerability_research=vulnerability_research,
        limit=limit,
    )
    if not selected:
        return {}
    coroutine = _collect_dependency_graphs_async(
        dependencies=selected,
        max_dependencies=max_dependencies,
    )
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coroutine).result()
