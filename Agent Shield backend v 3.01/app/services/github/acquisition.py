from typing import Any, Dict, List, Optional
from urllib.parse import unquote

try:
    from app.models.models import Dependency
    from app.parsers import parse_dependency_file
    from app.schemas import DependencyInventory, DependencySourceType, InputType, NormalizedDependency
    from app.services.discovery import classify_inventory_result
    from app.services.github.client import GitHubClient
    from app.services.versioning import normalize_version_fields
    from app.utils.repo_utils import collect_file_paths, detect_language_from_structure, find_dependency_files
except ModuleNotFoundError:
    from models.models import Dependency
    from parsers import parse_dependency_file
    from schemas import DependencyInventory, DependencySourceType, InputType, NormalizedDependency
    from services.discovery import classify_inventory_result
    from services.github.client import GitHubClient
    from services.versioning import normalize_version_fields
    from utils.repo_utils import collect_file_paths, detect_language_from_structure, find_dependency_files


def detect_has_lockfile(language: str, dependency_files: Dict[str, List[str]]) -> bool:
    lockfiles = dependency_files.get("lockfiles", [])
    if language == "python" and any(lf.endswith(("poetry.lock", "Pipfile.lock", "requirements.txt")) for lf in lockfiles):
        return True
    if language == "javascript" and any(lf.endswith(("package-lock.json", "yarn.lock", "pnpm-lock.yaml")) for lf in lockfiles):
        return True
    if language == "java" and any(lf.endswith("gradle.lockfile") for lf in lockfiles):
        return True
    return language != "unknown" and bool(lockfiles)


def derive_source_and_ecosystem(filename: str, fallback_language: str) -> tuple[str, str]:
    name = filename.lower()
    if name in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}:
        return "pip", "PyPI"
    if name in {"pyproject.toml", "poetry.lock"}:
        return "poetry", "PyPI"
    if name == "pipfile.lock":
        return "pipenv", "PyPI"
    if name in {"environment.yml", "environment.yaml", "conda.yml", "conda.yaml", "conda-lock.yml", "conda-lock.yaml"}:
        return "conda", "Conda"
    if name in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"}:
        return "npm", "npm"
    if name == "pom.xml":
        return "maven", "Maven"
    if name in {"cargo.toml", "cargo.lock"}:
        return "cargo", "crates.io"
    if name in {"go.mod", "go.sum"}:
        return "go", "Go"
    if fallback_language == "javascript":
        return "npm", "npm"
    if fallback_language == "java":
        return "maven", "Maven"
    return "unknown", "PyPI"


def normalize_dependency(
    dep: Dependency,
    filename: str,
    path: str,
    fallback_language: str,
) -> NormalizedDependency:
    source, ecosystem = derive_source_and_ecosystem(filename, fallback_language)
    version, version_kind, version_specifier = normalize_version_fields(dep.version)
    return NormalizedDependency(
        name=dep.name,
        version=version,
        version_kind=version_kind,
        version_specifier=version_specifier or None,
        language=dep.language,
        source=source,
        ecosystem=ecosystem,
        source_type=DependencySourceType.GITHUB_FILE,
        file_path=path,
        relationship="direct",
    )


def _ecosystem_from_purl(purl: str) -> str:
    lower = purl.lower()
    if lower.startswith("pkg:pypi/"):
        return "PyPI"
    if lower.startswith("pkg:npm/"):
        return "npm"
    if lower.startswith("pkg:maven/"):
        return "Maven"
    if lower.startswith("pkg:golang/"):
        return "Go"
    if lower.startswith("pkg:cargo/"):
        return "crates.io"
    return ""


def _parse_purl(purl: str) -> Dict[str, str]:
    value = (purl or "").strip()
    if not value.startswith("pkg:"):
        return {}
    without_scheme = value[4:]
    purl_type, _, remainder = without_scheme.partition("/")
    if not purl_type or not remainder:
        return {}
    path, _, _qualifiers = remainder.partition("?")
    name_part, _, version = path.rpartition("@")
    if not name_part:
        name_part = path
    return {
        "type": purl_type,
        "name": unquote(name_part),
        "version": unquote(version),
    }


def _find_component_purl(component: Dict[str, Any]) -> str:
    purl = str(component.get("purl", "") or component.get("packageUrl", "")).strip()
    if purl:
        return purl
    for ref in component.get("externalRefs", []) or []:
        if not isinstance(ref, dict):
            continue
        locator = str(ref.get("referenceLocator", "")).strip()
        if locator.startswith("pkg:"):
            return locator
    return ""


def _language_from_ecosystem(ecosystem: str) -> str:
    lower = ecosystem.lower()
    if lower in {"pypi", "python", "conda"}:
        return "python"
    if lower in {"npm", "javascript", "node"}:
        return "javascript"
    if lower == "maven":
        return "java"
    if lower == "go":
        return "go"
    if lower in {"crates.io", "cargo"}:
        return "rust"
    return ""


def _parse_sbom_component(component: Dict[str, Any]) -> Optional[NormalizedDependency]:
    name = str(component.get("name", "")).strip()
    version = str(component.get("version", "") or component.get("versionInfo", "")).strip()
    purl = _find_component_purl(component)
    purl_parts = _parse_purl(purl)
    if (not name or name == "NOASSERTION") and purl_parts.get("name"):
        name = purl_parts["name"]
    if (not version or version == "NOASSERTION") and purl_parts.get("version"):
        version = purl_parts["version"]
    if not name or not version:
        return None

    ecosystem = _ecosystem_from_purl(purl)
    version, version_kind, version_specifier = normalize_version_fields(version)
    return NormalizedDependency(
        name=name,
        version=version,
        version_kind=version_kind,
        version_specifier=version_specifier or None,
        language=_language_from_ecosystem(ecosystem),
        source="github_sbom",
        ecosystem=ecosystem,
        source_type=DependencySourceType.GITHUB_SBOM,
        package_url=purl or None,
        relationship="direct",
        metadata={"sbom_type": component.get("type", "")},
    )


def acquire_github_sbom_inventory(repo_url: str, token: Optional[str] = None) -> DependencyInventory:
    client = GitHubClient(repo_url, token)
    payload = client.fetch_sbom()
    sbom = payload.get("sbom", payload)
    components = sbom.get("packages") or sbom.get("components") or []
    if not components:
        raise RuntimeError("GitHub SBOM response succeeded but contained no package/component entries.")
    dependencies: Dict[str, NormalizedDependency] = {}
    warning_details: List[Dict[str, Any]] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        normalized = _parse_sbom_component(component)
        if not normalized:
            continue
        key = f"{normalized.ecosystem}:{normalized.name}:{normalized.version}".lower()
        dependencies[key] = normalized
        if normalized.version_kind.value != "exact":
            warning_details.append(
                {
                    "code": "NON_EXACT_VERSION",
                    "package": normalized.name,
                    "version": normalized.version,
                    "version_kind": normalized.version_kind.value,
                    "source": "github_sbom",
                    "message": "SBOM dependency version is not exact; exact-version enrichments may be skipped.",
                }
            )

    if not dependencies:
        raise RuntimeError("GitHub SBOM response succeeded but no package/component entries were parseable.")

    first_language = next((dep.language for dep in dependencies.values() if dep.language), "unknown")
    return DependencyInventory(
        repo_url=repo_url,
        language=first_language,
        input_type=InputType.GITHUB_REPO,
        dependency_files={"lockfiles": [], "manifests": []},
        has_lockfile=True,
        dependencies=list(dependencies.values()),
        warnings=["Dependencies acquired from GitHub SBOM."],
        warning_details=[
            {
                "code": "GITHUB_SBOM_USED",
                "message": "Dependencies were acquired from GitHub SBOM.",
                "components_seen": len(components),
                "dependencies_parsed": len(dependencies),
            }
        ]
        + warning_details,
    )


def acquire_github_file_inventory(repo_url: str, token: Optional[str] = None) -> DependencyInventory:
    client = GitHubClient(repo_url, token)
    structure = client.get_structure()
    all_file_paths = collect_file_paths(structure)
    language = detect_language_from_structure(all_file_paths)
    dependency_files = find_dependency_files(all_file_paths)
    has_lockfile = detect_has_lockfile(language, dependency_files)

    parsed_deps: Dict[str, NormalizedDependency] = {}
    warning_details: List[Dict[str, Any]] = []
    for path in dependency_files.get("lockfiles", []) + dependency_files.get("manifests", []):
        content = client.fetch_file(path)
        if not content:
            continue
        filename = path.split("/")[-1]
        for dep in parse_dependency_file(filename, content):
            normalized = normalize_dependency(dep, filename, path, language)
            dep_key = f"{normalized.ecosystem}:{normalized.name}:{normalized.version}:{normalized.file_path}".lower()
            parsed_deps[dep_key] = normalized
            if normalized.version_kind.value != "exact":
                warning_details.append(
                    {
                        "code": "NON_EXACT_VERSION",
                        "package": normalized.name,
                        "version": normalized.version,
                        "version_kind": normalized.version_kind.value,
                        "file_path": path,
                        "message": "Dependency version is not exact; exact-version enrichments may be skipped.",
                    }
                )

    inventory = DependencyInventory(
        repo_url=repo_url,
        language=language,
        input_type=InputType.GITHUB_REPO,
        dependency_files=dependency_files,
        has_lockfile=has_lockfile,
        dependencies=list(parsed_deps.values()),
        warning_details=warning_details,
    )
    return classify_inventory_result(
        inventory,
        blocked_reason="missing_versions_in_repo_fallback",
        discovery_source="github_file_fallback",
    )


def acquire_github_dependency_inventory(repo_url: str, token: Optional[str] = None) -> DependencyInventory:
    try:
        return acquire_github_sbom_inventory(repo_url, token)
    except Exception as exc:
        inventory = acquire_github_file_inventory(repo_url, token)
        reason = str(exc)
        inventory.warnings.append(f"GitHub SBOM fallback used: {reason}")
        inventory.warning_details.append(
            {
                "code": "GITHUB_SBOM_FALLBACK",
                "message": "GitHub SBOM was unavailable or not parseable; file parser fallback was used.",
                "reason": reason,
            }
        )
        return inventory
