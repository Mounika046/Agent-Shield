from typing import Optional

try:
    from app.models.models import Dependency
    from app.parsers import parse_dependency_file
    from app.services.discovery import classify_inventory_result
    from app.schemas import (
        DependencyInventory,
        DependencySourceType,
        InputType,
        NormalizedDependency,
        PackageCoordinate,
    )
    from app.services.github.acquisition import derive_source_and_ecosystem
    from app.services.versioning import normalize_version_fields
except ModuleNotFoundError:
    from models.models import Dependency
    from parsers import parse_dependency_file
    from services.discovery import classify_inventory_result
    from schemas import DependencyInventory, DependencySourceType, InputType, NormalizedDependency, PackageCoordinate
    from services.github.acquisition import derive_source_and_ecosystem
    from services.versioning import normalize_version_fields


def _language_from_ecosystem(ecosystem: str) -> str:
    normalized = ecosystem.strip().lower()
    if normalized in {"pypi", "python", "conda"}:
        return "python"
    if normalized in {"npm", "node", "javascript", "typescript"}:
        return "javascript"
    if normalized == "maven":
        return "java"
    return ""


def acquire_direct_package_inventory(
    package_name: str = "",
    package_version: str = "",
    ecosystem: Optional[str] = None,
    packages: Optional[list[PackageCoordinate]] = None,
) -> DependencyInventory:
    package_list = list(packages or [])
    if not package_list and package_name and package_version:
        package_list = [
            PackageCoordinate(
                package_name=package_name,
                package_version=package_version,
                ecosystem=ecosystem or "PyPI",
            )
        ]
    dependencies = []
    warnings = []
    if not packages and package_name and package_version and not ecosystem:
        warnings.append("No ecosystem provided for package input; defaulted to PyPI.")
    warning_details = []
    for item in package_list:
        safe_ecosystem = item.ecosystem or "PyPI"
        version, version_kind, version_specifier = normalize_version_fields(item.package_version)
        dependencies.append(
            NormalizedDependency(
                name=item.package_name,
                version=version,
                version_kind=version_kind,
                version_specifier=version_specifier or None,
                language=_language_from_ecosystem(safe_ecosystem),
                source="direct_input",
                ecosystem=safe_ecosystem,
                source_type=DependencySourceType.DIRECT_PACKAGE,
                relationship="direct",
            )
        )
        if version_kind.value != "exact":
            warning_details.append(
                {
                    "code": "NON_EXACT_VERSION",
                    "package": item.package_name,
                    "version": version,
                    "version_kind": version_kind.value,
                    "message": "Package input version is not exact; exact-version enrichments may be skipped.",
                }
            )
    language = dependencies[0].language if len({dep.language for dep in dependencies if dep.language}) == 1 and dependencies else "unknown"
    return DependencyInventory(
        input_type=InputType.PACKAGE,
        language=language,
        has_lockfile=True,
        dependencies=dependencies,
        warnings=warnings,
        warning_details=warning_details,
    )


def acquire_file_dependency_inventory(file_name: str, file_content: str) -> DependencyInventory:
    source, ecosystem = derive_source_and_ecosystem(file_name, "")
    dependencies = []
    warning_details = []
    for dep in parse_dependency_file(file_name, file_content):
        version, version_kind, version_specifier = normalize_version_fields(dep.version)
        dependencies.append(NormalizedDependency(
            name=dep.name,
            version=version,
            version_kind=version_kind,
            version_specifier=version_specifier or None,
            language=dep.language,
            source=source or "uploaded_file",
            ecosystem=ecosystem,
            source_type=DependencySourceType.UPLOADED_FILE,
            file_path=file_name,
            relationship="direct",
        ))
        if version_kind.value != "exact":
            warning_details.append(
                {
                    "code": "NON_EXACT_VERSION",
                    "package": dep.name,
                    "version": version,
                    "version_kind": version_kind.value,
                    "message": "Dependency version is not exact; exact-version enrichments may be skipped.",
                }
            )
    language = dependencies[0].language if dependencies else _language_from_ecosystem(ecosystem) or "unknown"
    dependency_files = {"lockfiles": [file_name], "manifests": []}
    inventory = DependencyInventory(
        input_type=InputType.DEPENDENCY_FILE,
        language=language,
        dependency_files=dependency_files,
        has_lockfile=True,
        dependencies=dependencies,
        warning_details=warning_details,
    )
    return classify_inventory_result(
        inventory,
        blocked_reason="missing_versions_in_file",
        discovery_source=file_name,
    )
