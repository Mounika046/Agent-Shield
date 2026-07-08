import re
from typing import Optional

try:
    from app.schemas import InputType, PackageCoordinate, ScanMode, ScanRequestContext
except ModuleNotFoundError:
    from schemas import InputType, PackageCoordinate, ScanMode, ScanRequestContext


SECURITY_TERMS = {"vulnerability", "vulnerabilities", "cve", "security", "exploit", "osv", "nvd"}
METADATA_TERMS = {"license", "licenses", "health", "trust", "maintenance", "maintainer", "metadata"}
DEVELOPER_TERMS = {"developer", "repo", "repository", "github", "stars", "forks", "issues", "full context", "overview"}
DEPENDENCY_LIST_LINE_RE = re.compile(
    r"^\s*[A-Za-z][A-Za-z0-9_.-]*(?:\[[^\]]+\])?\s*(==|>=|<=|~=|>|<)\s*[A-Za-z0-9_.!+*-]+",
    re.IGNORECASE,
)
DEPENDENCY_NAME_ONLY_LINE_RE = re.compile(
    r"^\s*[A-Za-z][A-Za-z0-9_.-]*(?:\[[^\]]+\])?\s*$",
    re.IGNORECASE,
)


def _coerce_packages(packages: Optional[list[PackageCoordinate]]) -> list[PackageCoordinate]:
    normalized = []
    for item in packages or []:
        if isinstance(item, PackageCoordinate):
            normalized.append(item)
        elif isinstance(item, dict):
            normalized.append(PackageCoordinate(**item))
    return normalized


def _looks_like_dependency_list(text: Optional[str]) -> bool:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip() and not line.strip().startswith("#")]
    if len(lines) < 2:
        return False
    matched = sum(1 for line in lines if DEPENDENCY_LIST_LINE_RE.match(line) or DEPENDENCY_NAME_ONLY_LINE_RE.match(line))
    return matched >= 2 and matched == len(lines)


def detect_input_type(context: ScanRequestContext) -> InputType:
    if context.repo_url:
        return InputType.GITHUB_REPO
    if context.packages or (context.package_name and context.package_version):
        return InputType.PACKAGE
    if context.file_name and context.file_content is not None:
        return InputType.DEPENDENCY_FILE
    return InputType.UNKNOWN


def infer_scan_mode(context: ScanRequestContext) -> ScanMode:
    if context.mode:
        return context.mode

    text = " ".join(
        value
        for value in [
            context.raw_text or "",
            context.repo_url or "",
            " ".join(package.package_name for package in context.packages) or context.package_name or "",
            context.file_name or "",
        ]
        if value
    ).lower()

    if any(term in text for term in DEVELOPER_TERMS):
        return ScanMode.DEVELOPER
    if any(term in text for term in METADATA_TERMS):
        return ScanMode.DETAILED
    if any(term in text for term in SECURITY_TERMS):
        return ScanMode.FAST
    return ScanMode.FAST


def normalize_request_context(
    raw_text: Optional[str] = None,
    repo_url: Optional[str] = None,
    token: Optional[str] = None,
    packages: Optional[list[PackageCoordinate]] = None,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    file_name: Optional[str] = None,
    file_content: Optional[str] = None,
    mode: Optional[ScanMode] = None,
) -> ScanRequestContext:
    inferred_file_name = file_name
    inferred_file_content = file_content
    if not repo_url and not package_name and not packages and not file_name and file_content is None and _looks_like_dependency_list(raw_text):
        inferred_file_name = "requirements.txt"
        inferred_file_content = raw_text
    normalized_packages = _coerce_packages(packages)
    if not normalized_packages and package_name and package_version and ecosystem:
        normalized_packages = [
            PackageCoordinate(
                package_name=package_name,
                package_version=package_version,
                ecosystem=ecosystem,
            )
        ]
    primary_package = normalized_packages[0] if normalized_packages else None
    context = ScanRequestContext(
        raw_text=raw_text,
        repo_url=repo_url,
        token=token,
        packages=normalized_packages,
        package_name=(primary_package.package_name if primary_package else package_name),
        package_version=(primary_package.package_version if primary_package else package_version),
        ecosystem=(primary_package.ecosystem if primary_package else ecosystem),
        file_name=inferred_file_name,
        file_content=inferred_file_content,
        mode=mode,
        mode_source="explicit" if mode is not None else "inferred",
    )
    context.input_type = detect_input_type(context)
    return context
