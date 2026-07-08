import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse


SUPPORTED_MODES = {"fast", "detailed", "developer"}
SECURITY_TERMS = {"vulnerability", "vulnerabilities", "security", "cve", "exploit", "risk"}
METADATA_TERMS = {"license", "licenses", "trust", "health", "maintenance", "metadata", "maintainer"}
DEVELOPER_TERMS = {"developer", "full", "repo context", "repository context", "stars", "forks", "issues"}
FILE_TERMS = {"file", "requirements.txt", "package.json", "pyproject.toml", "dependency file"}
PACKAGE_HINT_TERMS = {"package", "library", "dependency"}
REPO_HINT_TERMS = {"repo", "repository", "github"}
GITHUB_REPO_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$")
PACKAGE_WITH_VERSION_RE = re.compile(
    r"\b(?P<name>[A-Za-z][A-Za-z0-9_.-]*)\s+"
    r"(?:(?:version|ver)\s+)?"
    r"(?P<version>\d+(?:\.\d+){1,}(?:[A-Za-z0-9_.+-]*)?)"
    r"(?:\s+(?:(?:on|in)\s+)?(?P<ecosystem>pypi|python|npm|nodejs|node|javascript|typescript|maven|java))?"
    r"(?:\s+package)?\b",
    re.IGNORECASE,
)
ECOSYSTEM_ALIASES = {
    "pypi": "PyPI",
    "python": "PyPI",
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "javascript": "npm",
    "typescript": "npm",
    "maven": "Maven",
    "java": "Maven",
}
PACKAGE_STOP_WORDS = {
    "check",
    "scan",
    "analyze",
    "analyse",
    "review",
    "these",
    "this",
    "and",
    "package",
    "packages",
    "dependency",
    "dependencies",
    "python",
    "javascript",
    "npm",
    "node",
    "nodejs",
    "pypi",
    "maven",
    "java",
    "version",
    "ver",
}
DEPENDENCY_LIST_LINE_RE = re.compile(
    r"^\s*[A-Za-z][A-Za-z0-9_.-]*(?:\[[^\]]+\])?\s*(==|>=|<=|~=|>|<)\s*[A-Za-z0-9_.!+*-]+",
    re.IGNORECASE,
)
DEPENDENCY_NAME_ONLY_LINE_RE = re.compile(
    r"^\s*[A-Za-z][A-Za-z0-9_.-]*(?:\[[^\]]+\])?\s*$",
    re.IGNORECASE,
)


@dataclass
class RequestInterpretation:
    raw_text: str
    repo_url: Optional[str]
    token: Optional[str]
    packages: List[Dict[str, str]]
    package_name: Optional[str]
    package_version: Optional[str]
    ecosystem: Optional[str]
    file_name: Optional[str]
    file_content: Optional[str]
    mode: Optional[str]
    mode_source: str
    input_type: str
    clarification_question: Optional[str] = None


def _find_repo_url(text: str) -> Optional[str]:
    match = re.search(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?", text or "")
    return normalize_github_repo_url(match.group(0)) if match else None


def normalize_github_repo_url(repo_url: Optional[str]) -> Optional[str]:
    if not repo_url:
        return repo_url
    cleaned = str(repo_url).strip()
    if not cleaned:
        return None
    try:
        parsed = urlparse(cleaned)
    except ValueError:
        return cleaned
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
        return cleaned

    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) < 2:
        return cleaned

    owner = path_parts[0]
    repo = path_parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return cleaned
    return f"https://github.com/{owner}/{repo}"


def _find_mode(text: str, explicit_mode: Optional[str]) -> tuple[Optional[str], str]:
    if explicit_mode:
        value = str(explicit_mode).strip().lower()
        if "." in value:
            value = value.rsplit(".", 1)[-1]
        return (value if value in SUPPORTED_MODES else None), "explicit"
    lowered = (text or "").lower()
    for mode in SUPPORTED_MODES:
        if re.search(rf"\b{mode}\b", lowered):
            return mode, "explicit"
    return None, "inferred"


def _infer_mode(text: str) -> Optional[str]:
    lowered = (text or "").lower()
    if any(term in lowered for term in DEVELOPER_TERMS):
        return "developer"
    if any(term in lowered for term in METADATA_TERMS):
        return "detailed"
    if any(term in lowered for term in SECURITY_TERMS):
        return "fast"
    return None


def _guess_package_name(text: str) -> Optional[str]:
    lowered = (text or "").strip()
    if not lowered:
        return None
    if "github.com/" in lowered or "\n" in lowered:
        return None
    tokens = re.findall(r"[A-Za-z0-9_.-]+", lowered)
    stop = {
        "check",
        "scan",
        "analyze",
        "this",
        "package",
        "dependency",
        "library",
        "vulnerabilities",
        "vulnerability",
        "security",
        "for",
        "mode",
        "fast",
        "detailed",
        "developer",
        "version",
        "ver",
    }
    candidates = [token for token in tokens if token.lower() not in stop]
    if len(candidates) == 1 and len(tokens) <= 4:
        return candidates[0]
    return None


def _canonical_ecosystem(raw_value: Optional[str]) -> Optional[str]:
    if not raw_value:
        return None
    return ECOSYSTEM_ALIASES.get(str(raw_value).strip().lower(), str(raw_value).strip())


def _extract_packages(
    *,
    text: str,
    packages: Optional[List[Dict[str, str]]] = None,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    file_name: Optional[str] = None,
    file_content: Optional[str] = None,
    repo_url: Optional[str] = None,
) -> List[Dict[str, str]]:
    if repo_url or file_name or file_content is not None:
        return []
    if packages:
        normalized = []
        for item in packages:
            normalized.append(
                {
                    "package_name": str(item.get("package_name") or "").strip(),
                    "package_version": str(item.get("package_version") or "").strip(),
                    "ecosystem": _canonical_ecosystem(item.get("ecosystem")) or "",
                }
            )
        return normalized
    if package_name or package_version or ecosystem:
        return [
            {
                "package_name": str(package_name or "").strip(),
                "package_version": str(package_version or "").strip(),
                "ecosystem": _canonical_ecosystem(ecosystem) or "",
            }
        ]

    matches = []
    for match in PACKAGE_WITH_VERSION_RE.finditer(text or ""):
        package_name_candidate = str(match.group("name") or "").strip()
        if package_name_candidate.lower() in PACKAGE_STOP_WORDS:
            continue
        matches.append(
            {
                "package_name": package_name_candidate,
                "package_version": str(match.group("version") or "").strip(),
                "ecosystem": _canonical_ecosystem(match.group("ecosystem")) or "",
            }
        )

    global_ecosystem_match = re.search(
        r"\b(?:(?:on|in)\s+)?(pypi|python|npm|nodejs|node|javascript|typescript|maven|java)(?:\s+package)?\b",
        text or "",
        re.IGNORECASE,
    )
    global_ecosystem = _canonical_ecosystem(global_ecosystem_match.group(1)) if global_ecosystem_match else None
    if matches and global_ecosystem:
        for item in matches:
            if not item["ecosystem"]:
                item["ecosystem"] = global_ecosystem

    deduped = []
    seen = set()
    for item in matches:
        key = (
            item["package_name"].lower(),
            item["package_version"],
            item["ecosystem"].lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _find_incomplete_package_mentions(text: str) -> List[str]:
    mentions = []
    for segment in re.split(r"\b(?:and|,)\b", text or "", flags=re.IGNORECASE):
        cleaned = segment.strip()
        if not cleaned or PACKAGE_WITH_VERSION_RE.search(cleaned):
            continue
        lowered = cleaned.lower()
        if "github.com/" in lowered:
            continue
        if not (
            "package" in lowered
            or any(alias in lowered for alias in ECOSYSTEM_ALIASES)
        ):
            continue
        for token in re.findall(r"[A-Za-z][A-Za-z0-9_.-]*", cleaned):
            if token.lower() not in PACKAGE_STOP_WORDS:
                mentions.append(token)
                break
    return mentions


def _looks_like_dependency_list(text: str) -> bool:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip() and not line.strip().startswith("#")]
    if len(lines) < 2:
        return False
    matched = sum(1 for line in lines if DEPENDENCY_LIST_LINE_RE.match(line) or DEPENDENCY_NAME_ONLY_LINE_RE.match(line))
    return matched >= 2 and matched == len(lines)


def _detect_input_type(
    *,
    text: str,
    repo_url: Optional[str],
    packages: List[Dict[str, str]],
    package_name: Optional[str],
    package_version: Optional[str],
    file_name: Optional[str],
    file_content: Optional[str],
) -> str:
    if repo_url:
        return "github_repo"
    if file_name or file_content is not None or any(term in text.lower() for term in FILE_TERMS):
        return "dependency_file"
    if packages or package_name or package_version:
        return "package"
    guessed_package = _guess_package_name(text)
    if guessed_package:
        return "package"
    if any(term in text.lower() for term in REPO_HINT_TERMS):
        return "github_repo"
    if any(term in text.lower() for term in PACKAGE_HINT_TERMS):
        return "package"
    return "unknown"


def interpret_request(
    *,
    message: str,
    repo_url: Optional[str] = None,
    token: Optional[str] = None,
    packages: Optional[List[Dict[str, str]]] = None,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    file_name: Optional[str] = None,
    file_content: Optional[str] = None,
    mode: Optional[str] = None,
) -> RequestInterpretation:
    text = message or ""
    resolved_repo_url = normalize_github_repo_url(repo_url) or _find_repo_url(text)
    inferred_file_name = file_name
    inferred_file_content = file_content
    if not resolved_repo_url and not file_name and file_content is None and not packages and _looks_like_dependency_list(text):
        inferred_file_name = "requirements.txt"
        inferred_file_content = text
    resolved_packages = _extract_packages(
        text=text,
        packages=packages,
        package_name=package_name,
        package_version=package_version,
        ecosystem=ecosystem,
        file_name=inferred_file_name,
        file_content=inferred_file_content,
        repo_url=resolved_repo_url,
    )
    primary_package = resolved_packages[0] if resolved_packages else None
    resolved_package = (
        primary_package["package_name"]
        if primary_package
        else package_name or (None if resolved_repo_url or inferred_file_name or inferred_file_content is not None else _guess_package_name(text))
    )
    resolved_package_version = primary_package["package_version"] if primary_package else package_version
    resolved_ecosystem = primary_package["ecosystem"] if primary_package else _canonical_ecosystem(ecosystem)
    resolved_mode, mode_source = _find_mode(text, mode)
    if not resolved_mode:
        resolved_mode = _infer_mode(text)

    input_type = _detect_input_type(
        text=text,
        repo_url=resolved_repo_url,
        packages=resolved_packages,
        package_name=resolved_package,
        package_version=resolved_package_version,
        file_name=inferred_file_name,
        file_content=inferred_file_content,
    )

    question = None
    provided_targets = sum(
        1
        for present in [
            bool(resolved_repo_url),
            bool(resolved_packages or resolved_package or resolved_package_version),
            bool(inferred_file_name or inferred_file_content is not None),
        ]
        if present
    )
    if provided_targets > 1:
        question = "I see multiple analysis targets. Should I analyze the repo, the package, or the dependency file?"
    elif resolved_repo_url and not GITHUB_REPO_RE.match(resolved_repo_url):
        question = "Please provide a valid GitHub repository URL in the form https://github.com/OWNER/REPO."

    if input_type == "package":
        if question:
            pass
        elif not resolved_packages and not resolved_package:
            question = "Which package should I analyze?"
        else:
            incomplete_mentions = _find_incomplete_package_mentions(text)
            if incomplete_mentions:
                question = f"What exact version should I use for {', '.join(incomplete_mentions[:3])}?"
            else:
                incomplete_packages = [
                    item
                    for item in (resolved_packages or [])
                    if not item["package_name"] or not item["package_version"] or not item["ecosystem"]
                ]
                if incomplete_packages:
                    missing_names = ", ".join(item["package_name"] or "one package" for item in incomplete_packages[:3])
                    if any(not item["package_version"] for item in incomplete_packages):
                        question = f"What exact version should I use for {missing_names}?"
                    elif any(not item["ecosystem"] for item in incomplete_packages):
                        question = f"Which ecosystem should I use for {missing_names}, such as PyPI, npm, or Maven?"
                elif not resolved_packages and not resolved_package_version:
                    question = f"What exact version of {resolved_package} should I analyze?"
                elif not resolved_packages and not resolved_ecosystem:
                    question = f"Which ecosystem is {resolved_package} in, such as PyPI, npm, or Maven?"
    elif input_type == "github_repo":
        if question:
            pass
        elif not resolved_repo_url:
            question = "Please provide the GitHub repository URL to scan."
        elif "private" in text.lower() and not token:
            question = "This sounds like a private repository. Please provide a GitHub token, or confirm it is public."
    elif input_type == "dependency_file":
        if question:
            pass
        elif not inferred_file_name:
            question = "Please provide the dependency file name, such as requirements.txt, package.json, or pyproject.toml."
        elif inferred_file_content is None or not str(inferred_file_content).strip():
            question = f"Please provide the contents of {inferred_file_name} so I can analyze it."
    else:
        question = (
            "What should I analyze? Please provide a GitHub repo URL, a package name with exact version, "
            "or a dependency file name with its contents."
        )

    if not question and not resolved_mode:
        resolved_mode = "fast"

    return RequestInterpretation(
        raw_text=text,
        repo_url=resolved_repo_url,
        token=token,
        packages=resolved_packages,
        package_name=resolved_package,
        package_version=resolved_package_version,
        ecosystem=resolved_ecosystem,
        file_name=inferred_file_name,
        file_content=inferred_file_content,
        mode=resolved_mode,
        mode_source=mode_source,
        input_type=input_type,
        clarification_question=question,
    )


def build_backend_payload(interpretation: RequestInterpretation) -> Dict[str, object]:
    primary_package = interpretation.packages[0] if len(interpretation.packages) == 1 else None
    return {
        "repo_url": interpretation.repo_url,
        "token": interpretation.token,
        "packages": interpretation.packages or None,
        "package_name": primary_package["package_name"] if primary_package else None,
        "package_version": primary_package["package_version"] if primary_package else None,
        "ecosystem": primary_package["ecosystem"] if primary_package else None,
        "file_name": interpretation.file_name,
        "file_content": interpretation.file_content,
        "mode": interpretation.mode,
        "raw_text": interpretation.raw_text,
    }
