import requests
import re
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
try:
    from app.models.models import Dependency
except ModuleNotFoundError:
    from models.models import Dependency
import json
import base64
import os

def extract_repo_info(url: str) -> tuple[str, str]:
    """Extract owner and repo name from GitHub URL"""
    cleaned = url.strip().replace(".git", "").rstrip("/")
    parsed = urlparse(cleaned)
    path_parts = [part for part in parsed.path.split("/") if part]

    if len(path_parts) < 2:
        raise ValueError(
            "Invalid GitHub repository URL. Expected format: https://github.com/OWNER/REPO"
        )

    owner = path_parts[0]
    repo = path_parts[1]
    return owner, repo

def _github_headers(token: Optional[str] = None) -> Dict[str, str]:
    return {"Authorization": f"token {token}"} if token else {}


def get_repo_default_branch(repo_url: str, token: Optional[str] = None) -> str:
    owner, repo = extract_repo_info(repo_url)
    headers = _github_headers(token)
    repo_api = f"https://api.github.com/repos/{owner}/{repo}"
    repo_resp = requests.get(repo_api, headers=headers)

    if repo_resp.status_code == 404:
        raise Exception("Repository not found or you do not have access to it. For private repositories, ensure your GitHub token has 'repo' scope and is valid.")
    elif repo_resp.status_code == 403:
        raise Exception("Access forbidden. Your GitHub token may not have the required permissions (e.g., 'repo' scope for private repos) or may be expired.")
    elif repo_resp.status_code == 401:
        raise Exception("Unauthorized. Please check your GitHub token.")
    elif repo_resp.status_code != 200:
        raise Exception(f"Failed to fetch repo info: {repo_resp.status_code} - {repo_resp.text}")

    return repo_resp.json()["default_branch"]


def get_repo_structure_with_default_branch(repo_url: str, token: Optional[str] = None) -> tuple[Dict[str, Any], str]:
    """Get the repository file structure and the branch used for content fetches."""
    owner, repo = extract_repo_info(repo_url)
    headers = _github_headers(token)
    repo_api = f"https://api.github.com/repos/{owner}/{repo}"
    repo_resp = requests.get(repo_api, headers=headers)

    if repo_resp.status_code == 404:
        raise Exception("Repository not found or you do not have access to it. For private repositories, ensure your GitHub token has 'repo' scope and is valid.")
    elif repo_resp.status_code == 403:
        raise Exception("Access forbidden. Your GitHub token may not have the required permissions (e.g., 'repo' scope for private repos) or may be expired.")
    elif repo_resp.status_code == 401:
        raise Exception("Unauthorized. Please check your GitHub token.")
    elif repo_resp.status_code != 200:
        raise Exception(f"Failed to fetch repo info: {repo_resp.status_code} - {repo_resp.text}")

    default_branch = repo_resp.json()["default_branch"]

    # Step 2: Get full tree recursively
    tree_api = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
    tree_resp = requests.get(tree_api, headers=headers)

    if tree_resp.status_code == 404:
        raise Exception("Repository tree not found or you do not have access to it. Ensure the repository exists and your token has read access.")
    elif tree_resp.status_code == 403:
        raise Exception("Access forbidden to repository contents. Your GitHub token may lack 'repo' scope for private repositories.")
    elif tree_resp.status_code == 401:
        raise Exception("Unauthorized access to repository tree. Please verify your GitHub token.")
    elif tree_resp.status_code != 200:
        raise Exception(f"Failed to fetch repo tree: {tree_resp.status_code} - {tree_resp.text}")

    data = tree_resp.json()
    tree_data = data["tree"]

    # Step 3: Convert to folder structure
    structure = {}

    if data.get('truncated', False):
        # Tree is truncated, fetch all paths recursively
        all_paths = []
        def fetch_tree(tree_sha, path=''):
            tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}"
            tree_response = requests.get(tree_url, headers=headers)
            if tree_response.status_code == 200:
                tree_data_full = tree_response.json()
                for item in tree_data_full['tree']:
                    full_path = f"{path}/{item['path']}" if path else item['path']
                    if item['type'] == 'blob':
                        all_paths.append(full_path)
                    elif item['type'] == 'tree':
                        fetch_tree(item['sha'], full_path)
        
        fetch_tree(data['sha'])
        
        # Build structure from all_paths
        for path in all_paths:
            path_parts = path.split("/")
            current = structure
            for part in path_parts:
                if part not in current:
                    current[part] = {}
                current = current[part]
    else:
        # Not truncated, use tree_data
        for item in tree_data:
            path_parts = item["path"].split("/")
            current = structure
            for part in path_parts:
                if part not in current:
                    current[part] = {}
                current = current[part]

    return structure, default_branch


def get_repo_structure(repo_url: str, token: Optional[str] = None) -> Dict[str, Any]:
    """Get the repository file structure."""
    structure, _default_branch = get_repo_structure_with_default_branch(repo_url, token)
    return structure

def collect_file_paths(structure: Dict[str, Any]) -> List[str]:
    """Flatten the nested structure dict to a list of file paths."""
    paths = []
    def recurse(node, current_path):
        for key, value in node.items():
            path = f"{current_path}/{key}" if current_path else key
            if isinstance(value, dict):
                if not value:  # empty dict means file
                    paths.append(path)
                else:  # non-empty dict means folder
                    recurse(value, path)
    recurse(structure, "")
    return paths

def detect_language_from_structure(file_paths: List[str]) -> str:
    """Detect language from list of file paths"""
    file_names = set(os.path.basename(p).lower() for p in file_paths)
    if any(name in ['requirements.txt', 'pyproject.toml', 'poetry.lock', 'pipfile.lock', 'environment.yml', 'environment.yaml', 'conda.yml', 'conda.yaml', 'conda-lock.yml', 'conda-lock.yaml'] for name in file_names):
        return "python"
    if any(name in ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'] for name in file_names):
        return "javascript"
    if any(name in ['pom.xml', 'gradle.lockfile'] for name in file_names):
        return "java"
    if any(name == 'go.sum' for name in file_names):
        return "go"
    if any(name == 'cargo.lock' for name in file_names):
        return "rust"
    if any(name == 'gemfile.lock' for name in file_names):
        return "ruby"
    if any(name == 'composer.lock' for name in file_names):
        return "php"
    if any(name in ['packages.lock.json', 'project.assets.json'] for name in file_names):
        return "dotnet"

    # Fallback: detect by file extensions
    extensions = set()
    for p in file_paths:
        ext = p.split(".")[-1] if "." in p else ""
        if ext:
            extensions.add(f".{ext}")
    if ".py" in extensions:
        return "python"
    if ".js" in extensions or ".ts" in extensions:
        return "javascript"
    if ".java" in extensions:
        return "java"
    if ".go" in extensions:
        return "go"
    if ".rs" in extensions:
        return "rust"
    if ".rb" in extensions:
        return "ruby"
    if ".php" in extensions:
        return "php"
    if ".cs" in extensions:
        return "dotnet"

    return "unknown"

def collect_file_extensions(structure: Dict[str, Any]) -> set[str]:
    """Collect all file extensions from the structure"""
    extensions = set()
    def traverse(d):
        for key, value in d.items():
            if isinstance(value, dict):
                if not value:  # empty dict means file
                    ext = key.split(".")[-1] if "." in key else ""
                    if ext:
                        extensions.add(f".{ext}")
                else:
                    traverse(value)
    traverse(structure)
    return extensions

def find_dependency_files(repo_paths: list[str]):
    LOCKFILES = {
        # Python
        "poetry.lock",
        "Pipfile.lock",
        "requirements.txt",  # only if pinned
        "requirements-dev.txt",
        "requirements-prod.txt",
        "conda-lock.yml",
        "conda-lock.yaml",

        # Node.js
        "package-lock.json",
    }

    MANIFESTS = {
        # Python
        "pyproject.toml",
        "Pipfile",
        "setup.py",
        "requirements.txt",  # fallback
        "environment.yml",
        "environment.yaml",
        "conda.yml",
        "conda.yaml",

        # Node.js
        "package.json",

        # Java
        "pom.xml",
    }

    lockfiles = []
    manifests = []

    for path in repo_paths:
        filename = path.split("/")[-1]

        if filename in LOCKFILES:
            lockfiles.append(path)
        elif filename in MANIFESTS:
            manifests.append(path)

    return {
        "lockfiles": lockfiles,
        "manifests": manifests
    }

def is_probable_lockfile(filename: str) -> bool:
    name = filename.lower()
    return (
        name.endswith(".lock") or
        name.endswith(".lock.json") or
        "lock" in name and any(ext in name for ext in [".json", ".yaml", ".yml", ".hcl", ".b"])
    )

def validate_lockfile_content(filename: str, content: str) -> bool:
    if filename in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}:
        return bool(parse_requirements_txt(content))
    if filename == "package-lock.json":
        return '"dependencies"' in content
    if filename == "poetry.lock":
        return "[[package]]" in content
    if filename == "yarn.lock":
        return ":" in content and "version" in content
    if filename == "Cargo.lock":
        return "[package]" in content
    if filename == "Gemfile.lock":
        return "GEM" in content
    if filename == "composer.lock":
        return '"packages"' in content
    if filename in {"conda-lock.yml", "conda-lock.yaml"}:
        return "package:" in content or "packages:" in content
    return False

def fetch_file_content(owner: str, repo: str, path: str, token: Optional[str] = None, branch: Optional[str] = None) -> Optional[str]:
    """Fetch file content from GitHub."""
    headers = {"Authorization": f"token {token}"} if token else {}
    if token:
        # Use API for private repos
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": branch} if branch else None
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            content = response.json()["content"]
            return base64.b64decode(content).decode("utf-8")
        return None
    else:
        # Use raw for public repos
        resolved_branch = branch or "main"
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{resolved_branch}/{path}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        return None

def detect_language(owner: str, repo: str) -> str:
    """Detect programming language by checking for common dependency files."""
    # Check for Python
    if fetch_file_content(owner, repo, "requirements.txt") or fetch_file_content(owner, repo, "pyproject.toml"):
        return "python"
    # Check for JavaScript/Node.js
    if fetch_file_content(owner, repo, "package.json"):
        return "javascript"
    # Check for Java
    if fetch_file_content(owner, repo, "pom.xml"):
        return "java"
    # Default or unknown
    return "unknown"

def parse_requirements_txt(content: str) -> List[Dependency]:
    """Parse requirements.txt content."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ", "--index-url", "--extra-index-url")):
            continue
        if line.startswith(("git+", "http://", "https://", "-e ", "--editable ")):
            continue

        line = line.split("#", 1)[0].strip()
        line = line.split(";", 1)[0].strip()
        if not line:
            continue

        versioned = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([><=!~]{1,2})\s*([^\s]+)$", line)
        if versioned:
            name, op, version = versioned.groups()
            normalized_version = version if op == "==" else f"{op}{version}"
            deps.append(Dependency(name=name, version=normalized_version, language="python"))
            continue

        direct_ref = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*@\s*\S+$", line)
        if direct_ref:
            deps.append(Dependency(name=direct_ref.group(1), version="", language="python"))
            continue

        bare_name = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?$", line)
        if bare_name:
            deps.append(Dependency(name=bare_name.group(1), version="", language="python"))
    return deps

def parse_pyproject_toml(content: str) -> List[Dependency]:
    """Simple parser for pyproject.toml dependencies."""
    try:
        import tomllib as toml_parser  # Python 3.11+
    except ModuleNotFoundError:
        import tomli as toml_parser
    deps = []

    def add_dep(name: str, version: str):
        if name and version:
            deps.append(Dependency(name=name, version=version, language="python"))

    def normalize_dependency_entry(name: str, value: Any):
        if isinstance(value, str):
            add_dep(name, value)
        elif isinstance(value, dict):
            version = value.get("version") or value.get("ref") or value.get("path")
            if isinstance(version, str):
                add_dep(name, version)
        elif isinstance(value, list) and value:
            first = value[0]
            if isinstance(first, str):
                add_dep(name, first)

    def parse_poetry_sections_fallback(raw_content: str) -> None:
        """Fallback parser for Poetry dependency sections when TOML parsing fails."""
        current_section = ""
        for raw_line in raw_content.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Section header
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip().lower()
                continue

            in_poetry_main = current_section == "tool.poetry.dependencies"
            in_poetry_dev_legacy = current_section == "tool.poetry.dev-dependencies"
            in_poetry_group = (
                current_section.startswith("tool.poetry.group.")
                and current_section.endswith(".dependencies")
            )

            if not (in_poetry_main or in_poetry_dev_legacy or in_poetry_group):
                continue

            # Remove inline comments crudely; good enough for dependency lines.
            line = line.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue

            name_part, value_part = line.split("=", 1)
            name = name_part.strip().strip('"').strip("'")
            value = value_part.strip().strip('"').strip("'")
            if name and value:
                add_dep(name, value)

    try:
        data = toml_parser.loads(content)
        if "tool" in data and "poetry" in data["tool"]:
            poetry_deps = data["tool"]["poetry"].get("dependencies", {})
            for name, version in poetry_deps.items():
                normalize_dependency_entry(name, version)
            poetry_dev_deps = data["tool"]["poetry"].get("dev-dependencies", {})
            for name, version in poetry_dev_deps.items():
                normalize_dependency_entry(name, version)

            # Support modern Poetry groups, e.g. [tool.poetry.group.dev.dependencies]
            poetry_groups = data["tool"]["poetry"].get("group", {})
            if isinstance(poetry_groups, dict):
                for group_data in poetry_groups.values():
                    if isinstance(group_data, dict):
                        group_deps = group_data.get("dependencies", {})
                        if isinstance(group_deps, dict):
                            for name, version in group_deps.items():
                                normalize_dependency_entry(name, version)

        if "project" in data:
            project_deps = data["project"].get("dependencies", [])
            for dep in project_deps:
                match = re.match(r"^([A-Za-z0-9_.+-]+)(?:\[.*?\])?\s*([>=<!~].*)$", dep)
                if match:
                    name = match.group(1)
                    version = match.group(2).strip()
                    add_dep(name, version)
    except Exception:
        parse_poetry_sections_fallback(content)
    return deps


def parse_environment_yml(content: str) -> List[Dependency]:
    """Parse Conda environment YAML dependencies including nested pip section."""
    deps: List[Dependency] = []
    in_dependencies = False
    in_pip_block = False

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if re.match(r"^[A-Za-z_][A-Za-z0-9_-]*\s*:", stripped):
            key = stripped.split(":", 1)[0].strip().lower()
            if key == "dependencies":
                in_dependencies = True
                in_pip_block = False
                continue
            if in_dependencies:
                in_dependencies = False
                in_pip_block = False

        if not in_dependencies or not stripped.startswith("-"):
            continue

        item = stripped[1:].strip()
        if not item:
            continue

        if item.lower() == "pip:":
            in_pip_block = True
            continue

        if in_pip_block:
            pip_match = re.match(r"^([A-Za-z0-9_.+-]+)\s*(==|>=|<=|~=|>|<)?\s*(.*)$", item)
            if pip_match:
                name = pip_match.group(1).strip()
                version = (pip_match.group(3) or "").strip()
                deps.append(Dependency(name=name, version=version, language="python"))
            continue

        conda_match = re.match(r"^([A-Za-z0-9_.+-]+)(?:\s*[=><!~]+\s*|\s*=)(.*)$", item)
        if conda_match:
            name = conda_match.group(1).strip()
            version = (conda_match.group(2) or "").strip()
        else:
            name = item.split("=", 1)[0].strip()
            version = item[len(name):].lstrip("= ").strip() if len(item) > len(name) else ""

        deps.append(Dependency(name=name, version=version, language="python"))

    return deps

def parse_package_json(content: str) -> List[Dependency]:
    """Parse package.json for JavaScript dependencies."""
    deps = []
    try:
        data = json.loads(content)
        # Combine dependencies and devDependencies
        all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, version in all_deps.items():
            # Version might be a range, e.g., "^1.0.0"
            deps.append(Dependency(name=name, version=version, language="javascript"))
    except Exception:
        pass
    return deps

def parse_poetry_lock(content: str) -> List[Dependency]:
    """Simple parser for poetry.lock"""
    deps = []
    import re
    # Find [[package]] sections
    packages = re.findall(r'\[\[package\]\]\s*name = "([^"]+)"\s*version = "([^"]+)"', content)
    for name, version in packages:
        deps.append(Dependency(name=name, version=version, language="python"))
    return deps

def parse_package_lock_json(content: str) -> List[Dependency]:
    """Simple parser for package-lock.json"""
    deps = []
    try:
        data = json.loads(content)
        dependencies = data.get("dependencies", {})
        for name, info in dependencies.items():
            version = info.get("version", "")
            deps.append(Dependency(name=name, version=version, language="javascript"))
    except:
        pass
    return deps

def parse_pipfile_lock(content: str) -> List[Dependency]:
    """Simple parser for Pipfile.lock"""
    deps = []
    try:
        data = json.loads(content)
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "")
                if isinstance(version, str):
                    version = version.lstrip("=")
                deps.append(Dependency(name=name, version=version, language="python"))
    except Exception:
        pass
    return deps

def parse_pom_xml(content: str) -> List[Dependency]:
    """Simple parser for pom.xml dependencies (Maven)."""
    deps = []
    # Basic regex to extract <dependency> blocks
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(content)
        for dep in root.findall(".//{http://maven.apache.org/POM/4.0.0}dependency"):
            group_id = dep.find("{http://maven.apache.org/POM/4.0.0}groupId")
            artifact_id = dep.find("{http://maven.apache.org/POM/4.0.0}artifactId")
            version_elem = dep.find("{http://maven.apache.org/POM/4.0.0}version")
            if group_id is not None and artifact_id is not None and version_elem is not None:
                name = f"{group_id.text}:{artifact_id.text}"
                version = version_elem.text
                deps.append(Dependency(name=name, version=version, language="java"))
    except Exception:
        pass
    return deps
