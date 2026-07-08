from typing import List

try:
    from app.models.models import Dependency
    from app.utils.repo_utils import (
        parse_environment_yml,
        parse_package_json,
        parse_package_lock_json,
        parse_pipfile_lock,
        parse_poetry_lock,
        parse_pom_xml,
        parse_pyproject_toml,
        parse_requirements_txt,
        validate_lockfile_content,
    )
except ModuleNotFoundError:
    from models.models import Dependency
    from utils.repo_utils import (
        parse_environment_yml,
        parse_package_json,
        parse_package_lock_json,
        parse_pipfile_lock,
        parse_poetry_lock,
        parse_pom_xml,
        parse_pyproject_toml,
        parse_requirements_txt,
        validate_lockfile_content,
    )


def parse_dependency_file(filename: str, content: str) -> List[Dependency]:
    """Dispatch dependency parsing by filename while preserving existing parser behavior."""
    if filename in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}:
        return parse_requirements_txt(content) if validate_lockfile_content(filename, content) else []
    if filename == "poetry.lock":
        return parse_poetry_lock(content) if validate_lockfile_content(filename, content) else []
    if filename == "Pipfile.lock":
        return parse_pipfile_lock(content) if validate_lockfile_content(filename, content) else []
    if filename == "package-lock.json":
        return parse_package_lock_json(content) if validate_lockfile_content(filename, content) else []
    if filename == "package.json":
        return parse_package_json(content)
    if filename == "pyproject.toml":
        return parse_pyproject_toml(content)
    if filename in {"environment.yml", "environment.yaml", "conda.yml", "conda.yaml", "conda-lock.yml", "conda-lock.yaml"}:
        return parse_environment_yml(content)
    if filename == "pom.xml":
        return parse_pom_xml(content)
    return []
