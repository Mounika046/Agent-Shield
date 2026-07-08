from typing import Any, Dict, Optional

import requests

try:
    from app.config import get_config
    from app.utils.repo_utils import extract_repo_info, fetch_file_content, get_repo_structure_with_default_branch
except ModuleNotFoundError:
    from config import get_config
    from utils.repo_utils import extract_repo_info, fetch_file_content, get_repo_structure_with_default_branch


class GitHubClient:
    """Small boundary around current GitHub access helpers."""

    def __init__(self, repo_url: str, token: Optional[str] = None):
        self.repo_url = repo_url
        self.token = token
        self.owner, self.repo = extract_repo_info(repo_url)
        self.default_branch: Optional[str] = None

    def get_structure(self) -> Dict[str, Any]:
        structure, default_branch = get_repo_structure_with_default_branch(self.repo_url, self.token)
        self.default_branch = default_branch
        return structure

    def fetch_file(self, path: str) -> Optional[str]:
        return fetch_file_content(self.owner, self.repo, path, self.token, self.default_branch)

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"token {self.token}"} if self.token else {}

    def fetch_sbom(self) -> Dict[str, Any]:
        settings = get_config()
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/dependency-graph/sbom"
        response = requests.get(url, headers=self._headers(), timeout=settings.request_timeout_seconds)
        if response.status_code != 200:
            raise RuntimeError(f"GitHub SBOM unavailable: {response.status_code}")
        return response.json()

    def fetch_repo_metadata(self) -> Dict[str, Any]:
        settings = get_config()
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}"
        response = requests.get(url, headers=self._headers(), timeout=settings.request_timeout_seconds)
        response.raise_for_status()
        payload = response.json()
        return {
            "full_name": payload.get("full_name"),
            "description": payload.get("description"),
            "default_branch": payload.get("default_branch"),
            "stars": payload.get("stargazers_count"),
            "watchers": payload.get("watchers_count"),
            "forks": payload.get("forks_count"),
            "open_issues_count": payload.get("open_issues_count"),
            "updated_at": payload.get("updated_at"),
            "pushed_at": payload.get("pushed_at"),
            "language": payload.get("language"),
            "visibility": payload.get("visibility"),
            "html_url": payload.get("html_url"),
        }
