from typing import Optional

try:
    from app.schemas import MetadataEnrichment
    from app.services.github.client import GitHubClient
except ModuleNotFoundError:
    from schemas import MetadataEnrichment
    from services.github.client import GitHubClient


def enrich_github_repo(repo_url: str, token: Optional[str] = None) -> MetadataEnrichment:
    try:
        data = GitHubClient(repo_url, token).fetch_repo_metadata()
        return MetadataEnrichment(provider="github_api", status="success", data=data)
    except Exception as exc:
        return MetadataEnrichment(provider="github_api", status="failed", errors=[str(exc)])
