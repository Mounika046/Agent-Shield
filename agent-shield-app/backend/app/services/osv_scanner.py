from typing import Optional

try:
    from app.schemas import DependencyInventory
except ModuleNotFoundError:
    from schemas import DependencyInventory


def acquire_with_osv_scanner(repo_url: str, token: Optional[str] = None) -> DependencyInventory:
    """Provider boundary for future OSV-Scanner integration.

    The current phase keeps the custom parser fully wired and leaves this provider
    non-invasive until invoking the external scanner binary is configured.
    """
    return DependencyInventory(
        repo_url=repo_url,
        warnings=["OSV-Scanner provider is not configured; custom parser fallback was used."],
    )
