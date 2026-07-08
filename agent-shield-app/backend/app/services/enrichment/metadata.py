from typing import List

try:
    from app.schemas import MetadataEnrichment
except ModuleNotFoundError:
    from schemas import MetadataEnrichment


def planned_metadata_providers() -> List[MetadataEnrichment]:
    """Expose future enrichment slots without changing current scan behavior."""
    return [
        MetadataEnrichment(provider="deps.dev", status="planned"),
        MetadataEnrichment(provider="github_api", status="planned"),
        MetadataEnrichment(provider="github_sbom", status="planned"),
        MetadataEnrichment(provider="osv_scanner", status="planned"),
    ]
