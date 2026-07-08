from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

try:
    from app.config import get_config
    from app.schemas import DependencyInventory, MetadataEnrichment, VersionKind
except ModuleNotFoundError:
    from config import get_config
    from schemas import DependencyInventory, MetadataEnrichment, VersionKind


def _system_from_ecosystem(ecosystem: str) -> str:
    normalized = ecosystem.strip().lower()
    if normalized in {"pypi", "python"}:
        return "pypi"
    if normalized in {"npm", "javascript", "node"}:
        return "npm"
    if normalized == "maven":
        return "maven"
    if normalized in {"go", "golang"}:
        return "go"
    if normalized in {"crates.io", "cargo"}:
        return "cargo"
    return normalized


def _dedupe_links(links: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen_urls = set()
    result: List[Dict[str, str]] = []
    for link in links:
        label = str(link.get("label") or "").strip()
        url = str(link.get("url") or "").strip()
        if not label or not url or url in seen_urls:
            continue
        seen_urls.add(url)
        result.append({"label": label, "url": url})
    return result


def _extract_deps_dev_source_links(raw_links: Any) -> List[Dict[str, str]]:
    mapped: List[Dict[str, str]] = []
    fallback_candidates: List[str] = []

    def consider_entry(label: Any, url: Any) -> None:
        label_text = str(label or "").strip().upper()
        url_text = str(url or "").strip()
        if not url_text:
            return
        fallback_candidates.append(url_text)
        if label_text == "SOURCE_REPO":
            mapped.append({"label": "Repository", "url": url_text})
        elif label_text == "DOCUMENTATION":
            mapped.append({"label": "Documentation", "url": url_text})
        elif label_text == "ORIGIN":
            mapped.append({"label": "Package", "url": url_text})

    if isinstance(raw_links, list):
        for item in raw_links:
            if isinstance(item, dict):
                consider_entry(item.get("label") or item.get("type") or item.get("name"), item.get("url") or item.get("href"))
    elif isinstance(raw_links, dict):
        for label, url in raw_links.items():
            if isinstance(url, list):
                for entry in url:
                    if isinstance(entry, dict):
                        consider_entry(entry.get("label") or label, entry.get("url") or entry.get("href"))
                    else:
                        consider_entry(label, entry)
            else:
                consider_entry(label, url)

    mapped = _dedupe_links(mapped)
    has_repository = any(link["label"] == "Repository" for link in mapped)
    if not has_repository:
        for url in fallback_candidates:
            lowered = url.lower()
            if "github.com/" in lowered or "gitlab.com/" in lowered or "bitbucket.org/" in lowered:
                mapped.append({"label": "Repository", "url": url})
                break

    allowed_labels = {"Repository", "Documentation", "Package"}
    filtered = [link for link in mapped if link.get("label") in allowed_labels]
    return _dedupe_links(filtered)


def enrich_with_deps_dev(
    inventory: DependencyInventory,
    max_packages: Optional[int] = None,
) -> MetadataEnrichment:
    settings = get_config()
    packages: List[Dict[str, Any]] = []
    errors: List[str] = []
    skipped: List[Dict[str, Any]] = []

    dependencies = inventory.dependencies if max_packages is None else inventory.dependencies[:max_packages]
    for dep in dependencies:
        if not dep.name or not dep.version:
            continue
        if dep.version_kind != VersionKind.EXACT:
            skipped.append(
                {
                    "name": dep.name,
                    "version": dep.version,
                    "version_kind": dep.version_kind.value,
                    "version_specifier": dep.version_specifier or dep.version,
                    "reason": "non_exact_version",
                    "message": "Skipped deps.dev exact-version lookup because dependency version is not exact.",
                }
            )
            continue
        system = _system_from_ecosystem(dep.ecosystem)
        if not system:
            errors.append(f"{dep.name}: ecosystem is required for deps.dev")
            continue

        url = (
            f"https://api.deps.dev/v3/systems/{quote(system, safe='')}"
            f"/packages/{quote(dep.name, safe='')}/versions/{quote(dep.version, safe='')}"
        )
        try:
            response = requests.get(url, timeout=settings.request_timeout_seconds)
            response.raise_for_status()
            payload = response.json()
            packages.append(
                {
                    "name": dep.name,
                    "version": dep.version,
                    "system": system,
                    "licenses": payload.get("licenses", []),
                    "advisory_keys": payload.get("advisoryKeys", []),
                    "links": _extract_deps_dev_source_links(payload.get("links", [])),
                    "published_at": payload.get("publishedAt"),
                    "is_default": payload.get("isDefault"),
                }
            )
        except Exception as exc:
            errors.append(f"{dep.name}@{dep.version}: {exc}")

    status = "success" if packages and not errors else "partial" if packages or errors or skipped else "skipped"
    return MetadataEnrichment(
        provider="deps.dev",
        status=status,
        data={
            "packages": packages,
            "packages_checked_count": len(packages),
            "skipped": skipped,
            "skipped_count": len(skipped),
        },
        errors=errors,
    )
