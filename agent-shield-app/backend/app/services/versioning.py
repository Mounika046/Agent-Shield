import re
from typing import Tuple

from packaging.version import InvalidVersion, Version

try:
    from app.schemas import VersionKind
except ModuleNotFoundError:
    from schemas import VersionKind


RANGE_MARKERS = (">", "<", "~", "^", "*", ",", "||", " - ")


def classify_version(version: str) -> VersionKind:
    value = (version or "").strip()
    if not value or value.lower() in {"latest", "*", "x"}:
        return VersionKind.UNKNOWN
    if any(marker in value for marker in RANGE_MARKERS):
        return VersionKind.RANGE
    if re.search(r"(?i)(^|\.)x($|\.)", value):
        return VersionKind.RANGE
    try:
        Version(value.lstrip("v"))
        return VersionKind.EXACT
    except InvalidVersion:
        return VersionKind.UNKNOWN


def normalize_version_fields(version: str) -> Tuple[str, VersionKind, str]:
    value = (version or "").strip()
    kind = classify_version(value)
    specifier = value if kind != VersionKind.EXACT else ""
    return value, kind, specifier
