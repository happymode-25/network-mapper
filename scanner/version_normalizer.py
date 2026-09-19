"""Version string normalization and comparison.

Converts messy vendor version strings (``8.9p1``, ``1.2.3-rc1``, ``v12.0.3``)
into canonical dotted numeric form so they can be compared with
``packaging.version.Version``. ``packaging`` is the primary parser; string
comparison is used as a fallback for versions it rejects.
"""

import re
from typing import Optional

from packaging.version import InvalidVersion, Version

_TOKEN_RE = re.compile(r"\d+(?:\.\d+)*[a-zA-Z0-9]*")


def normalize_version(raw: Optional[str]) -> Optional[str]:
    """Return a canonical dotted-numeric version for ``raw``.

    Examples:
        "8.9p1"      -> "8.9.1"
        "1.2.3-rc1"  -> "1.2.3.1"
        "v12.0.3"    -> "12.0.3"
        "2.4.41"     -> "2.4.41"
    """
    if not raw:
        return raw
    value = raw.strip()
    value = value.lstrip("vV")
    match = re.search(r"\d+(\.\d+)*([.\-_]?[a-z]+\d*)*", value, re.IGNORECASE)
    if not match:
        match = re.search(r"\d+(\.\d+)*", value)
    if not match:
        return raw
    segment = match.group(0)
    # Replace separators like "p", "r", "b", "-beta" with "."
    canonical = re.sub(r"[a-zA-Z\-_]+", ".", segment)
    canonical = re.sub(r"\.+", ".", canonical).strip(".")
    try:
        Version(canonical)
    except InvalidVersion:
        # Drop the final dangling numeric if it made the version invalid.
        numeric = re.findall(r"\d+", canonical)
        if numeric:
            canonical = ".".join(numeric)
    return canonical


def _p(v: Optional[str]):
    """Parse a version into a comparable object (or None)."""
    if not v:
        return None
    try:
        return Version(normalize_version(v))
    except InvalidVersion:
        return v


def compare_versions(a: Optional[str], b: Optional[str]) -> int:
    """Compare two versions: -1, 0 or 1. Missing values sort lowest."""
    pa, pb = _p(a), _p(b)
    if pa is None and pb is None:
        return 0
    if pa is None:
        return -1
    if pb is None:
        return 1
    if isinstance(pa, Version) and isinstance(pb, Version):
        return (pa > pb) - (pa < pb)
    return (str(pa) > str(pb)) - (str(pa) < str(pb))


def version_in_range(
    version: Optional[str],
    min_version: Optional[str] = None,
    max_version: Optional[str] = None,
    min_exclusive: bool = False,
    max_exclusive: bool = False,
) -> bool:
    """Return True when ``version`` falls within the given version window.

    Bounds are inclusive by default; pass ``min_exclusive``/``max_exclusive``
    to mirror NVD's ``versionStartExcluding``/``versionEndExcluding``.
    """
    if min_version:
        cmp = compare_versions(version, min_version)
        if cmp < 0 or (min_exclusive and cmp == 0):
            return False
    if max_version:
        cmp = compare_versions(version, max_version)
        if cmp > 0 or (max_exclusive and cmp == 0):
            return False
    return True


def is_exact_match(version: Optional[str], target: Optional[str]) -> bool:
    """Return True when two versions are numerically identical."""
    if not version or not target:
        return False
    return compare_versions(version, target) == 0