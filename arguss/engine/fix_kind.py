"""Classify semver deltas into :class:`~arguss.core.models.FixKind`."""

from __future__ import annotations

from arguss.core.models import FixKind


def _first_digit_index(s: str) -> int | None:
    for i, ch in enumerate(s):
        if ch.isdigit():
            return i
    return None


def _strip_to_version_start(s: str) -> str:
    """Drop leading junk (``v``, ``~``, etc.) so the core starts at a digit."""
    i = _first_digit_index(s)
    if i is None:
        return ""
    return s[i:]


def _leading_nonnegative_int(segment: str) -> int | None:
    """Parse the leading decimal integer from a semver segment (stops at first non-digit)."""
    if not segment:
        return None
    end = 0
    while end < len(segment) and segment[end].isdigit():
        end += 1
    if end == 0:
        return None
    return int(segment[:end])


def _parse_semver_triplet(version: str) -> tuple[int, int, int] | None:
    """Extract (major, minor, patch) from a relaxed semver string.

    Prereleases and build metadata are not modeled: only the numeric prefix of
    each dot-separated segment is used (e.g. ``1.2.3-alpha`` → 1, 2, 3).
    """
    core = _strip_to_version_start(version)
    if not core:
        return None

    parts = core.split(".", 2)
    if len(parts) < 1:
        return None

    major = _leading_nonnegative_int(parts[0])
    if major is None:
        return None

    minor = 0
    patch = 0

    if len(parts) >= 2:
        m = _leading_nonnegative_int(parts[1])
        if m is None:
            return None
        minor = m
    if len(parts) >= 3:
        p = _leading_nonnegative_int(parts[2])
        if p is None:
            return None
        patch = p

    return (major, minor, patch)


def compare_versions(left: str, right: str) -> int | None:
    """Compare two version strings using relaxed semver triplets.

    Returns -1 if left < right, 0 if equal, 1 if left > right, or None if either
    side is unparseable.
    """
    a = _parse_semver_triplet(left)
    b = _parse_semver_triplet(right)
    if a is None or b is None:
        return None
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def pick_lowest_version_gt(from_version: str, candidates: tuple[str, ...]) -> str | None:
    """Return the lowest semver among ``candidates`` strictly greater than ``from_version``.

    Unparseable candidate versions are ignored. Returns None if no eligible version exists.
    """
    eligible: list[str] = []
    for ver in candidates:
        if compare_versions(from_version, ver) == -1:
            eligible.append(ver)

    if not eligible:
        return None

    lowest = eligible[0]
    for ver in eligible[1:]:
        if compare_versions(ver, lowest) == -1:
            lowest = ver
    return lowest


def classify_fix_kind(from_version: str, to_version: str) -> FixKind:
    """Classify the semver delta between two versions.

    Uses semver semantics: major if from.major != to.major, minor if same major
    but different minor, patch otherwise. Handles common prefix patterns ('v1.2.3',
    '~1.2.3', etc.) by stripping non-numeric leading characters.

    Returns FixKind.MAJOR for any unparseable version (conservative: we don't
    know what kind of change this is, so we assume it's major).
    """
    a = _parse_semver_triplet(from_version)
    b = _parse_semver_triplet(to_version)
    if a is None or b is None:
        return FixKind.MAJOR

    if a[0] != b[0]:
        return FixKind.MAJOR
    if a[1] != b[1]:
        return FixKind.MINOR
    return FixKind.PATCH
