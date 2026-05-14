"""CVSS v3.0 / v3.1 base score from vector strings.

Implements the Base Score formula from the FIRST CVSS v3.1 specification:
https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
import re
from typing import Final

# Confidentiality, Integrity, Availability impact coefficients
_CIA: Final[dict[str, float]] = {"N": 0.0, "L": 0.22, "H": 0.56}

_AV: Final[dict[str, float]] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}

_AC: Final[dict[str, float]] = {"L": 0.77, "H": 0.44}

_UI: Final[dict[str, float]] = {"N": 0.85, "R": 0.62}

_PR_UNCHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.62, "H": 0.27}

_PR_CHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.68, "H": 0.50}

_BASE_METRICS: Final[frozenset[str]] = frozenset({"AV", "AC", "PR", "UI", "S", "C", "I", "A"})


def _ceil_to_one_decimal(x: float) -> float:
    """CVSS Roundup: smallest value ≥ *x* expressed with one decimal place."""
    return math.ceil(x * 10.0 - 1e-12) / 10.0


def _parse_metric_pairs(rest: str) -> dict[str, str] | None:
    """Parse ``AV:N/AC:L/...`` into upper-cased metric → value."""
    out: dict[str, str] = {}
    for part in rest.split("/"):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            return None
        key, _, val = part.partition(":")
        key_u = key.strip().upper()
        val_s = val.strip()
        if not key_u or not val_s:
            return None
        if key_u in out:
            return None
        out[key_u] = val_s.upper()
    return out


def _compute_base_score(metrics: dict[str, str]) -> float | None:
    """Compute base score from validated metric letters, or None if any value is invalid."""
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError:
        return None

    scope = metrics["S"]
    if scope not in ("U", "C"):
        return None

    pr_map = _PR_UNCHANGED if scope == "U" else _PR_CHANGED
    try:
        pr = pr_map[metrics["PR"]]
    except KeyError:
        return None

    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)

    if scope == "U":  # noqa: SIM108 — spec branches for Unchanged vs Changed
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.15) ** 15)

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if scope == "U":  # noqa: SIM108 — Unchanged vs Changed base formula
        raw = impact + exploitability
    else:
        raw = 1.08 * (impact + exploitability)

    return min(10.0, _ceil_to_one_decimal(raw))


def parse_cvss3_vector(vector: str) -> float | None:
    """Parse a CVSS 3.x vector string and return the base score.

    Returns None if the vector is malformed, has unknown metric values,
    or isn't a CVSS 3.0 / 3.1 base vector (e.g. CVSS 2.0, CVSS 4.0).
    """
    if not isinstance(vector, str):
        return None
    stripped = vector.strip()
    if not stripped:
        return None

    upper = stripped.upper()
    if not (upper.startswith("CVSS:3.0/") or upper.startswith("CVSS:3.1/")):
        return None

    # Preserve original slash segment casing only for splitting; values are upper-cased.
    m = re.match(r"^CVSS:3\.[01]/(.*)$", stripped, flags=re.IGNORECASE | re.DOTALL)
    if not m or not m.group(1).strip():
        return None

    parsed = _parse_metric_pairs(m.group(1))
    if parsed is None:
        return None

    for req in _BASE_METRICS:
        if req not in parsed:
            return None

    unknown_keys = set(parsed) - _BASE_METRICS
    if unknown_keys:
        return None

    return _compute_base_score(parsed)
