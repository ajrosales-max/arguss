"""Generate Claude-prose executive summaries for scan results.

Presentation layer only — never influences verdicts. Failures are silent;
scans complete with ``executive_summary`` set to None.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from arguss.core.cache import Cache, get_connection, init_db
from arguss.explanations._client import call_claude
from arguss.settings import settings

_LOG = logging.getLogger(__name__)

_CACHE_SOURCE = "exec_summary"

_SYSTEM_PROMPT = """You are writing a 2-3 sentence executive summary for a software \
supply chain scan. You will be given structured data about findings, fix verdicts, \
and the most consequential veto signals.

Your job is to frame the data narratively — not to analyze it, not to recommend \
actions beyond what the data already says, not to invent details.

Rules:
- 2 to 3 sentences. No more.
- Reference specific package names and counts from the input.
- Headline the most consequential signal (a trust veto, a major-version escalation, \
  or a clean auto-merge story if there are no escalations).
- Plain language. No bullet points, no markdown, no headers, no preamble.
- Never invent packages, scores, or CVEs not present in the input.
- If the input shows zero findings, say so plainly in one sentence.

You are also provided EPSS (Exploit Prediction Scoring System) scores where available —
these are 0-1 probabilities that a CVE will be exploited in the next 30 days, updated
daily by FIRST.org. Use them to frame urgency when the highest EPSS is notable (>0.10).
"""


def build_claude_input(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Reduce a full scan result to the compact payload Claude needs."""
    summary = scan_result["summary"]
    entries = scan_result.get("entries", [])

    by_package: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        pkg = entry["candidate"]["package"]
        by_package.setdefault(pkg, []).append(entry)

    headline_packages: list[dict[str, Any]] = []
    for pkg, pkg_entries in by_package.items():
        worst = min(pkg_entries, key=lambda e: e["verdict"]["score"])
        finding = worst.get("finding") if isinstance(worst.get("finding"), dict) else {}
        candidate = worst.get("candidate") if isinstance(worst.get("candidate"), dict) else {}
        headline_packages.append(
            {
                "package": pkg,
                "finding_count": len(pkg_entries),
                "worst_score": worst["verdict"]["score"],
                "worst_tier": worst["verdict"]["tier"],
                "veto_signals": worst["verdict"].get("veto_signals", []),
                "reasons": worst["verdict"].get("reasons", [])[:3],
                "max_epss_score": candidate.get("max_epss_score"),
                "max_epss_cve_id": finding.get("cve_id"),
            }
        )
    headline_packages.sort(key=lambda p: p["worst_score"])
    headline_packages = headline_packages[:5]

    return {
        "summary": summary,
        "skipped_count": len(scan_result.get("skipped_findings", [])),
        "headline_packages": headline_packages,
        "highest_epss_in_scan": {
            "score": summary.get("max_epss_score"),
            "cve_id": summary.get("max_epss_cve_id"),
            "package": summary.get("max_epss_package"),
        },
    }


def cache_key(claude_input: dict[str, Any]) -> str:
    """Stable hash of the Claude input payload."""
    blob = json.dumps(claude_input, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _get_cache() -> Cache:
    conn = get_connection(settings.db_path)
    init_db(conn)
    return Cache(conn)


def generate_executive_summary(scan_result: dict[str, Any]) -> str | None:
    """Generate an executive summary, or return None on any failure."""
    claude_input = build_claude_input(scan_result)
    key = cache_key(claude_input)

    try:
        cache = _get_cache()
        cached = cache.get_cached_text(_CACHE_SOURCE, key)
        if cached is not None:
            return cached
    except Exception as exc:
        _LOG.warning("Executive summary cache read failed: %s", exc)

    user_message = json.dumps(claude_input, indent=2)
    result = call_claude(
        system_prompt=_SYSTEM_PROMPT,
        user_message=user_message,
        max_tokens=400,
        timeout=8.0,
    )

    if result is not None:
        try:
            cache = _get_cache()
            cache.set_cached_text(_CACHE_SOURCE, key, result, ttl_seconds=86400)
        except Exception as exc:
            _LOG.warning("Executive summary cache write failed: %s", exc)

    return result
