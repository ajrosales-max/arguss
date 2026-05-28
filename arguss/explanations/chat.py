"""Claude chat handler for scan-grounded Q&A.

Bounded to a single scan; uses the call_claude helper from the
explanations client module. Fail-soft like all Claude integration here.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel

from arguss.explanations._client import call_claude
from arguss.explanations.scan_cache import get_cached_scan_response

_LOG = logging.getLogger(__name__)

_SYSTEM_PROMPT_TEMPLATE = """You are an assistant helping a user understand an \
Arguss supply chain scan result. You will be given the structured scan data and \
the user's question.

Rules:
- Answer ONLY based on the scan data provided. Do not invent findings, packages, \
  scores, or recommendations beyond what's in the data.
- If asked about something outside this scan, politely say you can only answer \
  about this specific scan.
- Be concise. Plain language. No markdown headers or bullets unless the user \
  explicitly asks for a list.
- When citing specific findings, reference the package name, version delta, and \
  veto signals from the data.
- Don't speculate about CVEs not present in the scan.
- Don't make recommendations beyond what the verdict already says \
  (AUTO_MERGE / REVIEW_REQUIRED / DECLINE).

Scan data:
{scan_data}
"""


class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str


def answer_question(
    scan_input_hash: str,
    history: list[ChatMessage],
    question: str,
) -> str | None:
    """Generate an assistant response for a chat question about a scan.

    Returns None on any failure (Claude unavailable, scan not in cache, etc).
    """
    scan_data = get_cached_scan_response(scan_input_hash)
    if scan_data is None:
        return None

    compact = _compact_scan_data(scan_data)
    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
        scan_data=json.dumps(compact, indent=2),
    )

    history_text = "\n\n".join(
        f"User: {m.content}" if m.role == "user" else f"Assistant: {m.content}" for m in history
    )
    user_message = f"{history_text}\n\nUser: {question}" if history_text else question

    return call_claude(
        system_prompt=system_prompt,
        user_message=user_message,
        max_tokens=600,
        timeout=15.0,
    )


def _compact_scan_data(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Reduce a full scan response to a compact representation for chat."""
    entries = scan_data.get("entries", [])
    if not isinstance(entries, list):
        entries = []

    by_package: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        candidate = entry.get("candidate")
        verdict = entry.get("verdict")
        if not isinstance(candidate, dict) or not isinstance(verdict, dict):
            continue
        pkg = candidate.get("package")
        if not isinstance(pkg, str):
            continue
        score = verdict.get("score")
        if not isinstance(score, (int, float)):
            continue
        if pkg not in by_package or score < by_package[pkg]["verdict"]["score"]:
            by_package[pkg] = entry

    sorted_pkgs = sorted(by_package.values(), key=lambda e: e["verdict"]["score"])[:10]

    summary_raw = scan_data.get("summary")
    summary_dict: dict[str, Any] = summary_raw if isinstance(summary_raw, dict) else {}

    headline_entries: list[dict[str, Any]] = []
    for entry in sorted_pkgs:
        raw_finding = entry.get("finding")
        raw_candidate = entry.get("candidate")
        entry_finding: dict[str, Any] = raw_finding if isinstance(raw_finding, dict) else {}
        entry_candidate: dict[str, Any] = raw_candidate if isinstance(raw_candidate, dict) else {}
        headline_entries.append(
            {
                "package": entry_candidate.get("package"),
                "verdict": entry.get("verdict"),
                "cve_id": entry_finding.get("cve_id"),
                "epss_score": entry_finding.get("epss_score"),
                "max_epss_score": entry_candidate.get("max_epss_score"),
                "is_kev": entry_finding.get("is_kev", False),
                "kev_known_ransomware": entry_finding.get("kev_known_ransomware", False),
            }
        )

    return {
        "summary": summary_dict,
        "project_scores": scan_data.get("project_scores"),
        "executive_summary": scan_data.get("executive_summary"),
        "headline_entries": headline_entries,
        "highest_epss_in_scan": {
            "score": summary_dict.get("max_epss_score"),
            "cve_id": summary_dict.get("max_epss_cve_id"),
            "package": summary_dict.get("max_epss_package"),
        },
        "kev_findings": {
            "count": summary_dict.get("kev_count", 0),
            "cve_ids": summary_dict.get("kev_cve_ids", []),
        },
        "skipped_count": len(scan_data.get("skipped_findings", [])),
    }
