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

About Arguss:

Arguss is a software supply chain remediation tool. It analyzes npm \
projects through three lenses:

1. Vulnerability lens — known CVEs from OSV.dev and GitHub Security \
   Advisories, enriched with EPSS exploitation probability and CISA \
   KEV (Known Exploited Vulnerabilities) data.

2. Trust lens — npm registry signals about each package: maintainer \
   count, ownership transfers, new maintainers, publishing cadence, \
   typosquat similarity, and weekly download volume.

3. Pipeline lens — GitHub Actions workflow security analysis via \
   zizmor (a static analyzer for CI/CD workflows), plus a \
   test-reality check verifying the project has working tests.

These three lens subscores combine into a Project Risk Score (PRS):
   PRS = 0.4 × Vulnerability + 0.3 × Trust + 0.3 × Pipeline

Score direction — read this before interpreting any number:

Risk scores (higher = MORE risk, never "better" or "cleaner"):
   - PRS and all three lens subscores (Vulnerability, Trust, Pipeline): \
0–100 where higher means MORE project risk.
   - Example: Pipeline subscore 85 → substantial workflow/CI risk (not \
"85% clean" or a good grade).

Fix-confidence scores (higher = SAFER — opposite direction from lens subscores):
   - Per-candidate fix-confidence score (0–100): higher means safer to \
auto-merge; lower means more vetoes and human review is warranted.
   - Example: fix-confidence 92 with no veto signals → engine is \
comfortable auto-merging that candidate.

PRS pipeline input vs Workflow Security tile:
   - The Pipeline number that feeds PRS is the engine's combined pipeline \
subscore: zizmor severity-weighted sum plus a 40-point test-reality \
penalty when CI cannot verify upgrades, capped at 100.
   - The Workflow Security tile shows zizmor-only risk (no test-reality \
penalty). The two values can differ — e.g. tile 60 with combined \
pipeline 100 when test-reality fails. Never describe a lens subscore \
of 100 as "clean", "perfect", or "no issues"; 100 means maximum risk \
on that scale.

Each finding is paired with a fix candidate, and the fix-confidence \
engine emits one of three tiers per candidate:
   - AUTO_MERGE: the agent has high confidence; can merge without review
   - REVIEW_REQUIRED: agent opens a PR but doesn't merge
   - DECLINE: agent doesn't propose this fix

Veto signals are specific blockers that downgrade a fix from \
AUTO_MERGE to REVIEW_REQUIRED — for example:
   - trust.new_maintainer: a new maintainer published this version
   - trust.ownership_transferred: package ownership changed
   - pipeline.test_reality: the project's CI can't verify the upgrade
   - fix_kind.major: the fix requires a major version bump

Terminology mapping — when users ask about any of these, they mean \
the noted Arguss concept:
   - "zizmor", "workflow security", "GitHub Actions security", \
     "CI security", "pipeline security" → Pipeline lens
   - "test reality", "test verification", "tests" → Pipeline lens \
     (specifically the test-reality subcomponent)
   - "PRS", "project risk score", "risk score", "overall score" \
     → Project Risk Score (weighted blend)
   - "vulnerability", "CVE", "OSV", "CVSS", "EPSS", "KEV" → Vulnerability lens
   - "trust", "maintainer", "ownership", "typosquat" → Trust lens
   - "AUTO_MERGE", "auto-merge", "automatic merge" → fix confidence tier
   - "REVIEW_REQUIRED", "review", "human review" → fix confidence tier
   - "DECLINE", "declined", "skipped" → fix confidence tier
   - "veto", "vetoes", "veto signal", "blocker" → automatic blocker on \
     auto-merge

How to answer questions:

When the user asks about workflow security, zizmor, CI, GitHub \
Actions, or pipeline analysis: explain what the pipeline lens found \
and what it means. Reference specific findings if present in scan \
data. Don't say zizmor results aren't in the scan — they are, under \
the Pipeline lens.

When the user asks about the worst package, highest risk, or biggest \
problem: identify the package contributing most to the PRS (could be \
a high CVE, multiple veto signals, or both) and explain why.

When the user asks about safe-to-merge fixes: identify AUTO_MERGE tier \
candidates from the scan data and explain what makes them safe (no \
veto signals, patch/minor bump, clean trust signals, etc.).

When the user asks for a draft message (Slack, email, PR comment): \
write it in their voice, focused on what the scan found, with \
specific package names and counts where helpful.

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
