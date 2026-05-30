"""Generate human-readable prose explanations of fix-confidence verdicts.

The Claude integration lives here, separated from the decision engine
(arguss/engine/fix_confidence.py is pure and unaffected by this module).

Architectural ground rule: AI output is NEVER on the auto-merge path.
This module produces prose for human reviewers. Removing it entirely
doesn't change the agent's decisions; it only removes prose enrichment
in PR bodies and other human-facing surfaces.

Failure mode: any failure (missing API key, network error, API timeout,
rate limit, malformed response) returns None. Callers MUST handle None
by falling back to a deterministic alternative.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from arguss.core.models import Finding, FixCandidate, FixConfidence
from arguss.explanations._client import call_claude

_MAX_TOKENS: Final[int] = 512
_API_TIMEOUT_SECONDS: Final[float] = 15.0

_SYSTEM_PROMPT = """You explain software dependency upgrade decisions to engineers reviewing pull requests.

Be concise, technical, and honest about uncertainty. Write 3-5 sentences of plain Markdown prose. Do NOT include a preamble like "Here's an explanation:" - write the explanation directly. Do NOT repeat the structured data verbatim; synthesize it into context that helps a human reviewer decide.

If the agent is confident (AUTO_MERGE), explain why the fix is safe in context. If the agent is escalating (REVIEW_REQUIRED), explain what specifically concerns the agent and what the human should verify. If the agent is declining (DECLINE), explain why the fix should not be applied."""


def explain_verdict_to_human(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
    *,
    related_findings: Sequence[Finding] | None = None,
) -> str | None:
    """Generate a prose explanation of the verdict for human reviewers.

    Returns the prose string on success, or None on any failure (missing
    API key, network error, API timeout, rate limit, malformed response).
    Callers MUST handle None by falling back to a deterministic alternative.

    This function is sync (call from a threadpool in async contexts).
    """
    findings = tuple(related_findings) if related_findings else (finding,)
    user_prompt = _build_user_prompt(candidate, verdict, findings)

    return call_claude(
        system_prompt=_SYSTEM_PROMPT,
        user_message=user_prompt,
        max_tokens=_MAX_TOKENS,
        timeout=_API_TIMEOUT_SECONDS,
    )


def _sorted_findings_by_cvss(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda f: (-(f.cvss_score or 0.0), f.advisory_id or ""),
        )
    )


def _format_findings_block(findings: Sequence[Finding]) -> str:
    lines: list[str] = []
    for finding in _sorted_findings_by_cvss(findings):
        advisory_id = finding.advisory_id or "(no advisory ID)"
        cvss = (
            f"CVSS {finding.cvss_score:.1f}" if finding.cvss_score is not None else "CVSS unknown"
        )
        title = finding.title or advisory_id
        lines.append(f"- {advisory_id} ({cvss}): {title}")
    return "\n".join(lines)


def _build_user_prompt(
    candidate: FixCandidate,
    verdict: FixConfidence,
    findings: Sequence[Finding],
) -> str:
    """Construct the user prompt from structured inputs."""
    sorted_findings = _sorted_findings_by_cvss(findings)
    primary = sorted_findings[0]
    primary_advisory_id = primary.advisory_id or "(no advisory ID)"
    primary_cvss = f"{primary.cvss_score:.1f}" if primary.cvss_score is not None else "unknown"
    num_other = max(0, len(sorted_findings) - 1)
    findings_block = _format_findings_block(sorted_findings)

    reasons_block = "\n".join(f"- {r}" for r in verdict.reasons) or "- (no reasons)"
    veto_signals = ", ".join(verdict.veto_signals) if verdict.veto_signals else "none"

    multi_ack = ""
    if num_other > 0:
        multi_ack = (
            f"\n\nIf there are additional findings being addressed in the same upgrade "
            f"({num_other} of them), close with one sentence acknowledging them briefly "
            f"by ID. Do not deep-dive every finding."
        )

    return f"""You are explaining why an Arguss-generated PR is safe to auto-merge. The PR
upgrades {candidate.package} from {candidate.from_version} to {candidate.to_version} to address the
following advisories:

{findings_block}

Write a 3-5 sentence context paragraph for a security reviewer. Lead with
the highest-severity finding ({primary_advisory_id}, CVSS {primary_cvss}) —
describe its mechanism and real-world impact briefly. Mention the upgrade's
fix kind ({candidate.fix_kind.value}) and any concerns a reviewer should check.{multi_ack}

Do not repeat the package name or version numbers in the prose; those are
shown elsewhere in the PR body.

**Engine verdict:** {verdict.tier.value} (score: {verdict.score}/100)
**Veto signals fired:** {veto_signals}

**Structured reasons:**
{reasons_block}

**Primary CVE description (excerpt):**
{(primary.description or "(no description)")[:1500]}

Explain this decision in 3-5 sentences of plain Markdown prose suitable for a PR body. Write directly without preamble."""
