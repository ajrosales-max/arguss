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

from typing import Final

from arguss.core.models import Finding, FixCandidate, FixConfidence
from arguss.explanations._client import call_claude

_MAX_TOKENS: Final[int] = 512
_API_TIMEOUT_SECONDS: Final[float] = 15.0

_SYSTEM_PROMPT = """You explain software dependency upgrade decisions to engineers reviewing pull requests.

Be concise, technical, and honest about uncertainty. Write 3-5 sentences of plain Markdown prose. Do NOT include a preamble like "Here's an explanation:" — write the explanation directly. Do NOT repeat the structured data verbatim; synthesize it into context that helps a human reviewer decide.

If the agent is confident (AUTO_MERGE), explain why the fix is safe in context. If the agent is escalating (REVIEW_REQUIRED), explain what specifically concerns the agent and what the human should verify. If the agent is declining (DECLINE), explain why the fix should not be applied."""


def explain_verdict_to_human(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
) -> str | None:
    """Generate a prose explanation of the verdict for human reviewers.

    Returns the prose string on success, or None on any failure (missing
    API key, network error, API timeout, rate limit, malformed response).
    Callers MUST handle None by falling back to a deterministic alternative.

    This function is sync (call from a threadpool in async contexts).
    """
    user_prompt = _build_user_prompt(candidate, verdict, finding)

    return call_claude(
        system_prompt=_SYSTEM_PROMPT,
        user_message=user_prompt,
        max_tokens=_MAX_TOKENS,
        timeout=_API_TIMEOUT_SECONDS,
    )


def _build_user_prompt(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
) -> str:
    """Construct the user prompt from structured inputs."""
    reasons_block = "\n".join(f"- {r}" for r in verdict.reasons) or "- (no reasons)"
    veto_signals = ", ".join(verdict.veto_signals) if verdict.veto_signals else "none"

    return f"""A package vulnerability fix candidate has been evaluated:

**Package:** {candidate.package}
**Upgrade:** {candidate.from_version} → {candidate.to_version} ({candidate.fix_kind.value})
**Vulnerability:** {finding.advisory_id or "(no advisory ID)"}
**Title:** {finding.title}

**Engine verdict:** {verdict.tier.value} (score: {verdict.score}/100)
**Veto signals fired:** {veto_signals}

**Structured reasons:**
{reasons_block}

**CVE description (excerpt):**
{(finding.description or "(no description)")[:1500]}

Explain this decision in 3-5 sentences of plain Markdown prose suitable for a PR body. Write directly without preamble."""
