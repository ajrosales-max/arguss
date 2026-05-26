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

import logging
from typing import Final

from anthropic import Anthropic, APIError, APITimeoutError

from arguss.core.models import Finding, FixCandidate, FixConfidence
from arguss.settings import settings

_MAX_TOKENS: Final[int] = 512
_API_TIMEOUT_SECONDS: Final[float] = 15.0

_LOG = logging.getLogger(__name__)

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
    if not settings.anthropic_api_key:
        _LOG.debug("Anthropic API key not configured; skipping explanation")
        return None

    user_prompt = _build_user_prompt(candidate, verdict, finding)

    try:
        client = Anthropic(
            api_key=settings.anthropic_api_key,
            timeout=_API_TIMEOUT_SECONDS,
        )
        message = client.messages.create(
            model=settings.anthropic_explanation_model,
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
    except APITimeoutError:
        _LOG.warning("Anthropic API timeout during explanation generation")
        return None
    except APIError as exc:
        _LOG.warning("Anthropic API error during explanation generation: %s", exc)
        return None
    except Exception as exc:
        _LOG.warning("Unexpected error during explanation generation: %s", exc)
        return None

    if not message.content:
        _LOG.warning("Anthropic response had empty content")
        return None

    first_block = message.content[0]
    text = getattr(first_block, "text", None)
    if not isinstance(text, str) or not text.strip():
        _LOG.warning("Anthropic response had no usable text")
        return None

    return text.strip()


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
