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
from dataclasses import dataclass
from typing import Any, Final

from arguss.core.models import Finding, FixCandidate, FixConfidence
from arguss.explanations._client import call_claude

_MAX_TOKENS: Final[int] = 512
_FINDING_EXPLAIN_MAX_TOKENS: Final[int] = 384
_FINDING_EXPLAIN_SELECT_MAX_TOKENS: Final[int] = 512
_VERSION_RISKS_DELIMITER: Final[str] = "---VERSION_RISKS---"
_API_TIMEOUT_SECONDS: Final[float] = 15.0

_SYSTEM_PROMPT = """You explain software dependency upgrade decisions to engineers reviewing pull requests.

Be concise, technical, and honest about uncertainty. Write 3-5 sentences of plain Markdown prose. Do NOT include a preamble like "Here's an explanation:" - write the explanation directly. Do NOT repeat the structured data verbatim; synthesize it into context that helps a human reviewer decide.

If the agent is confident (AUTO_MERGE), explain why the fix is safe in context. If the agent is escalating (REVIEW_REQUIRED), explain what specifically concerns the agent and what the human should verify. If the agent is declining (DECLINE), explain why the fix should not be applied."""

_FINDING_EXPLAIN_SYSTEM = """You explain a single fix-confidence verdict on a supply chain scan results dashboard.

Write 2-4 sentences of plain prose for a security engineer reviewing findings. Be concise, technical, and honest about uncertainty. Do NOT include a preamble — write the explanation directly. Do NOT invent CVEs, scores, veto signals, or package details not present in the input.

If the verdict is AUTO_MERGE, explain why the proposed upgrade looks acceptable in context. If REVIEW_REQUIRED, explain what warrants human review. If DECLINE, explain why the fix should not be applied automatically."""

_FINDING_EXPLAIN_SELECT_SYSTEM = f"""You explain a fix-confidence verdict and version-change risks for a supply chain scan candidate-selection page.

Produce exactly two sections separated by the delimiter line `{_VERSION_RISKS_DELIMITER}` on its own line.

Section 1 (before the delimiter): 2-4 sentences of plain prose explaining the verdict for a security engineer. Be concise, technical, and honest about uncertainty. Do NOT include a preamble — write the explanation directly. Do NOT invent CVEs, scores, veto signals, or package details not present in the input.

Section 2 (after the delimiter): 2-4 sentences describing risks of applying the proposed version change (breaking changes, semver gaps, transitive impact, rollback concerns). Base this only on information in the input.

If the verdict is AUTO_MERGE, explain why the upgrade looks acceptable in context. If REVIEW_REQUIRED, explain what warrants human review. If DECLINE, explain why the fix should not be applied automatically."""


@dataclass(frozen=True)
class FindingExplainSections:
    verdict: str
    version_risks: str


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


def explain_finding_verdict_to_human(entry: dict[str, Any]) -> str | None:
    """Generate a short dashboard explanation for one finding entry.

    Display-only prose for humans. Returns None on any failure (same contract as
    ``explain_verdict_to_human``). Sync — call from a threadpool in async contexts.
    """
    finding_raw = entry.get("finding")
    candidate_raw = entry.get("candidate")
    verdict_raw = entry.get("verdict")
    finding: dict[str, Any] = finding_raw if isinstance(finding_raw, dict) else {}
    candidate: dict[str, Any] = candidate_raw if isinstance(candidate_raw, dict) else {}
    verdict: dict[str, Any] = verdict_raw if isinstance(verdict_raw, dict) else {}
    user_prompt = _build_finding_explain_user_prompt(finding, candidate, verdict)

    return call_claude(
        system_prompt=_FINDING_EXPLAIN_SYSTEM,
        user_message=user_prompt,
        max_tokens=_FINDING_EXPLAIN_MAX_TOKENS,
        timeout=_API_TIMEOUT_SECONDS,
    )


def explain_finding_verdict_for_select(entry: dict[str, Any]) -> FindingExplainSections | None:
    """Generate verdict explanation and version-change risks for candidate selection.

    Display-only prose for humans. Returns None on any failure (same contract as
    ``explain_finding_verdict_to_human``). Sync — call from a threadpool in async contexts.
    """
    finding_raw = entry.get("finding")
    candidate_raw = entry.get("candidate")
    verdict_raw = entry.get("verdict")
    finding: dict[str, Any] = finding_raw if isinstance(finding_raw, dict) else {}
    candidate: dict[str, Any] = candidate_raw if isinstance(candidate_raw, dict) else {}
    verdict: dict[str, Any] = verdict_raw if isinstance(verdict_raw, dict) else {}
    user_prompt = _build_finding_explain_select_user_prompt(finding, candidate, verdict)

    raw = call_claude(
        system_prompt=_FINDING_EXPLAIN_SELECT_SYSTEM,
        user_message=user_prompt,
        max_tokens=_FINDING_EXPLAIN_SELECT_MAX_TOKENS,
        timeout=_API_TIMEOUT_SECONDS,
    )
    if raw is None:
        return None
    return _parse_finding_explain_select_response(raw)


def _build_finding_explain_user_prompt(
    finding: dict[str, Any],
    candidate: dict[str, Any],
    verdict: dict[str, Any],
) -> str:
    dep_raw = finding.get("dependency")
    dep: dict[str, Any] = dep_raw if isinstance(dep_raw, dict) else {}
    package = candidate.get("package") or dep.get("name") or "package"
    from_version = candidate.get("from_version") or "?"
    to_version = candidate.get("to_version") or "?"
    fix_kind = candidate.get("fix_kind") or "unknown"
    tier = verdict.get("tier") or "unknown"
    score = verdict.get("score")
    score_text = str(score) if isinstance(score, (int, float)) else "unknown"
    veto_signals = verdict.get("veto_signals") or ()
    veto_list = veto_signals if isinstance(veto_signals, list) else list(veto_signals)
    veto_text = ", ".join(str(v) for v in veto_list) if veto_list else "none"
    reasons = verdict.get("reasons") or ()
    reason_lines = reasons if isinstance(reasons, list) else list(reasons)
    reasons_block = "\n".join(f"- {r}" for r in reason_lines) or "- (no reasons)"

    advisory_id = finding.get("advisory_id") or finding.get("title") or "(no advisory ID)"
    cvss_raw = finding.get("cvss_score")
    cvss_text = f"{cvss_raw:.1f}" if isinstance(cvss_raw, (int, float)) else "unknown"
    title = finding.get("title") or advisory_id
    description = finding.get("description") or "(no description)"

    return f"""Explain this fix-confidence verdict for a dashboard reader.

**Package upgrade:** {package} {from_version} → {to_version} ({fix_kind})
**Advisory:** {advisory_id} (CVSS {cvss_text}) — {title}
**Engine verdict:** {tier} (score: {score_text}/100)
**Veto signals fired:** {veto_text}

**Structured reasons:**
{reasons_block}

**Advisory excerpt (may be truncated):**
{str(description)[:1200]}

Write 2-4 sentences explaining why this verdict was assigned and what the reviewer should note. Plain prose only — no bullet points or headers."""


def _build_finding_explain_select_user_prompt(
    finding: dict[str, Any],
    candidate: dict[str, Any],
    verdict: dict[str, Any],
) -> str:
    base_prompt = _build_finding_explain_user_prompt(finding, candidate, verdict)
    return f"""{base_prompt.rstrip()}

Then on its own line write `{_VERSION_RISKS_DELIMITER}`. After the delimiter, write 2-4 sentences on risks of applying the proposed version change. Plain prose only in both sections — no bullet points or headers."""


def _parse_finding_explain_select_response(raw: str) -> FindingExplainSections | None:
    text = raw.strip()
    if not text or _VERSION_RISKS_DELIMITER not in text:
        return None
    verdict_part, version_risks_part = text.split(_VERSION_RISKS_DELIMITER, 1)
    verdict = verdict_part.strip()
    version_risks = version_risks_part.strip()
    if not verdict or not version_risks:
        return None
    return FindingExplainSections(verdict=verdict, version_risks=version_risks)


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
