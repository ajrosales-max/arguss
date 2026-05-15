# ──────────────────────────────────────────────────────────────────────────────
# Week 2 pivot marker (May 2026)
# ──────────────────────────────────────────────────────────────────────────────
# This module currently produces a single Project Risk Score (PRS) intended for
# human review:
#
#     PRS = 0.4 * CVE_risk + 0.3 * trust_risk + 0.3 * pipeline_risk
#
# Per docs/planning/pivot-rationale.md, Arguss is being repositioned as an
# autonomous remediation agent. In Week 6 this module will gain a second,
# additive output: a per-remediation fix-confidence score that gates whether
# the agent is allowed to act on a given finding without human review.
#
# The existing PRS computation and its consumers (CLI output, dashboard
# observability view) are unchanged by the pivot. The fix-confidence engine
# is purely additive — new function, new return type, new caller path from
# the agent loop (Week 7+).
#
# See:
#   - docs/planning/pivot-rationale.md   — why the pivot
#   - docs/planning/project-overview.md  — the new product framing
#   - docs/planning/week-3-plan.md       — current implementation scope
# ──────────────────────────────────────────────────────────────────────────────

"""Unified scoring engine.

Combines the three lens sub-scores into a single project risk score.
The math is real and stable from day one; only the inputs change.
"""

from datetime import UTC, datetime

from arguss.core.models import LensScore, ProjectScore, Remediation

# Default weights. Configurable via env or CLI in future.
DEFAULT_WEIGHTS = {
    "cve": 0.40,
    "trust": 0.30,
    "pipeline": 0.30,
}


def compute_project_score(
    cve: LensScore,
    trust: LensScore,
    pipeline: LensScore,
    project_path: str = ".",
    weights: dict[str, float] | None = None,
) -> ProjectScore:
    """Combine three lens scores into a unified ProjectScore.

    Args:
        cve: Vulnerability lens output.
        trust: Trust signal lens output.
        pipeline: Pipeline configuration lens output.
        project_path: Path to the project being scanned (for the report).
        weights: Optional override for lens weights. Must sum to 1.0.

    Returns:
        ProjectScore with overall risk, per-lens breakdown, and ranked remediations.
    """
    w = weights or DEFAULT_WEIGHTS
    _validate_weights(w)

    overall = cve.score * w["cve"] + trust.score * w["trust"] + pipeline.score * w["pipeline"]

    return ProjectScore(
        overall=round(overall, 2),
        lens_scores={
            "cve": cve,
            "trust": trust,
            "pipeline": pipeline,
        },
        top_remediations=_rank_remediations(cve, trust, pipeline),
        scanned_at=datetime.now(UTC),
        project_path=project_path,
    )


def _validate_weights(weights: dict[str, float]) -> None:
    """Ensure weights sum to 1.0 within floating-point tolerance."""
    total = sum(weights.values())
    if abs(total - 1.0) > 0.01:
        raise ValueError(f"Lens weights must sum to 1.0, got {total}")


def _rank_remediations(
    cve: LensScore,
    trust: LensScore,
    pipeline: LensScore,
) -> list[Remediation]:
    """Generate ranked list of top remediations.

    WEEK 6: Replace stub with real ranker that computes score reduction
    per proposed upgrade.
    """
    # Stub: return empty list for now. Real ranker lands Week 6.
    return []
