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
