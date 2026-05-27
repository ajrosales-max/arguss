"""Build project-level lens score aggregates for proposal reports."""

from __future__ import annotations

import logging

from arguss.core.models import LensScore, PipelineSnapshot, ProjectScores
from arguss.scoring.unified import compute_prs

logger = logging.getLogger(__name__)


def build_project_scores(
    cve: LensScore,
    trust: LensScore,
    pipeline: PipelineSnapshot,
) -> ProjectScores | None:
    """Aggregate lens outputs into :class:`ProjectScores`, or ``None`` on failure."""
    try:
        vulnerability_subscore = round(cve.score)
        trust_subscore = round(trust.score)
        pipeline_subscore = pipeline.subscore
        prs = compute_prs(vulnerability_subscore, trust_subscore, pipeline_subscore)
        return ProjectScores(
            prs=prs,
            vulnerability_subscore=vulnerability_subscore,
            trust_subscore=trust_subscore,
            pipeline_subscore=pipeline_subscore,
        )
    except Exception:
        logger.exception("failed to build project scores")
        return None
