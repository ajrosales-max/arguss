"""Build project-level lens score aggregates for proposal reports."""

from __future__ import annotations

import logging

from arguss.core.models import LensScore, PipelineSnapshot, ProjectScores, TestRealityState
from arguss.scoring.unified import compute_prs

logger = logging.getLogger(__name__)


def derive_test_reality_state(pipeline: PipelineSnapshot) -> TestRealityState:
    """Lift pipeline test-reality to a project-level status for the results UI."""
    if not pipeline.workflow_files:
        return "not_applicable"
    if pipeline.test_reality.safe_to_auto_merge:
        return "verified"
    return "vetoed"


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
            test_reality=derive_test_reality_state(pipeline),
        )
    except Exception:
        logger.exception("failed to build project scores")
        return None
