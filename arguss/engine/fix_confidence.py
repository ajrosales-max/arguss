"""Fix-confidence engine: combine lens outputs into a remediation verdict."""

from __future__ import annotations

from datetime import UTC, datetime

from arguss.core.models import (
    FixCandidate,
    FixConfidence,
    FixKind,
    FixTier,
    PipelineSnapshot,
    TrustDelta,
    TrustFlag,
)
from arguss.engine.kill_switch import is_kill_switch_active

ENGINE_VERSION = "fix-confidence-v1.0.0"

_KILL_SWITCH_REASON = "engine administratively disabled via kill switch"
_PROJECT_VETO_REASON = "project-level veto: all auto-merges halted for this repository"

_TRUST_FLAG_VETO: dict[TrustFlag, str] = {
    TrustFlag.OWNERSHIP_TRANSFER: "trust.ownership_transferred",
    TrustFlag.NEW_MAINTAINER: "trust.new_maintainer",
    TrustFlag.CADENCE_ANOMALY: "trust.cadence_anomaly",
    TrustFlag.DOWNLOAD_COLLAPSE: "trust.download_collapse",
}

_TRUST_FLAG_REASON: dict[TrustFlag, str] = {
    TrustFlag.OWNERSHIP_TRANSFER: ("trust veto: package ownership transferred between versions"),
    TrustFlag.NEW_MAINTAINER: "trust veto: new maintainer added",
    TrustFlag.CADENCE_ANOMALY: "trust veto: publish cadence anomaly detected",
    TrustFlag.DOWNLOAD_COLLAPSE: "trust veto: weekly download count collapsed",
}

_SCORE_REDUCTION: dict[str, int] = {
    "fix_kind.major": 50,
    "trust.unavailable": 20,
    "trust.ownership_transferred": 15,
    "trust.new_maintainer": 15,
    "trust.cadence_anomaly": 15,
    "trust.download_collapse": 15,
    "pipeline.unavailable": 25,
    "pipeline.test_reality": 25,
}

_FIX_KIND_LABEL: dict[FixKind, str] = {
    FixKind.PATCH: "patch-level",
    FixKind.MINOR: "minor-level",
    FixKind.MAJOR: "major-level",
}


def _utc_now() -> datetime:
    """Current time in UTC (patchable in tests for determinism)."""
    return datetime.now(UTC)


def _auto_merge_reason(fix_kind: FixKind) -> str:
    label = _FIX_KIND_LABEL[fix_kind]
    return f"{label} upgrade; trust signals unchanged; CI verifies tests"


def _collect_review_vetoes(
    candidate: FixCandidate,
    trust_delta: TrustDelta | None,
    pipeline_snapshot: PipelineSnapshot | None,
) -> tuple[list[str], list[str]]:
    """Gather independent review vetoes (steps 3–7). Each may fire simultaneously."""
    veto_signals: list[str] = []
    reasons: list[str] = []

    if candidate.fix_kind is FixKind.MAJOR:
        veto_signals.append("fix_kind.major")
        reasons.append("major version bump requires human review (never auto-merge)")

    if trust_delta is None:
        veto_signals.append("trust.unavailable")
        reasons.append("trust signals unavailable for this package upgrade")
    elif not trust_delta.safe_to_auto_merge:
        # Invariant from TrustDelta construction: safe_to_auto_merge is True iff
        # flags is empty. If that invariant breaks, this branch may not fire when
        # flags are present but safe_to_auto_merge is incorrectly True.
        for flag in trust_delta.flags:
            signal = _TRUST_FLAG_VETO[flag]
            veto_signals.append(signal)
            reasons.append(_TRUST_FLAG_REASON[flag])

    if pipeline_snapshot is None:
        veto_signals.append("pipeline.unavailable")
        reasons.append("pipeline snapshot unavailable; cannot verify CI")
    elif not pipeline_snapshot.test_reality.safe_to_auto_merge:
        veto_signals.append("pipeline.test_reality")
        blocked = pipeline_snapshot.test_reality.reasons_blocked
        if blocked:
            detail = "; ".join(blocked)
            reasons.append(
                "pipeline veto: Your project's CI provides no test signal "
                f"({detail}). The agent cannot verify behavior post-upgrade."
            )
        else:
            reasons.append(
                "pipeline veto: Your project's CI provides no test signal. "
                "The agent cannot verify behavior post-upgrade."
            )

    return veto_signals, reasons


def _score_for_review(veto_signals: tuple[str, ...]) -> int:
    score = 100
    for signal in veto_signals:
        score -= _SCORE_REDUCTION.get(signal, 0)
    return max(1, score)


def _decline_confidence(
    candidate: FixCandidate,
    *,
    reason: str,
    veto_signal: str,
    evaluated_at: datetime,
) -> FixConfidence:
    return FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=FixTier.DECLINE,
        score=0,
        reasons=(reason,),
        veto_signals=(veto_signal,),
        evaluated_at=evaluated_at,
        engine_version=ENGINE_VERSION,
    )


def compute_fix_confidence(
    candidate: FixCandidate,
    trust_delta: TrustDelta | None,
    pipeline_snapshot: PipelineSnapshot | None,
    project_veto: bool = False,
) -> FixConfidence:
    """Compute the engine's verdict for a remediation candidate.

    Inputs:
        candidate: the FixCandidate being evaluated
        trust_delta: the trust signal delta for this package across the upgrade
                     window. None means trust signals couldn't be computed
                     (e.g., package not on registry) — treated as a soft block.
        pipeline_snapshot: the repo's pipeline snapshot. None means the repo
                           context isn't available — treated as a hard block
                           (no CI verification = no auto-merge).
        project_veto: optional escape hatch. If True, force tier=DECLINE
                      regardless of other signals. The Week 6 design exposes
                      this hook; no consumer wires it yet.

    Returns FixConfidence with tier, score, reasons, and audit context.

    Evaluation order (each can downgrade tier):
        1. Kill switch active → DECLINE (terminal)
        2. project_veto → DECLINE (terminal)
        3. FixKind.MAJOR → REVIEW_REQUIRED (major bumps never auto-merge)
        4. trust_delta is None → REVIEW_REQUIRED (can't verify trust)
        5. trust_delta.safe_to_auto_merge is False → REVIEW_REQUIRED
           (with specific TrustFlag values as veto_signals)
        6. pipeline_snapshot is None → REVIEW_REQUIRED (no CI to verify)
        7. pipeline_snapshot.test_reality.safe_to_auto_merge is False
           → REVIEW_REQUIRED (with the specific reasons_blocked as veto_signals)

    If none of 1-7 triggered, tier = AUTO_MERGE.

    Score (0-100):
        Starts at 100 if AUTO_MERGE. Reduced by signal strength for
        REVIEW_REQUIRED. 0 for DECLINE.

    For REVIEW_REQUIRED, score reductions:
        - FixKind.MAJOR: -50 (major bumps are inherently risky)
        - Each trust veto signal: -15
        - Pipeline test_reality fail: -25
        - Trust unavailable: -20
        - Pipeline unavailable: -25
    Floor at 1 for REVIEW_REQUIRED (DECLINE is the only tier with score=0).

    The score is for the dashboard and for empirical tuning in Week 11.
    The tier is what the agent reads.

    Reasons (tuple of human-readable strings):
        - AUTO_MERGE: a one-line positive justification
          (e.g., "patch-level upgrade; trust signals unchanged; CI verifies tests")
        - REVIEW_REQUIRED: enumerated reasons each veto fired
        - DECLINE: the terminal reason (kill switch / project_veto)

    veto_signals (tuple of machine-readable IDs):
        - kill_switch
        - project_veto
        - fix_kind.major
        - trust.unavailable
        - trust.ownership_transferred
        - trust.new_maintainer
        - trust.cadence_anomaly
        - trust.download_collapse
        - pipeline.unavailable
        - pipeline.test_reality
    """
    evaluated_at = _utc_now()

    if is_kill_switch_active():
        return _decline_confidence(
            candidate,
            reason=_KILL_SWITCH_REASON,
            veto_signal="kill_switch",
            evaluated_at=evaluated_at,
        )

    if project_veto:
        return _decline_confidence(
            candidate,
            reason=_PROJECT_VETO_REASON,
            veto_signal="project_veto",
            evaluated_at=evaluated_at,
        )

    veto_signals, reasons = _collect_review_vetoes(candidate, trust_delta, pipeline_snapshot)

    if veto_signals:
        sorted_signals = tuple(sorted(veto_signals))
        return FixConfidence(
            candidate_id=candidate.candidate_id,
            tier=FixTier.REVIEW_REQUIRED,
            score=_score_for_review(sorted_signals),
            reasons=tuple(sorted(reasons)),
            veto_signals=sorted_signals,
            evaluated_at=evaluated_at,
            engine_version=ENGINE_VERSION,
        )

    return FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=FixTier.AUTO_MERGE,
        score=100,
        reasons=(_auto_merge_reason(candidate.fix_kind),),
        veto_signals=(),
        evaluated_at=evaluated_at,
        engine_version=ENGINE_VERSION,
    )
