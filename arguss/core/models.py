"""Core data models for Arguss.

These Pydantic models define the contracts between components.
All lenses, scoring, AI, and serialization layers consume and produce these types.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator

Severity = Literal["critical", "high", "medium", "low"]
LensName = Literal["cve", "trust", "pipeline"]
MigrationRisk = Literal["low", "medium", "high", "unknown"]
Confidence = Literal["low", "medium", "high"]


class Dependency(BaseModel):
    """A single package in the dependency graph."""

    name: str
    version: str
    ecosystem: str = "npm"
    direct: bool = Field(
        description="True if listed in the manifest directly; False if pulled in transitively."
    )
    path: list[str] = Field(
        default_factory=list,
        description="Chain of package names from project root to this dependency.",
    )
    parents: list[str] = Field(
        default_factory=list,
        description="Direct parents (packages that depend on this one).",
    )
    install_key: str = Field(
        default="",
        description=(
            "Raw lockfile ``packages`` key for this physical install "
            "(e.g. ``node_modules/glob/node_modules/minimatch``). Unique per physical "
            "install, fully deterministic, lockfile-relative (never a filesystem/temp "
            "path). Hashed into ``finding_id`` so identity tracks physical installs, not "
            "the display ``path``. Empty for synthetic/hand-built deps."
        ),
    )


def derive_finding_id(finding: Finding) -> str:
    """Stable id for a (dependency node, advisory) finding row.

    Identity is keyed on the physical install via ``Dependency.install_key`` (the raw
    lockfile ``packages`` key), NOT the logical ``path``. The install key is unique per
    physical install and fully deterministic, so same-version copies under different
    parents (e.g. ``minimatch@9.0.5`` x4) get distinct finding ids, and ids stay stable
    across re-scans regardless of unrelated lockfile changes. Synthetic deps without an
    install key fall back to an empty key segment (single-install fixtures only).
    """
    dep = finding.dependency
    advisory = finding.advisory_id or finding.title
    payload = f"{dep.name}|{dep.version}|{dep.install_key}|{advisory}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


class Finding(BaseModel):
    """A single risk finding from one of the three lenses."""

    dependency: Dependency
    lens: str
    severity: Severity
    score: float = Field(ge=0, le=100, description="Normalized severity score 0-100.")
    cvss_score: float | None = Field(
        default=None,
        description="Parsed CVSS base score when available from OSV (vulnerability lens only).",
    )
    title: str
    description: str
    remediation: str | None = None
    source_url: str | None = None
    advisory_id: str | None = Field(
        default=None,
        description="OSV advisory ID when lens is cve (e.g. GHSA-..., CVE-...).",
    )
    fixed_versions: tuple[str, ...] = Field(
        default_factory=tuple,
        description=(
            "Minimum fix versions from OSV ``affected`` ranges for this package; "
            "empty when the advisory has no fixed event. Populated by the vulnerability lens only."
        ),
    )
    published_at: str | None = Field(
        default=None,
        description="OSV advisory publish date (YYYY-MM-DD) when available.",
    )
    cve_id: str | None = Field(
        default=None,
        description="First CVE-* alias from the OSV record (alphabetically first when several).",
    )
    epss_score: float | None = Field(
        default=None,
        description="EPSS exploitation probability (0.0–1.0) for cve_id when available.",
    )
    epss_percentile: float | None = Field(
        default=None,
        description="EPSS percentile rank (0.0–1.0) among all CVEs when available.",
    )
    is_kev: bool = Field(
        default=False,
        description="True when cve_id is listed in the CISA KEV catalog (display-only).",
    )
    kev_date_added: str | None = Field(
        default=None,
        description="YYYY-MM-DD when CISA added this CVE to KEV.",
    )
    kev_due_date: str | None = Field(
        default=None,
        description="Federal patching deadline (YYYY-MM-DD) from KEV when present.",
    )
    kev_known_ransomware: bool = Field(
        default=False,
        description="True when KEV lists known ransomware campaign use.",
    )
    finding_id: str = Field(
        default="",
        description="Stable hash of name|version|install_key|advisory for joins and scan_counts.",
    )

    @model_validator(mode="after")
    def _ensure_finding_id(self) -> Self:
        if not self.finding_id:
            self.finding_id = derive_finding_id(self)
        return self


class ScanSkip(BaseModel):
    """Recorded when a lens could not complete fully (e.g. upstream API failure)."""

    reason: str
    detail: str
    lens: str


class NoFixSkip(BaseModel):
    """A finding with no automated remediation path (structured skip)."""

    kind: Literal["no_fix"] = "no_fix"
    finding_id: str = ""
    advisory_id: str = ""
    package: str = ""
    current_version: str = ""
    title: str = ""
    description: str = ""
    cvss_score: float | None = None
    severity: Severity | None = None
    source_url: str | None = None
    dependency_path: list[str] | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    kev_known_ransomware: bool = False
    kev_due_date: str | None = None
    reason: str = "no_fix_version_in_osv"
    reason_label: str = ""


class LensFailureSkip(BaseModel):
    """Lens-level degradation — scan incomplete, not per-finding no-fix."""

    kind: Literal["lens_failure"] = "lens_failure"
    reason: str = ""
    detail: str = ""
    lens: str = ""


SkippedFinding = NoFixSkip | LensFailureSkip


class LensScore(BaseModel):
    """Aggregated output of a single lens scan."""

    lens: LensName
    score: float = Field(ge=0, le=100)
    findings: list[Finding] = Field(default_factory=list)
    scan_skips: list[ScanSkip] = Field(default_factory=list)


class Explanation(BaseModel):
    """AI-generated explanation of a remediation."""

    summary: str
    why_it_matters: str
    migration_risk: MigrationRisk
    migration_notes: str
    suggested_steps: list[str]
    confidence: Confidence
    generated_at: datetime
    model: str = Field(description="Which Anthropic model produced this.")
    prompt_version: str = Field(description="Version tag of the prompt template used.")


class Remediation(BaseModel):
    """A proposed change that reduces project risk."""

    change: str = Field(description="Human-readable change, e.g., 'upgrade foo from 1.2 to 1.4'.")
    package_name: str
    from_version: str
    to_version: str
    findings_eliminated: list[Finding] = Field(default_factory=list)
    score_reduction: float = Field(
        ge=0,
        description="Estimated reduction in overall project score if applied.",
    )
    explanation: Explanation | None = None


class ProjectScore(BaseModel):
    """The unified result of an Arguss scan."""

    overall: float = Field(ge=0, le=100)
    lens_scores: dict[LensName, LensScore]
    top_remediations: list[Remediation] = Field(default_factory=list)
    scanned_at: datetime
    project_path: str


TestRealityState = Literal["verified", "vetoed", "not_applicable"]


@dataclass(frozen=True)
class ProjectScores:
    """Project-level aggregated risk scores from the three lenses.

    All fields optional - if a lens fails or has no score, the corresponding
    field is ``None``. PRS is ``None`` when any required lens output is missing.
    """

    prs: int | None = None
    vulnerability_subscore: int | None = None
    trust_subscore: int | None = None
    pipeline_subscore: int | None = None
    test_reality: TestRealityState | None = None


@dataclass(frozen=True)
class TrustSnapshot:
    """Static trust profile for a single package@version, captured at a point in time.

    Snapshots are the input to TrustDelta (Branch 2). The subscore field is
    consumed by the existing PRS path; the structured fields are consumed by
    the Week 6 fix-confidence engine.
    """

    package: str
    version: str
    captured_at: datetime

    # Maintainer data (from npm registry)
    maintainer_count: int
    maintainer_logins: tuple[
        str, ...
    ]  # sorted, for set comparison and frozen-dataclass compatibility

    # Publishing cadence (from npm registry version history)
    published_at: datetime
    days_since_previous_publish: int | None  # None if this is the first published version

    # Typosquat signals (computed)
    typosquat_distance: int | None  # min Levenshtein to top-1000 packages
    typosquat_nearest: (
        str | None
    )  # top-1000 name at min distance; equals package when package is in top-1000

    # Population
    weekly_downloads: int | None

    # Raw subscore for the existing PRS path (0-100, higher = riskier)
    subscore: int

    # OpenSSF Scorecard (display-only; does not affect subscore)
    scorecard_score: float | None = None
    scorecard_date: str | None = None
    scorecard_top_concerns: tuple[str, ...] | None = None


class TrustFlag(Enum):
    """Specific veto conditions that triggered ``safe_to_auto_merge=False``."""

    OWNERSHIP_TRANSFER = "ownership_transfer"
    NEW_MAINTAINER = "new_maintainer"
    CADENCE_ANOMALY = "cadence_anomaly"
    DOWNLOAD_COLLAPSE = "download_collapse"


@dataclass(frozen=True)
class TrustDelta:
    """What changed about a package's trust profile between two versions.

    Computed from two :class:`TrustSnapshot` records. Emitted by
    :func:`arguss.lenses.trust.fetch_delta` for development inspection and
    (Week 6) consumed by the fix-confidence engine as the agent's veto signal.
    """

    package: str
    from_version: str
    to_version: str

    maintainers_added: tuple[str, ...]
    maintainers_removed: tuple[str, ...]
    ownership_transferred: bool

    days_between_publishes: int
    publish_cadence_anomaly: bool

    weekly_downloads_change_pct: float | None

    flags: tuple[TrustFlag, ...]
    safe_to_auto_merge: bool


ZizmorSeverity = Literal["informational", "low", "medium", "high"]
ZizmorConfidence = Literal["unknown", "low", "medium", "high"]


@dataclass(frozen=True)
class ZizmorFinding:
    """Normalized finding from zizmor static analysis of a workflow file."""

    ident: str
    severity: ZizmorSeverity
    confidence: ZizmorConfidence
    description: str
    file: str
    line: int
    column: int
    feature: str
    annotation: str
    audit_url: str


@dataclass(frozen=True)
class TestReality:
    """Heuristic assessment: does this repo's CI actually verify changes?

    Four boolean conditions evaluated against the repo on disk. All four must
    hold for ``safe_to_auto_merge=True``. Conservative by design: false negatives
    escalate to human review; false positives would allow unverified auto-merge.
    """

    has_test_script: bool
    test_script_is_no_op: bool
    has_test_files: bool
    test_count: int
    workflow_runs_tests: bool
    safe_to_auto_merge: bool
    reasons_blocked: tuple[str, ...]


@dataclass(frozen=True)
class PipelineSnapshot:
    """Pipeline trust profile for a repository, captured at scan time."""

    repo_path: str
    workflow_files: tuple[str, ...]
    zizmor_findings: tuple[ZizmorFinding, ...]
    test_reality: TestReality
    subscore: int


class FixKind(Enum):
    """The semver delta of a remediation."""

    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"


class FixTier(Enum):
    """The agent's authority level for a specific fix.

    AUTO_MERGE: engine has high confidence; agent may merge without human review
    REVIEW_REQUIRED: agent opens a PR but does not auto-merge
    DECLINE: agent does not propose this fix (e.g., breaking change with no clear path)
    """

    AUTO_MERGE = "auto_merge"
    REVIEW_REQUIRED = "review_required"
    DECLINE = "decline"


def derive_repo_id(*, repo_path: Path, repo_identity: str | None = None) -> str:
    """Stable repository key for ``FixCandidate.repo_id`` / ``candidate_id``.

    Web GitHub scans pass canonical ``owner/repo`` so assessment (Contents API)
    and action re-scan (shallow clone) agree despite different temp directories.
    CLI and upload scans omit ``repo_identity`` and use the resolved filesystem path.
    """
    if repo_identity is not None:
        return repo_identity
    return str(repo_path.resolve())


# Bump when the cached scan_response payload shape changes OR when
# _derive_candidate_id inputs/hashing change. Mismatched reads → cache miss.
#
# History:
#   1 — original derivation (pre-stabilization)
#   2 — repo_id from owner/repo canonical identity (was: filesystem path)
#   3 — pre-deps payload shape
#   4 — deps array in cached scan_response payload
#   5 — finding_id on findings; source_finding_ids are finding_ids;
#       scan_counts object; candidate_id derivation input change
#   6 — vulnerability lens dedupes findings by finding_id; scan_counts
#       total_findings / findings_no_fix deflated for duplicate physical nodes
#   7 — scan_counts gains package_status_mixed_no_fix (display partition label)
#   8 — per-install parser; finding_id hashes install_key; deps carry install_key
SCAN_RESPONSE_SCHEMA_VERSION: int = 8


def _derive_candidate_id(
    package: str,
    from_version: str,
    to_version: str,
    fix_kind: FixKind,
    source_finding_ids: tuple[str, ...],
    repo_id: str,
) -> str:
    """Stable idempotency key for a remediation candidate (16 hex chars)."""
    finding_key = ",".join(sorted(source_finding_ids))
    payload = "|".join((package, from_version, to_version, fix_kind.value, finding_key, repo_id))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class FixCandidate:
    """A proposed remediation for a specific finding on a specific dependency.

    One FixCandidate represents one possible action: 'upgrade X from A to B'.
    Consolidation may merge multiple per-finding candidates into one per package.
    """

    package: str
    from_version: str
    to_version: str
    fix_kind: FixKind
    source_finding_ids: tuple[str, ...]  # finding_id values, not advisory IDs
    repo_id: str
    trust_subscore: int | None = None
    max_epss_score: float | None = None
    max_epss_percentile: float | None = None
    has_kev_finding: bool = False
    candidate_id: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "candidate_id",
            _derive_candidate_id(
                self.package,
                self.from_version,
                self.to_version,
                self.fix_kind,
                self.source_finding_ids,
                self.repo_id,
            ),
        )


@dataclass(frozen=True)
class FixConfidence:
    """The engine's verdict on a FixCandidate."""

    candidate_id: str
    tier: FixTier
    score: int
    reasons: tuple[str, ...]
    veto_signals: tuple[str, ...]
    evaluated_at: datetime
    engine_version: str
