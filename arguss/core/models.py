"""Core data models for Arguss.

These Pydantic models define the contracts between components.
All lenses, scoring, AI, and serialization layers consume and produce these types.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

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


class Finding(BaseModel):
    """A single risk finding from one of the three lenses."""

    dependency: Dependency
    lens: LensName
    severity: Severity
    score: float = Field(ge=0, le=100, description="Normalized severity score 0-100.")
    title: str
    description: str
    remediation: str | None = None
    source_url: str | None = None


class LensScore(BaseModel):
    """Aggregated output of a single lens scan."""

    lens: LensName
    score: float = Field(ge=0, le=100)
    findings: list[Finding] = Field(default_factory=list)


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
