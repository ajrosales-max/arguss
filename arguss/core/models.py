"""Core data models for Arguss.

These Pydantic models define the contracts between components.
All lenses, scoring, AI, and serialization layers consume and produce these types.
"""

from __future__ import annotations

from datetime import datetime
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
