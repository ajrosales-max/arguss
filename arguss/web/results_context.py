"""Build template context for the dedicated /results/{hash} page from cached scan payloads."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, cast

import bleach
from markdown_it import MarkdownIt

from arguss.core.models import Finding, LensFailureSkip, PipelineSnapshot, ZizmorSeverity
from arguss.engine.skips import no_fix_reason_label
from arguss.lenses.pipeline import (
    _PIPELINE_SUBSCORE_WEIGHTS,
    _SUBSCORE_CAP,
    _TEST_REALITY_PENALTY,
)
from arguss.lenses.trust import TRUST_SUBSCORE_WEIGHTS, aggregate_trust_subscores
from arguss.lenses.vulnerability import _normalize_cvss_to_100
from arguss.scoring.unified import DEFAULT_WEIGHTS

BreakdownLine = tuple[str, str] | dict[str, Any]

_PIPELINE_TEST_REALITY_MODE_REASONS: dict[str, str] = {
    "A": ("CI workflow doesn't run tests reliably — can't verify upgrade safety."),
    "B": (
        "No workflows or test files in the upload to verify upgrade safety. "
        "Try Mode A (URL scan) against the same project for live workflow analysis."
    ),
    "C": (
        "CI workflow doesn't run tests reliably — can't verify upgrade safety. "
        "Add a test invocation to your workflow before re-running."
    ),
}


def finding_confidence_score_tier(score: int | float) -> str:
    """Fix-confidence score tier: lower score = riskier (inverse of lens subscores)."""
    s = int(score)
    if s >= 70:
        return "safe"
    if s >= 30:
        return "caution"
    return "danger"


def apply_mode_aware_verdict_reasons(cached: dict[str, Any]) -> dict[str, Any]:
    mode = (cached.get("scan_meta") or {}).get("mode")
    custom = _PIPELINE_TEST_REALITY_MODE_REASONS.get(str(mode)) if mode else None
    if not custom:
        return cached
    entries = cached.get("entries")
    if not isinstance(entries, list):
        return cached
    new_entries: list[Any] = []
    for entry in entries:
        if not isinstance(entry, dict):
            new_entries.append(entry)
            continue
        verdict = entry.get("verdict")
        if not isinstance(verdict, dict):
            new_entries.append(entry)
            continue
        signals = verdict.get("veto_signals") or ()
        if "pipeline.test_reality" not in signals:
            new_entries.append(entry)
            continue
        reasons = list(verdict.get("reasons") or [])
        new_reasons: list[str] = []
        replaced = False
        for reason in reasons:
            if (
                not replaced
                and isinstance(reason, str)
                and (
                    "pipeline veto" in reason.lower()
                    or "test signal" in reason.lower()
                    or "cannot verify behavior" in reason.lower()
                )
            ):
                new_reasons.append(custom)
                replaced = True
            else:
                new_reasons.append(reason)
        if not replaced:
            new_reasons.append(custom)
        new_entries.append({**entry, "verdict": {**verdict, "reasons": new_reasons}})
    return {**cached, "entries": new_entries}


CHAT_SUGGESTED_QUESTIONS: tuple[str, ...] = (
    "Why was the worst-scoring package flagged?",
    "Which fixes are safest to merge first?",
    "Summarize the trust risks",
    "Draft a Slack message about this scan",
)

GLOSSARY_SHORT_DESCRIPTIONS: dict[str, str] = {
    "trust-save": (
        "An upgrade Arguss blocked despite the newer version being available, "
        "because trust signals like ownership transfer or new maintainer fired "
        "during the upgrade window."
    ),
    "auto-merge": (
        "Verdict tier: the fix passes all three lenses cleanly. In Mode C, "
        "Arguss opens a PR, waits for CI, and merges if green."
    ),
    "review": (
        "Verdict tier: at least one veto fired. A human needs to decide whether "
        "to merge despite the flagged risk."
    ),
    "decline": (
        "Verdict tier: no remediation recommended. Usually because no fix version "
        "exists, or multiple critical vetoes make even human review unproductive."
    ),
    "fix-kind-major": (
        "Veto: the available fix requires a major version bump (1.x → 2.x), "
        "which implies potential breaking changes outside the auto-merge envelope."
    ),
    "trust-new-maintainer": (
        "Veto: a new publishing identity was added between your current version "
        "and the upgrade target. A well-documented supply chain attack vector."
    ),
    "trust-ownership-transferred": (
        "Veto: the package's primary maintainer changed during the upgrade window. "
        "Combined with new-maintainer, this is the highest-risk trust combination."
    ),
    "pipeline-test-reality": (
        "Veto: Arguss can't verify tests will run on upgraded code. Needs a "
        "test script in package.json, real test files, and a workflow that runs them."
    ),
    "cvss": (
        "Common Vulnerability Scoring System. A 0–10 score for how damaging "
        "exploitation could be. Severity, not urgency."
    ),
    "epss": (
        "Exploit Prediction Scoring System. Daily-updated probability that a CVE "
        "will be exploited in the next 30 days. Probability, not severity."
    ),
    "kev": (
        "CISA's Known Exploited Vulnerabilities catalog. Documented active "
        "exploitation in the wild — the strongest 'this is happening now' signal."
    ),
    "prs": (
        "Project Risk Score: weighted blend of vulnerability (40%), trust (30%), "
        "and pipeline (30%) subscores. Useful for at-a-glance triage."
    ),
}

_TRUST_VETO_PRIORITY = (
    "trust.ownership_transferred",
    "trust.new_maintainer",
    "trust.cadence_anomaly",
    "trust.download_collapse",
)
_ZIZMOR_SEVERITIES: tuple[ZizmorSeverity, ...] = (
    "informational",
    "low",
    "medium",
    "high",
)
_OWNERSHIP_VETO = "trust.ownership_transferred"


def ordinal(n: int) -> str:
    """1 → '1st', 2 → '2nd', 22 → '22nd', etc."""
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


@dataclass(frozen=True)
class ScoreBreakdown:
    """Human-readable explanation of how a lens subscore was computed."""

    title: str
    description: str
    lines: list[BreakdownLine]
    formula: str | None
    final_value: int | str


def _finding_normalized_score(cvss: float | None) -> float:
    return _normalize_cvss_to_100(cvss)


def build_lens_explain(
    *,
    cve_findings: list[Finding],
    direct_trust_packages: list[dict[str, Any]],
    pipeline_snapshot: PipelineSnapshot,
) -> dict[str, Any]:
    """Serializable lens inputs captured at scan time for results-page breakdowns."""
    z_counts: Counter[str] = Counter(f.severity for f in pipeline_snapshot.zizmor_findings)
    tr = pipeline_snapshot.test_reality
    return {
        "vulnerability": {
            "findings": [
                {
                    "advisory_id": f.advisory_id or f.title,
                    "package": f.dependency.name,
                    "cvss_score": f.cvss_score,
                    "normalized_score": round(_finding_normalized_score(f.cvss_score), 1),
                }
                for f in sorted(
                    cve_findings, key=lambda x: -_finding_normalized_score(x.cvss_score)
                )
            ],
        },
        "trust": {
            "packages": sorted(
                direct_trust_packages,
                key=lambda p: -int(p["subscore"]),
            ),
        },
        "pipeline": {
            "workflow_files": list(pipeline_snapshot.workflow_files),
            "zizmor_counts": dict(z_counts),
            "zizmor_weighted_sum": sum(
                _PIPELINE_SUBSCORE_WEIGHTS[f.severity] for f in pipeline_snapshot.zizmor_findings
            ),
            "test_penalty": 0 if tr.safe_to_auto_merge else _TEST_REALITY_PENALTY,
            "subscore": pipeline_snapshot.subscore,
            "test_reality": {
                "has_test_script": tr.has_test_script,
                "test_script_is_no_op": tr.test_script_is_no_op,
                "has_test_files": tr.has_test_files,
                "test_count": tr.test_count,
                "workflow_runs_tests": tr.workflow_runs_tests,
                "safe_to_auto_merge": tr.safe_to_auto_merge,
                "reasons_blocked": list(tr.reasons_blocked),
            },
        },
    }


def build_vulnerability_breakdown(cached: dict[str, Any]) -> ScoreBreakdown:
    """Derive vulnerability subscore breakdown from cached scan data."""
    project_scores = cached.get("project_scores") or {}
    final = project_scores.get("vulnerability_subscore")
    explain = (cached.get("lens_explain") or {}).get("vulnerability", {})
    finding_rows: list[dict[str, Any]] = list(explain.get("findings") or [])

    if not finding_rows:
        for entry in cached.get("entries") or []:
            finding = entry.get("finding") or {}
            cvss = finding.get("cvss_score")
            finding_rows.append(
                {
                    "advisory_id": finding.get("title", "finding"),
                    "package": (finding.get("dependency") or {}).get("name", "?"),
                    "cvss_score": cvss,
                    "normalized_score": round(_finding_normalized_score(cvss), 1),
                }
            )
        finding_rows.sort(key=lambda row: -row["normalized_score"])

    lines: list[BreakdownLine] = []
    if finding_rows:
        lines.append(("Findings with CVE data", str(len(finding_rows))))
        for row in finding_rows[:8]:
            cvss = row.get("cvss_score")
            cvss_label = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "unknown → 50"
            lines.append(
                (
                    f"{row.get('package', '?')} ({row.get('advisory_id', 'advisory')})",
                    f"CVSS {cvss_label} → {row.get('normalized_score', '?')}/100",
                )
            )
        if len(finding_rows) > 8:
            lines.append(("Additional findings", str(len(finding_rows) - 8)))
    else:
        lines.append(("Findings", "0 (subscore 0)"))

    recomputed = round(max(row["normalized_score"] for row in finding_rows)) if finding_rows else 0
    if final is not None and recomputed != final:
        lines.append(("Displayed subscore (rounded)", str(final)))

    return ScoreBreakdown(
        title="Vulnerability",
        description=(
            "OSV advisories are scored from CVSS (0–10), normalized to 0–100. "
            "The project vulnerability subscore is the highest normalized finding score."
        ),
        lines=lines,
        formula="subscore = max over findings of min(100, CVSS × 10); missing CVSS → 50",
        final_value=final if final is not None else recomputed,
    )


def build_trust_breakdown(cached: dict[str, Any]) -> ScoreBreakdown:
    """Derive trust subscore breakdown (top-10 mean of direct dependency snapshots)."""
    project_scores = cached.get("project_scores") or {}
    final = project_scores.get("trust_subscore")
    packages: list[dict[str, Any]] = list(
        (cached.get("lens_explain") or {}).get("trust", {}).get("packages") or []
    )

    if not packages:
        seen: dict[tuple[str, str], int] = {}
        for entry in cached.get("entries") or []:
            candidate = entry.get("candidate") or {}
            pkg = candidate.get("package")
            ver = candidate.get("from_version")
            sub = candidate.get("trust_subscore")
            if pkg and ver is not None and sub is not None:
                seen[(pkg, ver)] = int(sub)
        packages = [
            {"name": name, "version": ver, "subscore": sub}
            for (name, ver), sub in sorted(seen.items(), key=lambda x: -x[1])
        ]

    subscores = [int(p["subscore"]) for p in packages]
    top_n = 10
    ordered = sorted(subscores, reverse=True)
    top = ordered[:top_n] if len(ordered) >= top_n else ordered
    recomputed = round(aggregate_trust_subscores(subscores)) if subscores else 0

    lines: list[BreakdownLine] = [("Direct dependencies scored", str(len(packages)))]
    for pkg in packages[:top_n]:
        lines.append((f"{pkg['name']}@{pkg['version']}", f"{pkg['subscore']}/100"))
        score = pkg.get("scorecard_score")
        if score is not None:
            scorecard_value: str | dict[str, Any] = f"{float(score):.1f}/10"
            concerns = pkg.get("scorecard_top_concerns") or []
            if concerns:
                scorecard_value = {
                    "text": scorecard_value,
                    "chips": [str(c) for c in concerns],
                }
            lines.append(
                {
                    "label": "Scorecard",
                    "value": scorecard_value,
                    "indent": True,
                }
            )
        else:
            lines.append(
                {
                    "label": "Scorecard",
                    "value": "not available",
                    "indent": True,
                    "muted": True,
                }
            )
    if len(packages) > top_n:
        lines.append(("Other direct deps (not in top 10)", str(len(packages) - top_n)))
    if top:
        lines.append(
            (
                f"Mean of top {len(top)} snapshot subscores",
                f"{sum(top) / len(top):.2f} → {recomputed}",
            )
        )
    w = TRUST_SUBSCORE_WEIGHTS
    formula = (
        f"Per-package snapshot risk (0–100): sole maintainer +{w.sole_maintainer}, "
        f"young package +{w.young_package}, typosquat +{w.typosquat_distance_1}/"
        f"+{w.typosquat_distance_2}, low downloads +{w.low_weekly_downloads}; "
        f"project subscore = mean(top {top_n} highest)"
    )
    return ScoreBreakdown(
        title="Trust",
        description=(
            "Trust subscores come from npm registry snapshots for each direct dependency. "
            "The project score aggregates the highest-risk packages."
        ),
        lines=lines,
        formula=formula,
        final_value=final if final is not None else recomputed,
    )


def build_workflow_security_breakdown(cached: dict[str, Any]) -> ScoreBreakdown:
    """Derive workflow security (zizmor-only) breakdown."""
    pipeline_explain = (cached.get("lens_explain") or {}).get("pipeline") or {}
    workflow_files = pipeline_explain.get("workflow_files") or []

    # No workflows scanned — return a not_applicable breakdown parallel to test_reality's.
    if not workflow_files:
        return ScoreBreakdown(
            title="Workflow Security",
            description=(
                "No GitHub Actions workflows were found to analyze. "
                "Workflow security analysis requires at least one .github/workflows/*.yml file. "
                "Mode B users can upload a workflows zip; Mode A users see workflows from the cloned repo."
            ),
            lines=[
                ("Workflows present", "No — not applicable"),
                ("zizmor analysis", "—"),
                ("Severity counts", "—"),
                ("Weighted sum", "—"),
            ],
            formula="not_applicable when no workflows are present to analyze",
            final_value="not_applicable",
        )

    z_counts: dict[str, int] = pipeline_explain.get("zizmor_counts") or {}
    weighted = int(pipeline_explain.get("zizmor_weighted_sum", 0))
    workflow_only = min(_SUBSCORE_CAP, weighted)

    lines: list[BreakdownLine] = []
    lines.append(("Workflow files scanned", str(len(workflow_files))))
    for severity in _ZIZMOR_SEVERITIES:
        count = z_counts.get(severity, 0)
        weight = _PIPELINE_SUBSCORE_WEIGHTS[severity]
        if count:
            lines.append((f"zizmor {severity} ({weight} pts each)", f"{count} → {count * weight}"))
    lines.append(("zizmor weighted sum", str(weighted)))
    if weighted > _SUBSCORE_CAP:
        lines.append((f"Capped at {_SUBSCORE_CAP}", str(workflow_only)))

    parts = [
        f"{severity}×{_PIPELINE_SUBSCORE_WEIGHTS[severity]}"
        for severity in _ZIZMOR_SEVERITIES
        if z_counts.get(severity)
    ]
    z_part = " + ".join(parts) if parts else "0"
    formula = f"min({_SUBSCORE_CAP}, ({z_part}))"
    return ScoreBreakdown(
        title="Workflow Security",
        description=(
            "zizmor static analysis on GitHub Actions workflows. "
            "Higher subscore means more workflow security risk."
        ),
        lines=lines,
        formula=formula,
        final_value=workflow_only,
    )


def _pass_fail(ok: bool) -> str:
    return "Pass" if ok else "Fail"


def build_test_reality_breakdown(cached: dict[str, Any]) -> ScoreBreakdown:
    """Four-condition test-reality checklist."""
    project_scores = cached.get("project_scores") or {}
    state = project_scores.get("test_reality", "not_applicable")
    pipeline = (cached.get("lens_explain") or {}).get("pipeline", {})
    tr: dict[str, Any] = pipeline.get("test_reality") or {}

    if not pipeline.get("workflow_files"):
        return ScoreBreakdown(
            title="Test Verification",
            description="No GitHub Actions workflows were found to verify post-upgrade behavior.",
            lines=[
                ("Workflows present", "No — not applicable"),
                ("Test script in package.json", "—"),
                ("Test script not a no-op", "—"),
                ("Test files in repo", "—"),
                ("Workflow invokes tests", "—"),
            ],
            formula=None,
            final_value=state,
        )

    has_script = bool(tr.get("has_test_script"))
    not_noop = has_script and not bool(tr.get("test_script_is_no_op"))
    has_files = bool(tr.get("has_test_files"))
    wf_tests = bool(tr.get("workflow_runs_tests"))
    lines: list[BreakdownLine] = [
        ("Test script in package.json", _pass_fail(has_script)),
        ("Test script not a no-op", _pass_fail(not_noop)),
        (f"Test files in repo ({tr.get('test_count', 0)} found)", _pass_fail(has_files)),
        ("Workflow invokes tests", _pass_fail(wf_tests)),
    ]
    if tr.get("reasons_blocked"):
        lines.append(("Blocked reasons", "; ".join(tr["reasons_blocked"])))

    return ScoreBreakdown(
        title="Test Verification",
        description=(
            "Binary check that your CI can catch regressions after an upgrade. "
            "When all four conditions fail, the agent vetoes auto-merge for affected fixes "
            f"and adds a {_TEST_REALITY_PENALTY}-point penalty to the pipeline subscore "
            "used in PRS calculation."
        ),
        lines=lines,
        formula="verified when all four conditions pass; otherwise vetoed for auto-merge",
        final_value=state,
    )


def build_score_breakdowns(cached: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """All lens breakdowns as plain dicts for template JSON."""
    ps = cached.get("project_scores") or {}
    w = DEFAULT_WEIGHTS
    vuln, trust, pipe, prs = (
        ps.get("vulnerability_subscore"),
        ps.get("trust_subscore"),
        ps.get("pipeline_subscore"),
        ps.get("prs"),
    )
    prs_lines: list[BreakdownLine] = []
    if vuln is not None:
        prs_lines.append((f"Vulnerability × {w['cve']:.0%}", f"{vuln} → {vuln * w['cve']:.1f}"))
    if trust is not None:
        prs_lines.append((f"Trust × {w['trust']:.0%}", f"{trust} → {trust * w['trust']:.1f}"))
    if pipe is not None:
        prs_lines.append(
            (f"Pipeline × {w['pipeline']:.0%}", f"{pipe} → {pipe * w['pipeline']:.1f}")
        )
    prs_breakdown = ScoreBreakdown(
        title="Project Risk Score",
        description=(
            "Weighted blend of the three numeric lens subscores. Note: the Pipeline input "
            "to PRS is the engine's combined pipeline subscore (zizmor analysis plus "
            "test-reality penalty), distinct from the standalone Workflow Security tile "
            "which shows zizmor-only."
        ),
        lines=prs_lines,
        formula=(
            f"PRS = round({w['cve']:.0%}×CVE + {w['trust']:.0%}×Trust + {w['pipeline']:.0%}×Pipeline)"
        ),
        final_value=prs if prs is not None else "—",
    )
    return {
        "vulnerability": asdict(build_vulnerability_breakdown(cached)),
        "trust": asdict(build_trust_breakdown(cached)),
        "workflow_security": asdict(build_workflow_security_breakdown(cached)),
        "test_reality": asdict(build_test_reality_breakdown(cached)),
        "prs": asdict(prs_breakdown),
    }


def _current_version(entries: list[dict[str, Any]]) -> str | None:
    for entry in entries:
        finding = entry.get("finding") or {}
        dependency = finding.get("dependency") or {}
        version = dependency.get("version")
        if version:
            return str(version)
        candidate = entry.get("candidate") or {}
        from_version = candidate.get("from_version")
        if from_version:
            return str(from_version)
    return None


@dataclass(frozen=True)
class ResultsPackageView:
    """One grouped package row for the results page."""

    name: str
    current_version: str | None
    entries: list[dict[str, Any]]
    total_count: int
    severity_range: str
    trust_subscore: int | None
    max_epss: float | None
    worst_tier: str
    has_kev: bool
    has_ownership_transferred: bool
    worst_trust_veto: str | None
    transitive_path: str
    summary_tier: str


def _tier_label(tier: str) -> str:
    mapping = {
        "auto_merge": "AUTO-MERGE",
        "review_required": "REVIEW",
        "decline": "DECLINE",
        "mixed": "MIXED",
    }
    return mapping.get(tier, tier.upper().replace("_", "-"))


def _collect_veto_signals(entry: dict[str, Any]) -> list[str]:
    verdict = entry.get("verdict") or {}
    signals = verdict.get("veto_signals") or ()
    return list(signals)


def _worst_trust_veto(entries: list[dict[str, Any]]) -> str | None:
    signals: list[str] = []
    for entry in entries:
        signals.extend(_collect_veto_signals(entry))
    trust_signals = [s for s in signals if isinstance(s, str) and s.startswith("trust.")]
    for preferred in _TRUST_VETO_PRIORITY:
        if preferred in trust_signals:
            return preferred
    return trust_signals[0] if trust_signals else None


def _transitive_path(entries: list[dict[str, Any]]) -> str:
    for entry in entries:
        finding = entry.get("finding") or {}
        dependency = finding.get("dependency") or {}
        path = dependency.get("path") or []
        if path:
            return " → ".join(str(step) for step in path)
    return ""


def _sort_entries_by_epss(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(entry: dict[str, Any]) -> tuple[bool, float]:
        candidate = entry.get("candidate") or {}
        epss = candidate.get("max_epss_score")
        return (epss is None, -(epss or 0.0))

    return sorted(entries, key=sort_key)


def build_packages(cached: dict[str, Any]) -> list[ResultsPackageView]:
    """Group cached scan entries into package rows with display metadata."""
    by_pkg: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in cached.get("entries") or []:
        candidate = entry.get("candidate") or {}
        package = candidate.get("package") or "unknown"
        by_pkg[package].append(entry)

    packages: list[ResultsPackageView] = []
    for name, entries in by_pkg.items():
        sorted_entries = _sort_entries_by_epss(entries)
        tiers: set[str] = set()
        for entry in entries:
            tier = (entry.get("verdict") or {}).get("tier")
            if isinstance(tier, str):
                tiers.add(tier)
        summary_tier: str = next(iter(tiers)) if len(tiers) == 1 else "mixed"
        severities = sorted(
            s
            for s in {(e.get("finding") or {}).get("severity") for e in entries}
            if isinstance(s, str)
        )
        severity_range = (
            severities[0] if len(severities) == 1 else f"{severities[0]}–{severities[-1]}"
        )
        trust_sub = (entries[0].get("candidate") or {}).get("trust_subscore")
        epss_scores: list[float] = []
        for entry in entries:
            score = (entry.get("candidate") or {}).get("max_epss_score")
            if isinstance(score, (int, float)):
                epss_scores.append(float(score))
        max_epss = max(epss_scores) if epss_scores else None
        has_kev = any((e.get("finding") or {}).get("is_kev") for e in entries)
        all_vetoes = [v for e in entries for v in _collect_veto_signals(e)]
        has_ownership = _OWNERSHIP_VETO in all_vetoes
        packages.append(
            ResultsPackageView(
                name=name,
                current_version=_current_version(entries),
                entries=sorted_entries,
                total_count=len(entries),
                severity_range=severity_range or "—",
                trust_subscore=trust_sub,
                max_epss=max_epss,
                worst_tier=_tier_label(summary_tier),
                has_kev=has_kev,
                has_ownership_transferred=has_ownership,
                worst_trust_veto=_worst_trust_veto(entries),
                transitive_path=_transitive_path(entries),
                summary_tier=summary_tier,
            )
        )

    def sort_key(pkg: ResultsPackageView) -> tuple[bool, bool, float, str]:
        return (
            not pkg.has_kev,
            pkg.max_epss is None,
            -(pkg.max_epss or 0.0),
            pkg.name.lower(),
        )

    return sorted(packages, key=sort_key)


def _prs_tier(prs: int | None) -> str:
    if prs is None:
        return "caution"
    if prs >= 70:
        return "danger"
    if prs >= 30:
        return "caution"
    return "safe"


_TIER_DISPLAY_LABELS: dict[str, str] = {
    "auto_merge": "AUTO_MERGE",
    "review_required": "REVIEW_REQUIRED",
    "decline": "DECLINE",
}

_CANDIDATE_TIER_ORDER: tuple[str, ...] = (
    "auto_merge",
    "review_required",
    "decline",
)

_ADVISORY_PREFIX_RE = re.compile(
    r"^(GHSA-[a-z0-9]+(?:-[a-z0-9]+)+|CVE-\d{4}-\d{4,})\s*:\s*",
    re.IGNORECASE,
)

_SCAN_MODE_DISPLAY: dict[str, str] = {
    "A": "Scan",
    "B": "Upload",
}


@dataclass(frozen=True)
class ResultsFindingView:
    """One CVE/advisory resolved by a fix candidate."""

    advisory_id: str
    cvss_score: float | None
    severity: str | None
    title: str
    source_url: str | None
    description_html: str | None = None
    affected_range: str | None = None
    fixed_range: str | None = None
    published_at: str | None = None


@dataclass(frozen=True)
class ResultsCandidateView:
    """One selectable fix candidate for the Scan results action picker."""

    candidate_id: str
    package: str
    from_version: str
    to_version: str
    tier: str
    tier_label: str
    score: int | float
    veto_signals: tuple[str, ...]
    reasons: tuple[str, ...]
    checked_by_default: bool
    findings: tuple[ResultsFindingView, ...]


def _strip_advisory_title_prefix(raw_title: str, advisory_id: str) -> str:
    title = _ADVISORY_PREFIX_RE.sub("", raw_title).strip()
    return title or advisory_id


_MD = MarkdownIt("commonmark", {"html": False}).enable("linkify")

_DESCRIPTION_ALLOWED_TAGS = frozenset(
    {
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "p",
        "br",
        "hr",
        "ul",
        "ol",
        "li",
        "strong",
        "em",
        "code",
        "pre",
        "a",
        "blockquote",
    }
)
_DESCRIPTION_ALLOWED_ATTRS = {
    "a": ["href", "title", "rel", "target"],
    "code": ["class"],
}


def _add_link_safety_attrs(html: str) -> str:
    """Ensure external links open safely in a new tab."""

    def _inject(match: re.Match[str]) -> str:
        tag = match.group(0)
        if "rel=" in tag.lower():
            return tag
        return tag[:-1] + ' rel="noopener noreferrer" target="_blank">'

    return re.sub(r"<a\s[^>]*>", _inject, html, flags=re.IGNORECASE)


def render_description_html(raw: str | None) -> str | None:
    """Render OSV markdown to sanitized HTML for /select finding descriptions."""
    if not raw:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    html = _MD.render(stripped)
    cleaned = bleach.clean(
        html,
        tags=_DESCRIPTION_ALLOWED_TAGS,
        attributes=_DESCRIPTION_ALLOWED_ATTRS,
        protocols=["http", "https", "mailto"],
        strip=True,
    )
    return _add_link_safety_attrs(cleaned)


def _finding_description(finding: dict[str, Any]) -> str | None:
    raw = finding.get("description")
    if not isinstance(raw, str):
        return None
    stripped = raw.strip()
    return stripped or None


def _finding_published_at(finding: dict[str, Any]) -> str | None:
    raw = finding.get("published_at")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()[:10]
    return None


def _finding_fixed_range(finding: dict[str, Any]) -> str | None:
    fixed = finding.get("fixed_versions")
    if not isinstance(fixed, (list, tuple)) or not fixed:
        return None
    versions = sorted(str(v) for v in fixed if v)
    if not versions:
        return None
    primary = versions[0]
    if len(versions) == 1:
        return f"≥ {primary}"
    return f"≥ {primary} (+{len(versions) - 1} more)"


def _finding_affected_range(finding: dict[str, Any]) -> str | None:
    fixed = finding.get("fixed_versions")
    if isinstance(fixed, (list, tuple)) and fixed:
        versions = sorted(str(v) for v in fixed if v)
        if versions:
            return f"< {versions[0]}"
    dep = finding.get("dependency")
    if isinstance(dep, dict):
        version = dep.get("version")
        if isinstance(version, str) and version.strip():
            return version.strip()
    return None


def _finding_source_url(finding: dict[str, Any], advisory_id: str) -> str | None:
    url = finding.get("source_url")
    if isinstance(url, str) and url:
        return url
    if advisory_id:
        return f"https://osv.dev/vulnerability/{advisory_id}"
    return None


def _finding_view_from_dict(finding: dict[str, Any]) -> ResultsFindingView | None:
    if not isinstance(finding, dict):
        return None
    advisory_id = finding.get("advisory_id") or finding.get("title") or "advisory"
    advisory_id = str(advisory_id)
    raw_title = str(finding.get("title") or advisory_id)
    cvss = finding.get("cvss_score")
    cvss_score = float(cvss) if isinstance(cvss, (int, float)) else None
    severity = finding.get("severity")
    return ResultsFindingView(
        advisory_id=advisory_id,
        cvss_score=cvss_score,
        severity=str(severity) if isinstance(severity, str) else None,
        title=_strip_advisory_title_prefix(raw_title, advisory_id),
        source_url=_finding_source_url(finding, advisory_id),
        description_html=render_description_html(_finding_description(finding)),
        affected_range=_finding_affected_range(finding),
        fixed_range=_finding_fixed_range(finding),
        published_at=_finding_published_at(finding),
    )


def _related_finding_dicts(entry: dict[str, Any]) -> list[dict[str, Any]]:
    related = entry.get("related_findings")
    if isinstance(related, list) and related:
        return [item for item in related if isinstance(item, dict)]
    finding = entry.get("finding")
    if isinstance(finding, dict):
        return [finding]
    return []


def _findings_for_entry(entry: dict[str, Any]) -> tuple[ResultsFindingView, ...]:
    views: list[ResultsFindingView] = []
    for finding_dict in _related_finding_dicts(entry):
        view = _finding_view_from_dict(finding_dict)
        if view is not None:
            views.append(view)
    views.sort(key=lambda f: (-(f.cvss_score or 0.0), f.advisory_id))
    return tuple(views)


def _entry_candidate_id(entry: dict[str, Any]) -> str:
    candidate = entry.get("candidate") or {}
    verdict = entry.get("verdict") or {}
    cid = candidate.get("candidate_id") or verdict.get("candidate_id")
    if cid:
        return str(cid)
    package = candidate.get("package", "unknown")
    from_version = candidate.get("from_version", "?")
    to_version = candidate.get("to_version", "?")
    return f"{package}:{from_version}:{to_version}"


def _candidate_view_from_entry(entry: dict[str, Any]) -> ResultsCandidateView | None:
    verdict = entry.get("verdict") or {}
    tier = verdict.get("tier")
    if not isinstance(tier, str) or tier not in _TIER_DISPLAY_LABELS:
        return None
    candidate = entry.get("candidate") or {}
    signals = verdict.get("veto_signals") or ()
    reasons = verdict.get("reasons") or ()
    if not isinstance(signals, (list, tuple)):
        signals = ()
    if not isinstance(reasons, (list, tuple)):
        reasons = ()
    score = verdict.get("score", 0)
    return ResultsCandidateView(
        candidate_id=_entry_candidate_id(entry),
        package=str(candidate.get("package", "unknown")),
        from_version=str(candidate.get("from_version", "?")),
        to_version=str(candidate.get("to_version", "?")),
        tier=tier,
        tier_label=_TIER_DISPLAY_LABELS[tier],
        score=score if isinstance(score, (int, float)) else 0,
        veto_signals=tuple(str(s) for s in signals),
        reasons=tuple(str(r) for r in reasons),
        checked_by_default=tier == "auto_merge",
        findings=_findings_for_entry(entry),
    )


def build_candidates_by_tier(cached: dict[str, Any]) -> dict[str, Any]:
    """Group scan entries into verdict-tier buckets for the selection UI."""
    buckets: dict[str, list[ResultsCandidateView]] = {tier: [] for tier in _CANDIDATE_TIER_ORDER}
    for entry in cached.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        view = _candidate_view_from_entry(entry)
        if view is None:
            continue
        buckets[view.tier].append(view)

    for tier in _CANDIDATE_TIER_ORDER:
        buckets[tier].sort(
            key=lambda candidate: (
                candidate.package.lower(),
                candidate.from_version,
                candidate.to_version,
            )
        )

    total_count = sum(len(buckets[tier]) for tier in _CANDIDATE_TIER_ORDER)
    return {
        "auto_merge": buckets["auto_merge"],
        "review_required": buckets["review_required"],
        "decline": buckets["decline"],
        "total_count": total_count,
        "tier_order": _CANDIDATE_TIER_ORDER,
        "tier_labels": _TIER_DISPLAY_LABELS,
    }


def _format_completed_ago(iso_ts: str | None) -> str:
    if not iso_ts:
        return "just now"
    try:
        completed = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        if completed.tzinfo is None:
            completed = completed.replace(tzinfo=UTC)
        delta = datetime.now(UTC) - completed
        minutes = int(delta.total_seconds() // 60)
        if minutes < 1:
            return "just now"
        if minutes < 60:
            return f"{minutes} min ago"
        hours = minutes // 60
        return f"{hours} hr ago" if hours == 1 else f"{hours} hrs ago"
    except ValueError:
        return "recently"


@dataclass(frozen=True)
class ResultsNoFixSkipView:
    """Vulnerable finding with no automated fix, for the critical results section."""

    advisory_id: str
    package: str
    current_version: str
    title: str
    description: str
    cvss_score: float | None
    severity: str | None
    source_url: str | None
    dependency_path: str
    epss_score: float | None
    epss_percentile: float | None
    is_kev: bool
    kev_known_ransomware: bool
    kev_due_date: str | None
    reason: str
    reason_label: str


def _coerce_skip_dict(item: Any) -> dict[str, Any] | None:
    if isinstance(item, dict):
        return item
    if hasattr(item, "model_dump"):
        return cast(dict[str, Any], item.model_dump())
    return None


def _dependency_path_display(path: Any) -> str:
    if isinstance(path, str):
        return path
    if isinstance(path, list):
        parts = [str(p) for p in path if p is not None and str(p)]
        return " → ".join(parts)
    return ""


def _no_fix_sort_key(view: ResultsNoFixSkipView) -> tuple[int, float, float, str]:
    return (
        0 if view.is_kev else 1,
        -(view.epss_score or 0.0),
        -(view.cvss_score or 0.0),
        view.advisory_id,
    )


def _no_fix_view_from_dict(data: dict[str, Any]) -> ResultsNoFixSkipView | None:
    if data.get("kind") != "no_fix":
        return None
    advisory_id = str(data.get("advisory_id") or "")
    reason = str(data.get("reason") or "no_fix_version_in_osv")
    cvss = data.get("cvss_score")
    cvss_score = float(cvss) if isinstance(cvss, (int, float)) else None
    epss = data.get("epss_score")
    epss_score = float(epss) if isinstance(epss, (int, float)) else None
    epss_pct = data.get("epss_percentile")
    epss_percentile = float(epss_pct) if isinstance(epss_pct, (int, float)) else None
    severity = data.get("severity")
    source = data.get("source_url")
    return ResultsNoFixSkipView(
        advisory_id=advisory_id,
        package=str(data.get("package") or ""),
        current_version=str(data.get("current_version") or ""),
        title=str(data.get("title") or advisory_id),
        description=str(data.get("description") or ""),
        cvss_score=cvss_score,
        severity=str(severity) if isinstance(severity, str) else None,
        source_url=str(source) if isinstance(source, str) and source else None,
        dependency_path=_dependency_path_display(data.get("dependency_path")),
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        is_kev=bool(data.get("is_kev")),
        kev_known_ransomware=bool(data.get("kev_known_ransomware")),
        kev_due_date=str(data["kev_due_date"]) if data.get("kev_due_date") else None,
        reason=reason,
        reason_label=str(data.get("reason_label") or no_fix_reason_label(reason)),
    )


@dataclass(frozen=True)
class PackageStatusEntry:
    package: str
    version: str
    is_direct: bool


@dataclass(frozen=True)
class PackageStatusSummary:
    total: int
    clean: tuple[PackageStatusEntry, ...]
    no_fix_count: int
    auto_merge_count: int
    review_required_count: int
    decline_count: int
    accounted_total: int
    integrity_ok: bool


def _packages_with_findings(cached: dict[str, Any]) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for entry in cached.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        candidate = entry.get("candidate") or {}
        package = str(candidate.get("package") or "").strip()
        version = str(candidate.get("from_version") or "").strip()
        if package and version:
            found.add((package, version))
    for item in cached.get("skipped_findings") or []:
        data = _coerce_skip_dict(item)
        if not data or data.get("kind") != "no_fix":
            continue
        package = str(data.get("package") or "").strip()
        version = str(data.get("current_version") or "").strip()
        if package and version:
            found.add((package, version))
    return found


def _no_fix_package_count(cached: dict[str, Any]) -> int:
    packages: set[tuple[str, str]] = set()
    for item in cached.get("skipped_findings") or []:
        data = _coerce_skip_dict(item)
        if not data or data.get("kind") != "no_fix":
            continue
        package = str(data.get("package") or "").strip()
        version = str(data.get("current_version") or "").strip()
        if package and version:
            packages.add((package, version))
    return len(packages)


def build_package_status_summary(cached: dict[str, Any]) -> PackageStatusSummary:
    """Per-lockfile package buckets for the results page status section."""
    scan_meta = cached.get("scan_meta") or {}
    dep_counts = scan_meta.get("dep_counts") or {}
    total = int(dep_counts.get("direct") or 0) + int(dep_counts.get("transitive") or 0)

    deps = cached.get("deps") or []
    with_findings = _packages_with_findings(cached)
    summary = cached.get("summary") or {}

    clean_entries: list[PackageStatusEntry] = []
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        package = str(dep.get("package") or "").strip()
        version = str(dep.get("version") or "").strip()
        if not package or not version:
            continue
        if (package, version) in with_findings:
            continue
        clean_entries.append(
            PackageStatusEntry(
                package=package,
                version=version,
                is_direct=bool(dep.get("is_direct")),
            )
        )
    clean_entries.sort(
        key=lambda entry: (not entry.is_direct, entry.package.lower(), entry.version)
    )

    no_fix_count = _no_fix_package_count(cached)
    auto_merge_count = int(summary.get("auto_merge_count") or 0)
    review_required_count = int(summary.get("review_required_count") or 0)
    decline_count = int(summary.get("decline_count") or 0)

    accounted_total = (
        len(clean_entries) + no_fix_count + auto_merge_count + review_required_count + decline_count
    )
    integrity_ok = accounted_total == total

    return PackageStatusSummary(
        total=total,
        clean=tuple(clean_entries),
        no_fix_count=no_fix_count,
        auto_merge_count=auto_merge_count,
        review_required_count=review_required_count,
        decline_count=decline_count,
        accounted_total=accounted_total,
        integrity_ok=integrity_ok,
    )


def build_no_fix_skips(cached: dict[str, Any]) -> tuple[ResultsNoFixSkipView, ...]:
    views: list[ResultsNoFixSkipView] = []
    for item in cached.get("skipped_findings") or []:
        data = _coerce_skip_dict(item)
        if not data:
            continue
        view = _no_fix_view_from_dict(data)
        if view is not None:
            views.append(view)
    return tuple(sorted(views, key=_no_fix_sort_key))


def build_lens_failure_skips(cached: dict[str, Any]) -> tuple[LensFailureSkip, ...]:
    out: list[LensFailureSkip] = []
    for item in cached.get("skipped_findings") or []:
        data = _coerce_skip_dict(item)
        if not data or data.get("kind") != "lens_failure":
            continue
        out.append(LensFailureSkip.model_validate(data))
    return tuple(out)


def build_results_context(cached: dict[str, Any], scan_hash: str) -> dict[str, Any]:
    """Template context for results.html from a cached scan payload."""
    cached = apply_mode_aware_verdict_reasons(cached)
    packages = build_packages(cached)
    project_scores = cached.get("project_scores") or {}
    summary = cached.get("summary") or {}
    scan_meta = cached.get("scan_meta") or {}
    prs = project_scores.get("prs")

    pipeline_explain = (cached.get("lens_explain") or {}).get("pipeline") or {}
    workflow_files = pipeline_explain.get("workflow_files") or []
    zizmor_weighted = int(pipeline_explain.get("zizmor_weighted_sum") or 0)

    # When no workflows were discovered, surface "not_applicable" instead of a misleading 0.
    # Parallel to how Test Verification reports not_applicable when there's nothing to verify.
    if pipeline_explain and not workflow_files:
        workflow_security_subscore: int | str | None = "not_applicable"
    elif pipeline_explain:
        workflow_security_subscore = min(_SUBSCORE_CAP, zizmor_weighted)
    else:
        workflow_security_subscore = None

    scan_mode = str(scan_meta.get("mode") or "")
    candidates_by_tier = build_candidates_by_tier(cached)
    no_fix_skips = build_no_fix_skips(cached)
    lens_failure_skips = build_lens_failure_skips(cached)
    mode_display = _SCAN_MODE_DISPLAY.get(scan_mode, scan_mode or "—")

    scan: dict[str, Any] = {
        **cached,
        "packages": packages,
        "scan_input_hash": scan_hash,
        "dep_counts": scan_meta.get("dep_counts") or {"direct": 0, "transitive": 0},
        "prs_tier": _prs_tier(prs if isinstance(prs, int) else None),
        "completed_ago": _format_completed_ago(scan_meta.get("completed_at")),
        "repo_display": scan_meta.get("repo_display", "Unknown repository"),
        "ref_display": scan_meta.get("ref", "HEAD"),
        "mode_display": mode_display,
        "workflow_security_subscore": workflow_security_subscore,
    }

    package_status = build_package_status_summary(cached)

    return {
        "scan": scan,
        "packages": packages,
        "scan_input_hash": scan_hash,
        "project_scores": project_scores,
        "summary": summary,
        "executive_summary": cached.get("executive_summary"),
        "skipped_findings": cached.get("skipped_findings") or [],
        "no_fix_skips": no_fix_skips,
        "lens_failure_skips": lens_failure_skips,
        "actions": cached.get("actions"),
        "breakdowns": build_score_breakdowns(cached),
        "chat_suggested_questions": CHAT_SUGGESTED_QUESTIONS,
        "chat_endpoint_url": f"/dashboard/chat?scan_input_hash={scan_hash}",
        "candidates_by_tier": candidates_by_tier,
        "show_candidate_selection": False,
        "show_plan_cta": scan_mode == "A" and candidates_by_tier["total_count"] > 0,
        "show_upload_action_note": scan_mode == "B",
        "package_status": package_status,
    }
