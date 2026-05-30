"""Tests for GitHub PR title/body generation."""

from __future__ import annotations

from datetime import UTC, datetime

from arguss.core.models import Dependency, Finding, FixCandidate, FixConfidence, FixKind, FixTier
from arguss.engine import explanation as explanation_mod
from arguss.engine.fix_confidence import ENGINE_VERSION
from arguss.web import github_action as ga

_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


def _finding(
    *,
    advisory_id: str,
    title: str,
    cvss_score: float | None = None,
    fixed_versions: tuple[str, ...] = ("3.36.0",),
    package: str = "simple-git",
    version: str = "3.28.0",
    path: list[str] | None = None,
) -> Finding:
    dep_path = path if path is not None else ["root", package]
    return Finding(
        dependency=Dependency(
            name=package,
            version=version,
            direct=True,
            path=dep_path,
        ),
        lens="cve",
        severity="critical" if cvss_score and cvss_score >= 9 else "high",
        score=90.0,
        cvss_score=cvss_score,
        title=title,
        description="test",
        advisory_id=advisory_id,
        fixed_versions=fixed_versions,
        source_url=f"https://osv.dev/vulnerability/{advisory_id}",
    )


def _candidate(
    *,
    package: str = "simple-git",
    from_version: str = "3.28.0",
    to_version: str = "3.36.0",
    source_finding_ids: tuple[str, ...] = ("GHSA-test",),
) -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version=from_version,
        to_version=to_version,
        fix_kind=FixKind.MINOR,
        source_finding_ids=source_finding_ids,
        repo_id="/tmp/repo",
    )


def _verdict(candidate: FixCandidate) -> FixConfidence:
    return FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=FixTier.AUTO_MERGE,
        score=95,
        reasons=("minor-level upgrade; trust signals unchanged; CI verifies tests",),
        veto_signals=(),
        evaluated_at=_FIXED_TIME,
        engine_version=ENGINE_VERSION,
    )


def test_pr_description_single_finding_uses_advisory_line_format() -> None:
    finding = _finding(advisory_id="GHSA-test", title="DoS in test package")
    candidate = _candidate()
    body = ga._render_pr_body(candidate, _verdict(candidate), finding)
    assert "**[GHSA-test](https://osv.dev/vulnerability/GHSA-test)**" in body
    assert "[GitHub advisory](https://github.com/advisories/GHSA-test)" in body
    assert "Fixes 2 vulnerabilities" not in body


def test_pr_description_multi_finding_lists_all_cves() -> None:
    findings = (
        _finding(
            advisory_id="GHSA-hffm-xvc3-vprc",
            title="simple-git is vulnerable to Remote Code Execution",
            cvss_score=9.8,
            fixed_versions=("3.36.0",),
        ),
        _finding(
            advisory_id="GHSA-jcxm-m3jx-f287",
            title="simple-git Affected by Command Execution via Option-Parsing Bypass",
            cvss_score=8.1,
            fixed_versions=("3.32.0",),
        ),
        _finding(
            advisory_id="GHSA-r275-fr43-pm7q",
            title="blockUnsafeOperationsPlugin bypass via case-insensitive protocol.allow",
            cvss_score=9.8,
            fixed_versions=("3.32.3",),
        ),
    )
    candidate = _candidate(
        source_finding_ids=tuple(f.advisory_id or "" for f in findings),
    )
    body = ga._render_pr_body(
        candidate,
        _verdict(candidate),
        findings[0],
        related_findings=findings,
    )
    assert "Fixes 3 vulnerabilities in simple-git:" in body
    assert "GHSA-hffm-xvc3-vprc" in body
    assert "GHSA-jcxm-m3jx-f287" in body
    assert "GHSA-r275-fr43-pm7q" in body
    assert "consolidates fixes for 3 advisories" in body


def test_pr_description_multi_finding_sorted_by_severity() -> None:
    low = _finding(
        advisory_id="GHSA-low",
        title="low severity",
        cvss_score=4.0,
        fixed_versions=("3.30.0",),
    )
    high = _finding(
        advisory_id="GHSA-high",
        title="high severity",
        cvss_score=9.8,
        fixed_versions=("3.36.0",),
    )
    findings = (low, high)
    candidate = _candidate(source_finding_ids=("GHSA-low", "GHSA-high"))
    body = ga._render_pr_body(
        candidate,
        _verdict(candidate),
        low,
        related_findings=findings,
    )
    high_pos = body.index("GHSA-high")
    low_pos = body.index("GHSA-low")
    assert high_pos < low_pos


def test_title_no_siblings_uses_simple_format() -> None:
    candidate = _candidate(source_finding_ids=("GHSA-abc",))
    finding = _finding(advisory_id="GHSA-abc", title="test")
    title = ga._pr_title(candidate, finding, siblings=[])
    assert title == "Arguss: patch simple-git (3.28.0 → 3.36.0, fixes GHSA-abc)"
    assert " line" not in title


def test_title_with_siblings_includes_version_line_indicator() -> None:
    candidate = _candidate(
        package="minimatch",
        from_version="9.0.5",
        to_version="9.0.7",
        source_finding_ids=("GHSA-a", "GHSA-b", "GHSA-c"),
    )
    sibling = _candidate(
        package="minimatch",
        from_version="3.0.0",
        to_version="3.1.0",
        source_finding_ids=("GHSA-x",),
    )
    finding = _finding(
        package="minimatch",
        version="9.0.5",
        advisory_id="GHSA-a",
        title="a",
    )
    title = ga._pr_title(candidate, finding, siblings=[sibling])
    assert "v9 line" in title
    assert "resolves 3 CVEs" in title


def test_title_single_cve_says_fixes() -> None:
    candidate = _candidate(source_finding_ids=("GHSA-one",))
    finding = _finding(advisory_id="GHSA-one", title="one")
    title = ga._pr_title(candidate, finding)
    assert "fixes GHSA-one" in title


def test_title_multi_cve_says_resolves() -> None:
    findings = (
        _finding(advisory_id="GHSA-a", title="a", cvss_score=9.0),
        _finding(advisory_id="GHSA-b", title="b", cvss_score=8.0),
    )
    candidate = _candidate(source_finding_ids=("GHSA-a", "GHSA-b"))
    title = ga._pr_title(candidate, findings[0], related_findings=findings)
    assert title == "Arguss: patch simple-git (3.28.0 → 3.36.0, resolves 2 CVEs)"


def test_advisory_line_single_link() -> None:
    finding = _finding(
        advisory_id="GHSA-q8mj-m7cp-5q26",
        title="qs has a remotely triggerable DoS",
        cvss_score=5.3,
        package="qs",
        version="6.11.0",
    )
    line = ga._render_advisory_line(finding)
    assert "**[GHSA-q8mj-m7cp-5q26]" in line
    assert "qs has a remotely triggerable DoS" in line
    assert ": GHSA-q8mj-m7cp-5q26" not in line
    assert "https://osv.dev/vulnerability/GHSA-q8mj-m7cp-5q26" in line
    assert "https://github.com/advisories/GHSA-q8mj-m7cp-5q26" in line
    assert "(CVSS 5.3)" in line


def test_advisory_lines_sorted_by_cvss_descending() -> None:
    low = _finding(advisory_id="GHSA-low", title="low", cvss_score=4.0)
    high = _finding(advisory_id="GHSA-high", title="high", cvss_score=9.8)
    section = ga._render_fixes_section(_candidate(), (low, high))
    assert section.index("GHSA-high") < section.index("GHSA-low")


def test_dependency_path_single_renders_inline() -> None:
    finding = _finding(
        advisory_id="GHSA-test",
        title="t",
        path=["root", "eslint", "minimatch"],
    )
    rendered = ga._render_dependency_paths([finding])
    assert rendered == "**Dependency path:** `root → eslint → minimatch`"


def test_dependency_path_multiple_dedupes() -> None:
    f1 = _finding(
        advisory_id="GHSA-a",
        title="a",
        path=["root", "a", "pkg"],
    )
    f2 = _finding(
        advisory_id="GHSA-b",
        title="b",
        path=["root", "b", "pkg"],
    )
    rendered = ga._render_dependency_paths([f1, f2])
    assert "**Dependency paths:**" in rendered
    assert "root → a → pkg" in rendered
    assert "root → b → pkg" in rendered
    assert "via GHSA-a" in rendered
    assert "via GHSA-b" in rendered


def test_dependency_path_caps_at_five_with_summary() -> None:
    findings = [
        _finding(
            advisory_id=f"GHSA-{i}",
            title=f"t{i}",
            path=["root", f"path{i}", "pkg"],
        )
        for i in range(7)
    ]
    rendered = ga._render_dependency_paths(findings)
    assert "_… and 2 more transitive paths_" in rendered


def test_sibling_note_empty_when_no_siblings() -> None:
    assert ga._render_sibling_note(_candidate(), []) == ""


def test_sibling_note_lists_each_version() -> None:
    candidate = _candidate(package="minimatch", from_version="9.0.5", to_version="9.0.7")
    siblings = [
        _candidate(package="minimatch", from_version="3.0.0", to_version="3.1.0"),
        _candidate(package="minimatch", from_version="10.0.0", to_version="10.0.1"),
    ]
    note = ga._render_sibling_note(candidate, siblings)
    assert "**Sibling versions:**" in note
    assert "v3.0.0 → v3.1.0" in note
    assert "v10.0.0 → v10.0.1" in note
    assert "separate PR" in note


def test_claude_prompt_includes_all_finding_ids() -> None:
    findings = (
        _finding(advisory_id="GHSA-a", title="a", cvss_score=9.0),
        _finding(advisory_id="GHSA-b", title="b", cvss_score=8.0),
    )
    candidate = _candidate(source_finding_ids=("GHSA-a", "GHSA-b"))
    prompt = explanation_mod._build_user_prompt(candidate, _verdict(candidate), findings)
    assert "GHSA-a" in prompt
    assert "GHSA-b" in prompt


def test_claude_prompt_instructs_acknowledge_others_when_multi() -> None:
    findings = (
        _finding(advisory_id="GHSA-a", title="a", cvss_score=9.0),
        _finding(advisory_id="GHSA-b", title="b", cvss_score=8.0),
    )
    candidate = _candidate(source_finding_ids=("GHSA-a", "GHSA-b"))
    prompt = explanation_mod._build_user_prompt(candidate, _verdict(candidate), findings)
    assert "additional findings" in prompt
    assert "1 of them" in prompt
    assert "by ID" in prompt


def test_claude_prompt_single_finding_no_multi_ack_instruction() -> None:
    finding = _finding(advisory_id="GHSA-only", title="only")
    candidate = _candidate(source_finding_ids=("GHSA-only",))
    prompt = explanation_mod._build_user_prompt(candidate, _verdict(candidate), (finding,))
    assert "additional findings" not in prompt
