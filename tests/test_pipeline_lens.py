"""Tests for pipeline lens, test reality heuristics, and ``pipeline-snapshot`` CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest
from typer.testing import CliRunner

import arguss.cli as cli_mod
import arguss.lenses.pipeline as pipeline_mod
from arguss.core.models import TestReality as TestRealityModel
from arguss.core.models import ZizmorFinding
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.lenses.pipeline import (
    PipelineLens,
    _compute_subscore,
    _test_script_is_no_op,
    _workflow_runs_tests,
    fetch_pipeline_snapshot,
)

_FIXTURES = Path("tests/fixtures/repos")


def _fixture(name: str) -> Path:
    return _FIXTURES / name


def test_clean_fixture_safe_to_auto_merge() -> None:
    tr = fetch_pipeline_snapshot(_fixture("clean-with-tests")).test_reality
    assert tr.safe_to_auto_merge is True
    assert tr.reasons_blocked == ()
    assert tr.has_test_script is True
    assert tr.workflow_runs_tests is True


def test_no_test_script_blocks_auto_merge() -> None:
    tr = fetch_pipeline_snapshot(_fixture("no-test-script")).test_reality
    assert tr.safe_to_auto_merge is False
    assert any("scripts.test" in r for r in tr.reasons_blocked)


def test_noop_test_script_blocks_auto_merge() -> None:
    tr = fetch_pipeline_snapshot(_fixture("noop-test-script")).test_reality
    assert tr.safe_to_auto_merge is False
    assert tr.test_script_is_no_op is True
    assert any("no-op" in r for r in tr.reasons_blocked)


def test_no_test_files_blocks_auto_merge() -> None:
    tr = fetch_pipeline_snapshot(_fixture("no-test-files")).test_reality
    assert tr.safe_to_auto_merge is False
    assert tr.has_test_files is False
    assert any("no test files" in r for r in tr.reasons_blocked)


def test_workflow_not_running_tests_blocks_auto_merge() -> None:
    tr = fetch_pipeline_snapshot(_fixture("workflow-skips-tests")).test_reality
    assert tr.safe_to_auto_merge is False
    assert tr.workflow_runs_tests is False
    assert any("workflow" in r and "test" in r for r in tr.reasons_blocked)


def test_yarn_test_recognized() -> None:
    tr = fetch_pipeline_snapshot(_fixture("yarn-tests")).test_reality
    assert tr.safe_to_auto_merge is True
    assert tr.workflow_runs_tests is True


def test_subscore_no_findings_clean_ci() -> None:
    tr = TestRealityModel(
        has_test_script=True,
        test_script_is_no_op=False,
        has_test_files=True,
        test_count=1,
        workflow_runs_tests=True,
        safe_to_auto_merge=True,
        reasons_blocked=(),
    )
    assert _compute_subscore([], tr) == 0


def test_subscore_findings_only() -> None:
    findings = [
        ZizmorFinding(
            ident="a",
            severity="medium",
            confidence="medium",
            description="d",
            file="ci.yml",
            line=1,
            column=1,
            feature="f",
            annotation="a",
            audit_url="https://example.com",
        )
    ] * 3
    tr = TestRealityModel(
        has_test_script=True,
        test_script_is_no_op=False,
        has_test_files=True,
        test_count=1,
        workflow_runs_tests=True,
        safe_to_auto_merge=True,
        reasons_blocked=(),
    )
    assert _compute_subscore(findings, tr) == 45


def test_subscore_test_reality_penalty() -> None:
    tr = TestRealityModel(
        has_test_script=False,
        test_script_is_no_op=False,
        has_test_files=False,
        test_count=0,
        workflow_runs_tests=False,
        safe_to_auto_merge=False,
        reasons_blocked=("x",),
    )
    assert _compute_subscore([], tr) == 40


def test_subscore_both_combined() -> None:
    findings = [
        ZizmorFinding(
            ident="h",
            severity="high",
            confidence="high",
            description="d",
            file="ci.yml",
            line=1,
            column=1,
            feature="f",
            annotation="a",
            audit_url="https://example.com",
        )
    ] * 2
    tr = TestRealityModel(
        has_test_script=False,
        test_script_is_no_op=False,
        has_test_files=False,
        test_count=0,
        workflow_runs_tests=False,
        safe_to_auto_merge=False,
        reasons_blocked=("x",),
    )
    assert _compute_subscore(findings, tr) == 100


def test_subscore_caps_at_100() -> None:
    findings = [
        ZizmorFinding(
            ident="h",
            severity="high",
            confidence="high",
            description="d",
            file="ci.yml",
            line=1,
            column=1,
            feature="f",
            annotation="a",
            audit_url="https://example.com",
        )
    ] * 10
    tr = TestRealityModel(
        has_test_script=False,
        test_script_is_no_op=False,
        has_test_files=False,
        test_count=0,
        workflow_runs_tests=False,
        safe_to_auto_merge=False,
        reasons_blocked=("x",),
    )
    assert _compute_subscore(findings, tr) == 100


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("echo 'no tests'", True),
        ('echo "no test" && exit 0', True),
        ("exit 0", True),
        ("true", True),
        ("jest", False),
        ("jest --coverage", False),
        ("npm run test:unit", False),
        ("vitest", False),
        ("tsc --noEmit", False),
    ],
)
def test_noop_script_patterns(script: str, expected: bool) -> None:
    assert _test_script_is_no_op(script) is expected


@pytest.mark.parametrize(
    "content",
    [
        "npm test",
        "npm run test",
        "yarn test",
        "yarn run test",
        "pnpm test",
        "pnpm run test",
        "bun test",
        "bun run test",
    ],
)
def test_workflow_regex_matches(tmp_path: Path, content: str) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(f"steps:\n  - run: {content}\n", encoding="utf-8")
    assert _workflow_runs_tests(wf_dir) is True


@pytest.mark.parametrize(
    "content",
    [
        "npm install",
        "npm run build",
        "npm run lint",
        "python test.py",
    ],
)
def test_workflow_regex_no_match(tmp_path: Path, content: str) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(f"steps:\n  - run: {content}\n", encoding="utf-8")
    assert _workflow_runs_tests(wf_dir) is False


def test_fetch_pipeline_snapshot_clean_fixture() -> None:
    snap = fetch_pipeline_snapshot(_fixture("clean-with-tests"))
    assert snap.repo_path.endswith("clean-with-tests")
    assert ".github/workflows/ci.yml" in snap.workflow_files
    assert len(snap.zizmor_findings) >= 1
    assert snap.test_reality.safe_to_auto_merge is True
    assert snap.subscore >= 0


def test_fetch_pipeline_snapshot_no_dot_github(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"x","scripts":{"test":"jest"}}',
        encoding="utf-8",
    )
    (tmp_path / "__tests__").mkdir()
    (tmp_path / "__tests__" / "a.test.js").write_text("test('x',()=>{});", encoding="utf-8")
    snap = fetch_pipeline_snapshot(tmp_path)
    assert snap.workflow_files == ()
    assert snap.test_reality.workflow_runs_tests is False
    assert snap.test_reality.safe_to_auto_merge is False
    assert snap.test_reality.reasons_blocked == ("no workflows directory",)


def test_reasons_short_circuit_no_package_json(tmp_path: Path) -> None:
    """Missing package.json must not also claim scripts.test is missing."""
    snap = fetch_pipeline_snapshot(tmp_path)
    tr = snap.test_reality
    assert tr.has_test_script is False
    assert tr.test_script_is_no_op is False
    assert "no package.json found" in tr.reasons_blocked
    assert not any("scripts.test" in r for r in tr.reasons_blocked)
    assert not any("no-op" in r for r in tr.reasons_blocked)
    assert "no workflows directory" in tr.reasons_blocked
    assert not any("workflow runs tests" in r for r in tr.reasons_blocked)


def test_pipeline_lens_scan_clean_fixture() -> None:
    lens = PipelineLens(repo_path=_fixture("clean-with-tests"))
    score = lens.scan([])
    assert score.lens == "pipeline"
    assert score.score >= 0
    assert len(score.findings) >= 1


def test_pipeline_lens_scan_no_repo_path() -> None:
    score = PipelineLens().scan([])
    assert score.score == 50.0
    assert score.findings[0].title == "Unpinned action reference"


def test_pipeline_lens_findings_include_test_reality() -> None:
    lens = PipelineLens(repo_path=_fixture("noop-test-script"))
    score = lens.scan([])
    titles = [f.title for f in score.findings]
    assert any("test reality" in t.lower() for t in titles)


def test_cli_pipeline_snapshot_success_and_failure(tmp_path: Path) -> None:
    runner = CliRunner()
    with mock.patch.object(cli_mod, "fetch_pipeline_snapshot") as mock_fetch:
        mock_fetch.return_value = pipeline_mod.fetch_pipeline_snapshot(_fixture("clean-with-tests"))
        ok = runner.invoke(
            cli_mod.app,
            ["pipeline-snapshot", str(_fixture("clean-with-tests"))],
        )
    assert ok.exit_code == 0
    body = json.loads(ok.stdout)
    assert "test_reality" in body
    assert "subscore" in body

    with mock.patch.object(
        cli_mod,
        "fetch_pipeline_snapshot",
        side_effect=ZizmorClientError("zizmor missing"),
    ):
        bad = runner.invoke(cli_mod.app, ["pipeline-snapshot", str(tmp_path)])
    assert bad.exit_code == 1


@pytest.mark.integration
def test_integration_pipeline_snapshot_clean_fixture() -> None:
    snap = fetch_pipeline_snapshot(_fixture("clean-with-tests"))
    assert len(snap.zizmor_findings) >= 2
    for z in snap.zizmor_findings:
        assert z.ident
        assert z.description
        assert z.file
        assert z.audit_url
    assert any(z.ident == "unpinned-uses" for z in snap.zizmor_findings)
