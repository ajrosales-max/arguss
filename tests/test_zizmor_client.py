"""Tests for :class:`arguss.lenses._zizmor_client.ZizmorClient` and ``zizmor-scan`` CLI."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest
from typer.testing import CliRunner

import arguss.cli as cli_mod
from arguss.core.models import ZizmorFinding
from arguss.lenses._zizmor_client import (
    ZizmorClient,
    ZizmorClientError,
    _parse_zizmor_output,
)


def _finding_json(
    *,
    ident: str = "unpinned-uses",
    desc: str = "unpinned action reference",
    url: str = "https://docs.zizmor.sh/audits/#unpinned-uses",
    severity: str = "High",
    confidence: str = "High",
    row: int = 6,
    column: int = 14,
    feature: str = "actions/checkout@v4",
    annotation: str = "action is not pinned to a hash (required by blanket policy)",
    file_path: str = "/path/to/ci.yml",
    kind: str = "Primary",
    ignored: bool = False,
) -> dict:
    return {
        "ident": ident,
        "desc": desc,
        "url": url,
        "determinations": {
            "confidence": confidence,
            "severity": severity,
            "persona": "Regular",
        },
        "locations": [
            {
                "symbolic": {
                    "key": {
                        "Local": {
                            "prefix": None,
                            "given_path": file_path,
                        }
                    },
                    "annotation": annotation,
                    "route": {"route": []},
                    "feature_kind": {"Subfeature": {"after": 0, "fragment": {"Raw": feature}}},
                    "kind": kind,
                },
                "concrete": {
                    "location": {
                        "start_point": {"row": row, "column": column},
                        "end_point": {"row": row, "column": column + 19},
                        "offset_span": {"start": 100, "end": 119},
                    },
                    "feature": feature,
                    "comments": [],
                },
            }
        ],
        "ignored": ignored,
    }


def _completed_process(
    returncode: int, stdout: str, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["zizmor"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


@pytest.fixture
def client() -> ZizmorClient:
    with mock.patch("arguss.lenses._zizmor_client.shutil.which", return_value="/usr/bin/zizmor"):
        return ZizmorClient(binary="/usr/bin/zizmor")


def test_clean_run_returns_empty_list(client: ZizmorClient, tmp_path: Path) -> None:
    wf = tmp_path / "ci.yml"
    wf.write_text("name: CI\non: push\n", encoding="utf-8")
    with mock.patch(
        "arguss.lenses._zizmor_client.subprocess.run",
        return_value=_completed_process(0, "[]"),
    ) as run_mock:
        findings = client.scan_workflows(wf)
    assert findings == []
    run_mock.assert_called_once()


def test_findings_present_exit_zero(client: ZizmorClient, tmp_path: Path) -> None:
    wf = tmp_path / "ci.yml"
    wf.write_text("name: CI\n", encoding="utf-8")
    payload = [
        _finding_json(ident="a", row=5, column=10),
        _finding_json(ident="b", row=7, column=2),
        _finding_json(ident="c", row=9, column=0),
    ]
    with mock.patch(
        "arguss.lenses._zizmor_client.subprocess.run",
        return_value=_completed_process(0, json.dumps(payload)),
    ):
        findings = client.scan_workflows(wf)

    assert len(findings) == 3
    assert findings[0].ident == "a"
    assert findings[0].line == 6
    assert findings[0].column == 11
    assert findings[1].line == 8
    assert findings[1].column == 3


def test_severity_mapping_all_four() -> None:
    for title, expected in [
        ("Informational", "informational"),
        ("Low", "low"),
        ("Medium", "medium"),
        ("High", "high"),
    ]:
        raw = json.dumps([_finding_json(severity=title)])
        findings = _parse_zizmor_output(raw)
        assert len(findings) == 1
        assert findings[0].severity == expected


def test_confidence_mapping() -> None:
    for title, expected in [
        ("Low", "low"),
        ("Medium", "medium"),
        ("High", "high"),
        ("Unknown", "unknown"),
    ]:
        raw = json.dumps([_finding_json(confidence=title)])
        findings = _parse_zizmor_output(raw)
        assert findings[0].confidence == expected


def test_unknown_severity_defaults_medium(caplog: pytest.LogCaptureFixture) -> None:
    raw = json.dumps([_finding_json(severity="Critical")])
    with caplog.at_level("WARNING"):
        findings = _parse_zizmor_output(raw)
    assert findings[0].severity == "medium"
    assert any("unknown severity" in r.message for r in caplog.records)


def test_ignored_findings_filtered() -> None:
    payload = [
        _finding_json(ident="keep1"),
        _finding_json(ident="skip", ignored=True),
        _finding_json(ident="keep2"),
    ]
    findings = _parse_zizmor_output(json.dumps(payload))
    assert len(findings) == 2
    assert {f.ident for f in findings} == {"keep1", "keep2"}


def test_primary_location_preferred() -> None:
    payload = [
        {
            **_finding_json(ident="x"),
            "locations": [
                {
                    "symbolic": {
                        "key": {"Local": {"prefix": None, "given_path": "/p/w.yml"}},
                        "annotation": "related",
                        "kind": "Related",
                    },
                    "concrete": {
                        "location": {
                            "start_point": {"row": 1, "column": 1},
                            "end_point": {"row": 1, "column": 2},
                        },
                        "feature": "related-snippet",
                        "comments": [],
                    },
                },
                {
                    "symbolic": {
                        "key": {"Local": {"prefix": None, "given_path": "/p/w.yml"}},
                        "annotation": "primary ann",
                        "kind": "Primary",
                    },
                    "concrete": {
                        "location": {
                            "start_point": {"row": 10, "column": 5},
                            "end_point": {"row": 10, "column": 20},
                        },
                        "feature": "primary-snippet",
                        "comments": [],
                    },
                },
            ],
        }
    ]
    findings = _parse_zizmor_output(json.dumps(payload))
    assert findings[0].line == 11
    assert findings[0].column == 6
    assert findings[0].feature == "primary-snippet"
    assert findings[0].annotation == "primary ann"


def test_fallback_first_location_when_no_primary() -> None:
    payload = [
        {
            **_finding_json(ident="x"),
            "locations": [
                {
                    "symbolic": {
                        "key": {"Local": {"prefix": None, "given_path": "/p/first.yml"}},
                        "annotation": "first",
                        "kind": "Related",
                    },
                    "concrete": {
                        "location": {
                            "start_point": {"row": 2, "column": 3},
                            "end_point": {"row": 2, "column": 4},
                        },
                        "feature": "first-feature",
                        "comments": [],
                    },
                },
            ],
        }
    ]
    findings = _parse_zizmor_output(json.dumps(payload))
    assert findings[0].line == 3
    assert findings[0].file == "first.yml"


def test_subprocess_timeout_raises(client: ZizmorClient, tmp_path: Path) -> None:
    wf = tmp_path / "ci.yml"
    wf.write_text("name: CI\n", encoding="utf-8")
    with (
        mock.patch(
            "arguss.lenses._zizmor_client.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["zizmor"], timeout=30),
        ),
        pytest.raises(ZizmorClientError, match="timed out"),
    ):
        client.scan_workflows(wf)


def test_unexpected_exit_code_raises(client: ZizmorClient, tmp_path: Path) -> None:
    wf = tmp_path / "ci.yml"
    wf.write_text("name: CI\n", encoding="utf-8")
    with (
        mock.patch(
            "arguss.lenses._zizmor_client.subprocess.run",
            return_value=_completed_process(1, "", "fatal: something broke"),
        ),
        pytest.raises(ZizmorClientError, match="fatal: something broke"),
    ):
        client.scan_workflows(wf)


def test_zizmor_not_on_path_raises() -> None:
    with (
        mock.patch("arguss.lenses._zizmor_client.shutil.which", return_value=None),
        pytest.raises(ZizmorClientError, match="not found on PATH"),
    ):
        ZizmorClient()


def test_malformed_json_raises(client: ZizmorClient, tmp_path: Path) -> None:
    wf = tmp_path / "ci.yml"
    wf.write_text("name: CI\n", encoding="utf-8")
    with (
        mock.patch(
            "arguss.lenses._zizmor_client.subprocess.run",
            return_value=_completed_process(0, "not-json"),
        ),
        pytest.raises(ZizmorClientError, match="invalid JSON"),
    ):
        client.scan_workflows(wf)


def test_empty_locations_skipped_with_warning(caplog: pytest.LogCaptureFixture) -> None:
    payload = [
        {
            "ident": "x",
            "desc": "d",
            "url": "u",
            "determinations": {"severity": "Low", "confidence": "Low"},
            "locations": [],
            "ignored": False,
        }
    ]
    with caplog.at_level("WARNING"):
        findings = _parse_zizmor_output(json.dumps(payload))
    assert findings == []
    assert any("no usable location" in r.message for r in caplog.records)


def test_cli_zizmor_scan_success_and_error(tmp_path: Path) -> None:
    runner = CliRunner()
    wf = tmp_path / "ci.yml"
    wf.write_text("name: CI\n", encoding="utf-8")
    fake = ZizmorFinding(
        ident="unpinned-uses",
        severity="high",
        confidence="high",
        description="unpinned",
        file="ci.yml",
        line=7,
        column=15,
        feature="actions/checkout@v4",
        annotation="ann",
        audit_url="https://docs.zizmor.sh/audits/#unpinned-uses",
    )
    with mock.patch.object(cli_mod, "ZizmorClient") as mock_cls:
        mock_cls.return_value.scan_workflows.return_value = [fake]
        ok = runner.invoke(cli_mod.app, ["zizmor-scan", str(wf)])
    assert ok.exit_code == 0
    body = json.loads(ok.stdout)
    assert body[0]["ident"] == "unpinned-uses"
    assert body[0]["line"] == 7

    with mock.patch.object(
        cli_mod,
        "ZizmorClient",
        side_effect=ZizmorClientError("zizmor not found on PATH"),
    ):
        bad = runner.invoke(cli_mod.app, ["zizmor-scan", str(wf)])
    assert bad.exit_code == 1


@pytest.mark.integration
def test_integration_sample_workflow_finds_unpinned() -> None:
    fixture = Path("tests/fixtures/workflows/sample-with-findings/ci.yml")
    assert fixture.is_file()
    client = ZizmorClient()
    findings = client.scan_workflows(fixture)
    assert len(findings) >= 2
    for f in findings:
        assert f.ident
        assert f.description
        assert f.file
        assert f.line >= 1
        assert f.column >= 1
        assert f.audit_url.startswith("https://")
    assert any(f.ident == "unpinned-uses" for f in findings)
