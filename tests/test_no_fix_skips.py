"""Unit tests for structured no-fix and lens-failure skip views in results context."""

from __future__ import annotations

from typing import Any

import pytest

import arguss.engine.propose as propose_mod
from arguss.core.models import LensFailureSkip, NoFixSkip
from arguss.engine.propose import propose_fixes
from arguss.engine.skips import no_fix_reason_label, no_fix_skip_from_finding
from arguss.web.results_context import (
    build_lens_failure_skips,
    build_no_fix_skips,
    build_results_context,
)
from tests.test_propose_fixes import (
    FIXTURES,
    _cve_finding,
    _mock_fetch_snapshot,
    _mock_vulnerability_lens,
    _safe_pipeline,
)


def _no_fix_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": "no_fix",
        "advisory_id": "GHSA-abc",
        "package": "lodash",
        "current_version": "4.17.20",
        "title": "Prototype pollution",
        "description": "Detailed advisory text",
        "cvss_score": 7.5,
        "severity": "high",
        "source_url": "https://osv.dev/vulnerability/GHSA-abc",
        "dependency_path": ["app", "lodash"],
        "epss_score": 0.42,
        "epss_percentile": 0.91,
        "is_kev": True,
        "kev_known_ransomware": False,
        "kev_due_date": "2026-01-01",
        "reason": "no_fix_version_in_osv",
        "reason_label": no_fix_reason_label("no_fix_version_in_osv"),
    }
    base.update(overrides)
    return base


def test_no_fix_skip_carries_full_finding_detail() -> None:
    cached = {"skipped_findings": [_no_fix_payload()]}
    views = build_no_fix_skips(cached)
    assert len(views) == 1
    v = views[0]
    assert v.title == "Prototype pollution"
    assert v.description == "Detailed advisory text"
    assert v.package == "lodash"
    assert v.current_version == "4.17.20"
    assert v.dependency_path == "app → lodash"


def test_no_fix_skip_emits_accurate_reason() -> None:
    cached = {
        "skipped_findings": [
            _no_fix_payload(
                reason="no_advisory_id", reason_label=no_fix_reason_label("no_advisory_id")
            )
        ]
    }
    v = build_no_fix_skips(cached)[0]
    assert v.reason == "no_advisory_id"
    assert v.reason_label == "Fix version not determinable (no advisory ID)"


def test_no_fix_skip_includes_epss_kev_when_present() -> None:
    v = build_no_fix_skips({"skipped_findings": [_no_fix_payload()]})[0]
    assert v.is_kev is True
    assert v.epss_score == pytest.approx(0.42)
    assert v.kev_due_date == "2026-01-01"


def test_lens_failure_skip_has_kind_discriminator() -> None:
    cached = {
        "skipped_findings": [
            {
                "kind": "lens_failure",
                "reason": "osv_unavailable",
                "detail": "OSV API error",
                "lens": "vulnerability",
            }
        ]
    }
    skips = build_lens_failure_skips(cached)
    assert len(skips) == 1
    assert isinstance(skips[0], LensFailureSkip)
    assert skips[0].kind == "lens_failure"


def test_skipped_findings_all_objects_no_bare_strings() -> None:
    finding = _cve_finding(advisory_id="GHSA-no-fix", fixed_versions=())
    skip = no_fix_skip_from_finding(finding, "no_fix_version_in_osv")
    assert isinstance(skip, NoFixSkip)
    cached = {
        "entries": [],
        "project_scores": {},
        "summary": {
            "total_findings": 1,
            "auto_merge_count": 0,
            "review_required_count": 0,
            "decline_count": 0,
        },
        "skipped_findings": [skip.model_dump()],
    }
    ctx = build_results_context(cached, "hash")
    for item in ctx["skipped_findings"]:
        assert isinstance(item, dict)
        assert "kind" in item


def test_skip_does_not_affect_candidate_count(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:

    from arguss.settings import Settings
    from arguss.settings import settings as live_settings

    db = tmp_path / "propose.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "kill_switch_absent"))

    findings = [
        _cve_finding(advisory_id="GHSA-has-fix"),
        _cve_finding(advisory_id="GHSA-no-fix", fixed_versions=()),
    ]
    _mock_vulnerability_lens(monkeypatch, findings)
    _mock_fetch_snapshot(monkeypatch)
    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", lambda _p: _safe_pipeline())
    monkeypatch.setattr(propose_mod, "fetch_delta", lambda *a, **k: propose_mod.__dict__.get("_td"))

    from tests.test_propose_fixes import _safe_trust_delta

    monkeypatch.setattr(propose_mod, "fetch_delta", lambda *a, **k: _safe_trust_delta())

    report = propose_fixes(FIXTURES / "minimal.json")
    cached = {
        "entries": [e.model_dump() if hasattr(e, "model_dump") else e for e in report.entries],
        "skipped_findings": [s.model_dump() for s in report.skipped_findings],
        "summary": report.summary.__dict__,
        "project_scores": report.project_scores.__dict__ if report.project_scores else {},
        "scan_meta": {"mode": "A"},
    }
    # serialize entries properly
    from arguss.core.serialization import proposal_entry_payload

    cached["entries"] = [proposal_entry_payload(e) for e in report.entries]
    ctx = build_results_context(cached, "h")
    assert ctx["candidates_by_tier"]["total_count"] == len(report.entries)
    assert len(ctx["no_fix_skips"]) >= 1
