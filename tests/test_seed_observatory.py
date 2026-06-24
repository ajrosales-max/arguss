"""Tests for scripts/seed_observatory.py (offline, no live git/npm)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

import arguss.engine.propose as propose_mod
from arguss.core.models import Dependency, Finding, LensScore, TrustDelta, TrustSnapshot
from arguss.explanations.scan_cache import scan_input_hash
from arguss.settings import Settings
from arguss.settings import settings as live_settings

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPO_FIXTURES = Path(__file__).parent / "fixtures" / "repos"
_LOCK_FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"


def _load_seed_module() -> Any:
    path = _REPO_ROOT / "scripts" / "seed_observatory.py"
    module_name = "seed_observatory"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        msg = f"cannot load seed module from {path}"
        raise RuntimeError(msg)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def isolate_observatory_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports_dir = tmp_path / "observatory-reports"
    monkeypatch.setattr(
        "arguss.web.observatory_seed.default_reports_dir",
        lambda: reports_dir,
    )


@pytest.fixture
def seed_mod() -> Any:
    return _load_seed_module()


@pytest.fixture
def seed_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "seed_observatory.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "kill_switch_absent"))
    return db


def _copy_fixture_repo(tmp_path: Path, name: str) -> Path:
    dest = tmp_path / name
    shutil.copytree(_REPO_FIXTURES / name, dest)
    return dest


def _patch_clone_and_lockfile(
    monkeypatch: pytest.MonkeyPatch,
    seed_mod: Any,
    *,
    repo_fixture: str,
    tmp_path: Path,
) -> Path:
    clone_root = _copy_fixture_repo(tmp_path, repo_fixture)
    lock_src = _LOCK_FIXTURES / "minimal.json"

    def fake_shallow_clone(owner: str, repo: str, ref: str) -> Path:
        return clone_root

    def fake_generate_lockfile(repo_path: Path) -> Path:
        lockfile = repo_path / "package-lock.json"
        shutil.copy(lock_src, lockfile)
        return lockfile

    monkeypatch.setattr(seed_mod, "_shallow_clone", fake_shallow_clone)
    monkeypatch.setattr(seed_mod, "_generate_lockfile", fake_generate_lockfile)
    return clone_root


def _mock_external_lenses(monkeypatch: pytest.MonkeyPatch) -> None:
    finding = Finding(
        dependency=Dependency(name="left-pad", version="1.3.0", direct=True),
        lens="cve",
        severity="high",
        score=75.0,
        title="GHSA-test: left-pad advisory",
        description="test",
        advisory_id="GHSA-seed-test",
        fixed_versions=("1.3.1",),
    )
    lens_score = LensScore(lens="cve", score=80.0, findings=[finding])
    instance = mock.MagicMock()
    instance.scan.return_value = lens_score
    monkeypatch.setattr(propose_mod, "VulnerabilityLens", lambda cache: instance)

    snap = TrustSnapshot(
        package="left-pad",
        version="1.3.0",
        captured_at=datetime.now(UTC),
        maintainer_count=1,
        maintainer_logins=("u",),
        published_at=datetime(2020, 1, 1, tzinfo=UTC),
        days_since_previous_publish=1,
        typosquat_distance=0,
        typosquat_nearest="left-pad",
        weekly_downloads=1000,
        subscore=30,
    )
    monkeypatch.setattr(propose_mod, "fetch_snapshot", lambda *a, **k: snap)
    monkeypatch.setattr(
        propose_mod,
        "fetch_delta",
        lambda *a, **k: TrustDelta(
            package="left-pad",
            from_version="1.3.0",
            to_version="1.3.1",
            maintainers_added=(),
            maintainers_removed=(),
            ownership_transferred=False,
            days_between_publishes=10,
            publish_cadence_anomaly=False,
            weekly_downloads_change_pct=0.0,
            flags=(),
            safe_to_auto_merge=True,
        ),
    )


def test_scan_one_returns_row_with_hash_and_scanned_at(
    seed_mod: Any,
    seed_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_clone_and_lockfile(
        monkeypatch,
        seed_mod,
        repo_fixture="clean-with-tests",
        tmp_path=tmp_path,
    )
    _mock_external_lenses(monkeypatch)

    row = seed_mod._scan_one("fixture", "clean-with-tests", "main")

    assert row["error"] is None
    assert row["scan_hash"]
    assert row["scanned_at"]
    assert row["owner"] == "fixture"
    assert row["repo"] == "clean-with-tests"
    assert row["ref"] == "main"
    assert row["auto_fix_count"] + row["review_count"] + row["decline_count"] >= 1


def test_scan_one_persists_report_artifact(
    seed_mod: Any,
    seed_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reports_dir = tmp_path / "observatory-reports"
    _patch_clone_and_lockfile(
        monkeypatch,
        seed_mod,
        repo_fixture="clean-with-tests",
        tmp_path=tmp_path / "repo",
    )
    _mock_external_lenses(monkeypatch)

    row = seed_mod._scan_one("fixture", "clean-with-tests", "main")

    assert row["error"] is None
    assert row["scan_hash"]
    report_path = reports_dir / f"{row['scan_hash']}.json"
    assert report_path.is_file()
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert scan_input_hash(payload) == row["scan_hash"]
    assert payload.get("scan_counts")
    assert payload.get("summary")


def test_scan_one_pipeline_fixture_affects_tier_counts(
    seed_mod: Any,
    seed_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real pipeline lens via repo_path: healthy CI vs missing tests changes tiers."""
    _mock_external_lenses(monkeypatch)

    _patch_clone_and_lockfile(
        monkeypatch,
        seed_mod,
        repo_fixture="clean-with-tests",
        tmp_path=tmp_path / "clean",
    )
    clean_row = seed_mod._scan_one("fixture", "clean-with-tests", "main")

    _patch_clone_and_lockfile(
        monkeypatch,
        seed_mod,
        repo_fixture="no-test-files",
        tmp_path=tmp_path / "no-tests",
    )
    blocked_row = seed_mod._scan_one("fixture", "no-test-files", "main")

    assert clean_row["error"] is None
    assert blocked_row["error"] is None
    assert clean_row["auto_fix_count"] >= 1
    assert blocked_row["review_count"] >= 1
    assert clean_row["auto_fix_count"] > blocked_row["auto_fix_count"]


def test_run_discovery_skips_failed_clone(
    seed_mod: Any,
    seed_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        seed_mod,
        "_DISCOVERY",
        (("fixture", "clean-with-tests", "main"),),
    )

    def boom(owner: str, repo: str, ref: str) -> Path:
        raise subprocess.CalledProcessError(128, "git", stderr="clone failed")

    monkeypatch.setattr(seed_mod, "_shallow_clone", boom)

    rows = seed_mod._run_discovery()

    assert rows == []
    captured = capsys.readouterr()
    assert "SKIP:" in captured.err
    assert "CalledProcessError" in captured.err


def test_prune_orphan_reports_removes_stale_keeps_current(
    seed_mod: Any,
    tmp_path: Path,
) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    keep_hash = "a" * 64
    stale_hash = "b" * 64
    (reports / f"{keep_hash}.json").write_text("{}", encoding="utf-8")
    (reports / f"{stale_hash}.json").write_text("{}", encoding="utf-8")

    removed = seed_mod._prune_orphan_reports(
        [{"scan_hash": keep_hash}],
        reports_dir=reports,
    )

    assert removed == 1
    assert (reports / f"{keep_hash}.json").is_file()
    assert not (reports / f"{stale_hash}.json").exists()


def test_main_zero_rows_skips_prune_and_seed_write(
    seed_mod: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed_out = tmp_path / "seed.json"
    reports = tmp_path / "reports"
    reports.mkdir()
    stale = reports / f"{'c' * 64}.json"
    stale.write_text("{}", encoding="utf-8")
    original = '{"version": 1, "scans": [{"name": "kept"}]}\n'
    seed_out.write_text(original, encoding="utf-8")

    monkeypatch.setattr(seed_mod, "_run_discovery", lambda: [])
    monkeypatch.setattr(
        "arguss.web.observatory_seed.default_reports_dir",
        lambda: reports,
    )
    monkeypatch.setattr(sys, "argv", ["seed_observatory.py", "-o", str(seed_out)])

    rc = seed_mod.main()

    assert rc == 1
    assert seed_out.read_text(encoding="utf-8") == original
    assert stale.is_file()
    captured = capsys.readouterr()
    assert "zero successful scans" in captured.err


def _finding_dict(
    finding_id: str,
    *,
    name: str,
    version: str,
    install_key: str = "",
) -> dict[str, Any]:
    dependency: dict[str, Any] = {"name": name, "version": version}
    if install_key:
        dependency["install_key"] = install_key
    return {"finding_id": finding_id, "dependency": dependency}


def _classify_payload(
    seed_mod: Any,
    tmp_path: Path,
    payload: dict[str, Any],
) -> int:
    lockfile = _LOCK_FIXTURES / "prod-dev-classify.json"
    lock_copy = tmp_path / "package-lock.json"
    shutil.copy(lockfile, lock_copy)
    return seed_mod._classify_prod_findings(payload, lock_copy)


def test_classify_prod_findings_comprehensive_fixture(
    seed_mod: Any,
    tmp_path: Path,
) -> None:
    payload: dict[str, Any] = {
        "scan_counts": {"total_findings": 8},
        "deps": [
            {
                "package": "dev-only-pkg",
                "version": "1.0.0",
                "install_key": "node_modules/dev-only-pkg",
            },
            {
                "package": "prod-pkg",
                "version": "2.0.0",
                "install_key": "node_modules/prod-pkg",
            },
            {
                "package": "dev-optional-pkg",
                "version": "3.0.0",
                "install_key": "node_modules/dev-optional-pkg",
            },
            {
                "package": "mixed-pkg",
                "version": "4.0.0",
                "install_key": "node_modules/mixed-dev",
            },
            {
                "package": "mixed-pkg",
                "version": "4.0.0",
                "install_key": "node_modules/mixed-prod",
            },
        ],
        "entries": [
            {
                "finding": _finding_dict(
                    "f-dev",
                    name="dev-only-pkg",
                    version="1.0.0",
                    install_key="node_modules/dev-only-pkg",
                ),
            },
            {
                "finding": _finding_dict(
                    "f-prod",
                    name="prod-pkg",
                    version="2.0.0",
                    install_key="node_modules/prod-pkg",
                ),
                "related_findings": [
                    _finding_dict(
                        "f-prod",
                        name="prod-pkg",
                        version="2.0.0",
                        install_key="node_modules/prod-pkg",
                    ),
                ],
            },
            {
                "finding": _finding_dict(
                    "f-optional",
                    name="dev-optional-pkg",
                    version="3.0.0",
                    install_key="node_modules/dev-optional-pkg",
                ),
            },
            {
                "finding": _finding_dict(
                    "f-absent",
                    name="absent-key-pkg",
                    version="9.0.0",
                    install_key="node_modules/absent-key-pkg",
                ),
            },
        ],
        "skipped_findings": [
            {
                "kind": "no_fix",
                "finding_id": "f-skip-dev",
                "package": "dev-only-pkg",
                "current_version": "1.0.0",
            },
            {
                "kind": "no_fix",
                "finding_id": "f-skip-prod",
                "package": "prod-pkg",
                "current_version": "2.0.0",
            },
            {
                "kind": "no_fix",
                "finding_id": "f-skip-mixed",
                "package": "mixed-pkg",
                "current_version": "4.0.0",
            },
            {
                "kind": "no_fix",
                "finding_id": "f-skip-fallback",
                "package": "unknown-pkg",
                "current_version": "9.9.9",
            },
            {"kind": "lens_failure", "reason": "upstream", "detail": "x", "lens": "cve"},
            "GHSA-advisory-only",
        ],
    }

    prod = _classify_payload(seed_mod, tmp_path, payload)

    assert prod == 6
    assert prod <= payload["scan_counts"]["total_findings"]


def test_classify_prod_findings_resolves_related_without_install_key(
    seed_mod: Any,
    tmp_path: Path,
) -> None:
    payload: dict[str, Any] = {
        "scan_counts": {"total_findings": 2},
        "deps": [
            {
                "package": "dev-only-pkg",
                "version": "1.0.0",
                "install_key": "node_modules/dev-only-pkg",
            },
            {
                "package": "prod-pkg",
                "version": "2.0.0",
                "install_key": "node_modules/prod-pkg",
            },
        ],
        "entries": [
            {
                "finding": _finding_dict(
                    "f-primary",
                    name="prod-pkg",
                    version="2.0.0",
                    install_key="node_modules/prod-pkg",
                ),
                "related_findings": [
                    _finding_dict("f-related-dev", name="dev-only-pkg", version="1.0.0"),
                ],
            },
        ],
        "skipped_findings": [],
    }

    prod = _classify_payload(seed_mod, tmp_path, payload)

    assert prod == 1


def test_classify_prod_findings_warns_when_universe_mismatch(
    seed_mod: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload: dict[str, Any] = {
        "scan_counts": {"total_findings": 3},
        "deps": [],
        "entries": [
            {
                "finding": _finding_dict(
                    "only-one",
                    name="prod-pkg",
                    version="2.0.0",
                    install_key="node_modules/prod-pkg",
                ),
            },
        ],
        "skipped_findings": [],
    }

    _classify_payload(seed_mod, tmp_path, payload)
    captured = capsys.readouterr()

    assert "WARN: prod classifier finding universe mismatch" in captured.err
    assert "seen=1" in captured.err
    assert "total_findings=3" in captured.err


def test_scan_one_row_includes_prod_findings(
    seed_mod: Any,
    seed_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_clone_and_lockfile(
        monkeypatch,
        seed_mod,
        repo_fixture="clean-with-tests",
        tmp_path=tmp_path,
    )
    _mock_external_lenses(monkeypatch)

    row = seed_mod._scan_one("fixture", "clean-with-tests", "main")

    assert row["error"] is None
    assert "prod_findings" in row
    assert isinstance(row["prod_findings"], int)
    assert row["prod_findings"] <= row["total_findings"]
