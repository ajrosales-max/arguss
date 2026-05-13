"""Skeleton tests — canary suite that stays green for the whole project."""

import json
from pathlib import Path

from typer.testing import CliRunner

from arguss.cli import app
from arguss.core.models import LensScore, ProjectScore
from arguss.lenses import PipelineLens, TrustLens, VulnerabilityLens
from arguss.scoring import compute_project_score

runner = CliRunner()


def test_cli_runs_end_to_end(tmp_path: Path) -> None:
    """The CLI accepts a path and prints a valid ProjectScore JSON."""
    fake_lockfile = tmp_path / "package-lock.json"
    fake_lockfile.write_text('{"lockfileVersion": 3, "packages": {}}')

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0, f"CLI failed: {result.output}"
    output = json.loads(result.stdout)
    assert "overall" in output
    assert 0 <= output["overall"] <= 100
    assert "lens_scores" in output
    assert set(output["lens_scores"].keys()) == {"cve", "trust", "pipeline"}


def test_unified_scoring_math() -> None:
    """The unified score is a weighted average of the three lenses."""
    cve = LensScore(lens="cve", score=100.0, findings=[])
    trust = LensScore(lens="trust", score=0.0, findings=[])
    pipeline = LensScore(lens="pipeline", score=0.0, findings=[])

    score = compute_project_score(cve, trust, pipeline)

    # 100 * 0.4 + 0 * 0.3 + 0 * 0.3 = 40
    assert score.overall == 40.0


def test_unified_scoring_all_max() -> None:
    """When all lenses max out, overall is 100."""
    cve = LensScore(lens="cve", score=100.0, findings=[])
    trust = LensScore(lens="trust", score=100.0, findings=[])
    pipeline = LensScore(lens="pipeline", score=100.0, findings=[])

    score = compute_project_score(cve, trust, pipeline)
    assert score.overall == 100.0


def test_unified_scoring_all_zero() -> None:
    """When all lenses are clean, overall is 0."""
    cve = LensScore(lens="cve", score=0.0, findings=[])
    trust = LensScore(lens="trust", score=0.0, findings=[])
    pipeline = LensScore(lens="pipeline", score=0.0, findings=[])

    score = compute_project_score(cve, trust, pipeline)
    assert score.overall == 0.0


def test_lenses_return_valid_lens_scores() -> None:
    """Each lens returns a LensScore matching its declared name."""
    from arguss.core.models import Dependency

    deps = [Dependency(name="x", version="1.0.0", direct=True)]

    cve = VulnerabilityLens().scan(deps)
    trust = TrustLens().scan(deps)
    pipeline = PipelineLens().scan(".")

    assert cve.lens == "cve"
    assert trust.lens == "trust"
    assert pipeline.lens == "pipeline"
    assert all(0 <= s.score <= 100 for s in [cve, trust, pipeline])


def test_project_score_serializes_to_json() -> None:
    """A ProjectScore round-trips through JSON cleanly."""
    cve = LensScore(lens="cve", score=50.0, findings=[])
    trust = LensScore(lens="trust", score=30.0, findings=[])
    pipeline = LensScore(lens="pipeline", score=20.0, findings=[])

    score = compute_project_score(cve, trust, pipeline)
    serialized = score.model_dump_json()
    restored = ProjectScore.model_validate_json(serialized)

    assert restored.overall == score.overall


def test_health_endpoint() -> None:
    """The FastAPI health endpoint responds correctly."""
    from fastapi.testclient import TestClient

    from arguss.api import app as api_app

    client = TestClient(api_app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "arguss"


def test_cache_round_trip(tmp_path: Path) -> None:
    """The SQLite cache writes and reads back values correctly."""
    from arguss.core.cache import Cache, get_connection, init_db

    db_path = tmp_path / "test.db"
    conn = get_connection(db_path)
    init_db(conn)
    cache = Cache(conn)

    cache.set_api_response("osv", "test-key", {"vulns": ["CVE-1"]})
    assert cache.get_api_response("osv", "test-key") == {"vulns": ["CVE-1"]}
    assert cache.get_api_response("osv", "nonexistent") is None
