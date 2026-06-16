"""Tests for download-ranked top-1000 loader."""

from __future__ import annotations

from pathlib import Path

from arguss.core.top_1000_list import load_ranked_top_1000


def test_load_ranked_top_1000_preserves_line_order(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "npm-top-1000-2026-06.txt").write_text(
        "semver\nminimatch\n# comment\n\ndebug\n",
        encoding="utf-8",
    )

    ranked = load_ranked_top_1000(data_dir=data_dir)

    assert ranked == [(1, "semver"), (2, "minimatch"), (3, "debug")]


def test_load_ranked_top_1000_picks_newest_file(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "npm-top-1000-2026-05.txt").write_text("old\n", encoding="utf-8")
    (data_dir / "npm-top-1000-2026-06.txt").write_text("new\n", encoding="utf-8")

    assert load_ranked_top_1000(data_dir=data_dir) == [(1, "new")]
