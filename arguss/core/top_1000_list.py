"""Download-ranked top-1000 npm list with preserved rank order.

Separate from :func:`arguss.lenses.trust._load_top_1000_npm`, which loads the same
file into a ``frozenset`` for typosquat checks (order irrelevant there).
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DATA_DIR = _REPO_ROOT / "data"


def load_ranked_top_1000(*, data_dir: Path | None = None) -> list[tuple[int, str]]:
    """Load ``(rank, name)`` from the newest ``data/npm-top-1000-*.txt``.

    Rank is 1-based line order in the file (download rank). Lines starting with
    ``#`` and blank lines are skipped.
    """
    base = data_dir or _DATA_DIR
    if not base.is_dir():
        return []
    candidates = sorted(base.glob("npm-top-1000-*.txt"))
    if not candidates:
        return []
    latest = candidates[-1]
    ranked: list[tuple[int, str]] = []
    rank = 0
    for line in latest.read_text(encoding="utf-8").splitlines():
        name = line.strip()
        if not name or name.startswith("#"):
            continue
        rank += 1
        ranked.append((rank, name))
    return ranked
