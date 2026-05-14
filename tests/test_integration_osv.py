"""Integration tests that hit the real OSV.dev API.

Skipped in the default test run (see ``addopts`` in pyproject.toml). Run with:

    uv run pytest -m integration -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arguss.core.cache import Cache, get_connection, init_db
from arguss.lenses._osv_client import OsvClient


@pytest.mark.integration
def test_lodash_old_version_has_known_vulns(tmp_path: Path) -> None:
    """lodash@4.17.20 has known CVEs — verify query_single against the live API."""
    conn = get_connection(tmp_path / "test.db")
    init_db(conn)
    cache = Cache(conn)
    with OsvClient(cache=cache) as client:
        ids = client.query_single("lodash", "4.17.20")
    assert len(ids) >= 1
