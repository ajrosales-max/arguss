"""Integration tests for the vulnerability lens against real OSV.dev.

These tests hit the live OSV API. They are skipped by default and run
separately via ``pytest -m integration``. They prove the full lens pipeline
(parser → OSV client → CVSS parsing → finding generation) works against
real production data.
"""

from __future__ import annotations

import pytest

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import Dependency
from arguss.lenses._osv_client import OsvClient
from arguss.lenses.vulnerability import VulnerabilityLens


@pytest.mark.integration
def test_lens_finds_real_cves_against_known_vulnerable_deps() -> None:
    """Scanning a known-vulnerable dep produces real CVE findings.

    Uses lodash@4.17.20 (multiple known CVEs) and a clean reference dep
    (``is-array@1.0.1``) to verify both the positive and negative cases.
    """
    conn = get_connection(":memory:")
    init_db(conn)
    cache = Cache(conn)

    with OsvClient(cache=cache) as osv:
        lens = VulnerabilityLens(cache=cache, osv_client=osv)

        deps = [
            Dependency(name="lodash", version="4.17.20", ecosystem="npm", direct=True),
            Dependency(name="is-array", version="1.0.1", ecosystem="npm", direct=True),
        ]

        score = lens.scan(deps)

    assert score.score > 0, "Expected real CVE findings from lodash@4.17.20"
    assert len(score.findings) >= 1

    lodash_findings = [f for f in score.findings if f.dependency.name == "lodash"]
    assert len(lodash_findings) >= 1

    assert score.score == max(f.score for f in score.findings)

    findings_with_advice = [
        f for f in score.findings if f.remediation and "Upgrade lodash" in f.remediation
    ]
    assert len(findings_with_advice) >= 1
