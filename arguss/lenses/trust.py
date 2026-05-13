"""Trust signal lens — maintainer health, typosquatting, OpenSSF Scorecard.

WEEK 4: Replace fake data with npm registry + typosquat + Scorecard integration.
"""

from arguss.core.models import Dependency, Finding, LensScore


class TrustLens:
    """Scans dependencies for package trust signals."""

    def scan(self, deps: list[Dependency]) -> LensScore:
        """Return a LensScore for the given dependencies.

        Currently returns hardcoded fake data for skeleton testing.
        """
        if not deps:
            return LensScore(lens="trust", score=0.0, findings=[])

        fake_finding = Finding(
            dependency=deps[0],
            lens="trust",
            severity="medium",
            score=40.0,
            title=f"Single-maintainer package: {deps[0].name}",
            description=(
                "Fake trust signal for skeleton testing. "
                "Will be replaced with real npm registry data in Week 4."
            ),
            remediation="Review maintainer history before upgrading",
            source_url=f"https://www.npmjs.com/package/{deps[0].name}",
        )

        return LensScore(lens="trust", score=40.0, findings=[fake_finding])
