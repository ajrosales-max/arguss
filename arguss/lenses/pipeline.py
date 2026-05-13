"""Pipeline configuration lens — GitHub Actions workflow analysis via zizmor.

WEEK 5: Replace fake data with real zizmor subprocess wrapper.
"""

from pathlib import Path

from arguss.core.models import Dependency, Finding, LensScore


class PipelineLens:
    """Scans GitHub Actions workflows for configuration risks."""

    def scan(self, project_path: str | Path) -> LensScore:
        """Return a LensScore for the project's .github/workflows directory.

        Currently returns hardcoded fake data for skeleton testing.
        """
        fake_dep = Dependency(
            name=".github/workflows/ci.yml",
            version="N/A",
            ecosystem="github-actions",
            direct=True,
        )

        fake_finding = Finding(
            dependency=fake_dep,
            lens="pipeline",
            severity="medium",
            score=50.0,
            title="Unpinned action reference",
            description=(
                "Fake pipeline finding for skeleton testing. "
                "Will be replaced with real zizmor output in Week 5."
            ),
            remediation="Pin actions to a specific SHA",
            source_url=None,
        )

        return LensScore(lens="pipeline", score=50.0, findings=[fake_finding])
