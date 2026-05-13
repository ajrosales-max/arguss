"""Arguss CLI entry point.

Usage:
    arguss scan ./path/to/project
"""

import json
import sys
from pathlib import Path

import typer
from rich.console import Console

from arguss.core.models import Dependency
from arguss.lenses import PipelineLens, TrustLens, VulnerabilityLens
from arguss.scoring import compute_project_score

app = typer.Typer(
    name="arguss",
    help="Secure CI/CD & Software Supply Chain Risk Analyzer",
    no_args_is_help=True,
)
console = Console()

@app.callback()
def _callback() -> None:
    """Required to force subcommand invocation pattern."""

@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to project root or package-lock.json"),
    no_ai: bool = typer.Option(  # noqa: ARG001
        False,
        "--no-ai",
        help="Skip AI-assisted remediation explanations (offline-safe mode).",
    ),
    output_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format: json or pretty.",
    ),
) -> None:
    """Scan a project for supply chain risks."""
    project_path = Path(path).resolve()
    if not project_path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {project_path}")
        sys.exit(1)

    # WEEK 3: Replace with real parser.parse_lockfile(project_path)
    deps = _fake_deps()

    cve = VulnerabilityLens().scan(deps)
    trust = TrustLens().scan(deps)
    pipeline = PipelineLens().scan(project_path)

    score = compute_project_score(
        cve=cve,
        trust=trust,
        pipeline=pipeline,
        project_path=str(project_path),
    )

    if output_format == "pretty":
        _print_pretty(score)
    else:
        print(score.model_dump_json(indent=2))


def _fake_deps() -> list[Dependency]:
    """Return hardcoded dependency list for skeleton testing.

    WEEK 3: Delete this. Replace with real parser.
    """
    return [
        Dependency(
            name="fake-package",
            version="1.0.0",
            ecosystem="npm",
            direct=True,
            path=["root", "fake-package"],
            parents=["root"],
        ),
        Dependency(
            name="fake-transitive",
            version="2.3.1",
            ecosystem="npm",
            direct=False,
            path=["root", "fake-package", "fake-transitive"],
            parents=["fake-package"],
        ),
    ]


def _print_pretty(score) -> None:  # type: ignore[no-untyped-def]
    """Pretty-print a ProjectScore to the terminal."""
    console.print(f"\n[bold]Arguss Scan Result[/bold] — {score.project_path}")
    console.print(f"Overall risk: [bold]{score.overall:.1f}[/bold] / 100\n")
    for lens_name, lens in score.lens_scores.items():
        console.print(f"  [cyan]{lens_name}[/cyan]: {lens.score:.1f} ({len(lens.findings)} findings)")


if __name__ == "__main__":
    app()
