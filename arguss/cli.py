"""Arguss CLI entry point.

Usage:
    arguss scan ./path/to/project
"""

import json
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import TrustFlag
from arguss.core.parser import ParserError, lockfile_project_for_sbom, parse_lockfile
from arguss.core.sbom import generate_sbom
from arguss.lenses import PipelineLens, TrustLens, VulnerabilityLens
from arguss.lenses._trust_client import TrustClientError
from arguss.lenses._zizmor_client import ZizmorClient, ZizmorClientError
from arguss.lenses.trust import fetch_delta, fetch_snapshot
from arguss.scoring import compute_project_score
from arguss.settings import settings, validate_settings

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

    try:
        deps = parse_lockfile(project_path)
    except ParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    validate_settings()
    conn = get_connection(settings.db_path)
    init_db(conn)
    cache = Cache(conn)

    cve = VulnerabilityLens(cache=cache).scan(deps)
    trust = TrustLens(cache=cache).scan(deps)
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


@app.command()
def sbom(
    path: str = typer.Argument(..., help="Path to project root or package-lock.json"),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write SBOM to this file. Default: stdout.",
    ),
    project_name: str | None = typer.Option(
        None,
        "--name",
        help="Project name for the SBOM root component. Default: directory name.",
    ),
) -> None:
    """Generate a CycloneDX 1.7 SBOM for the given project."""
    project_path = Path(path).resolve()
    if not project_path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {project_path}")
        sys.exit(1)

    try:
        deps = parse_lockfile(project_path)
        pname, pver = lockfile_project_for_sbom(project_path, project_name_override=project_name)
    except ParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    bom = generate_sbom(deps, pname, pver)
    text = json.dumps(bom, indent=2)

    if output:
        out_path = Path(output).expanduser()
        out_path.write_text(text + "\n", encoding="utf-8")
        console.print(f"SBOM written to {out_path}")
    else:
        print(text)


@app.command()
def trust_snapshot(
    package: str = typer.Argument(..., help="Package name, e.g. 'express' or '@types/node'"),
    version: str = typer.Argument(..., help="Specific version, e.g. '4.17.21'"),
) -> None:
    """Print a TrustSnapshot for a specific package@version, for development inspection."""
    validate_settings()
    conn = get_connection(settings.db_path)
    init_db(conn)
    cache = Cache(conn)
    try:
        snap = fetch_snapshot(cache, package, version)
    except TrustClientError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    finally:
        conn.close()

    def _json_default(obj: object) -> object:
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    payload = asdict(snap)
    print(json.dumps(payload, indent=2, default=_json_default))


@app.command()
def trust_delta(
    package: str = typer.Argument(..., help="Package name, e.g. 'express' or '@types/node'"),
    from_version: str = typer.Argument(..., help="The 'from' version, e.g. '4.17.20'"),
    to_version: str = typer.Argument(..., help="The 'to' version, e.g. '4.17.21'"),
) -> None:
    """Print a TrustDelta between two package versions, for development inspection."""
    validate_settings()
    conn = get_connection(settings.db_path)
    init_db(conn)
    cache = Cache(conn)
    try:
        delta = fetch_delta(cache, package, from_version, to_version)
    except TrustClientError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    finally:
        conn.close()

    def _json_default(obj: object) -> object:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, TrustFlag):
            return obj.value
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    payload = asdict(delta)
    print(json.dumps(payload, indent=2, default=_json_default))


@app.command()
def zizmor_scan(
    workflows_dir: Annotated[
        Path,
        typer.Argument(
            ...,
            help="Path to a .github/workflows/ directory or a specific workflow file",
            exists=True,
        ),
    ],
) -> None:
    """Run zizmor against a workflows directory and print normalized findings as JSON."""
    try:
        client = ZizmorClient()
        findings = client.scan_workflows(workflows_dir)
    except ZizmorClientError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    payload = [asdict(f) for f in findings]
    print(json.dumps(payload, indent=2))


def _print_pretty(score) -> None:  # type: ignore[no-untyped-def]
    """Pretty-print a ProjectScore to the terminal."""
    console.print(f"\n[bold]Arguss Scan Result[/bold] — {score.project_path}")
    console.print(f"Overall risk: [bold]{score.overall:.1f}[/bold] / 100\n")
    for lens_name, lens in score.lens_scores.items():
        console.print(
            f"  [cyan]{lens_name}[/cyan]: {lens.score:.1f} ({len(lens.findings)} findings)"
        )


if __name__ == "__main__":
    app()
