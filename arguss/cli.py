"""Arguss CLI entry point.

Usage:
    arguss scan ./path/to/project
    arguss propose-fixes ./path/to/package-lock.json
"""

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.parser import ParserError, lockfile_project_for_sbom, parse_lockfile
from arguss.core.sbom import generate_sbom
from arguss.core.serialization import finalize_scan_payload, json_default
from arguss.engine.propose import propose_fixes
from arguss.jobs.top_1000_sweep import run_sweep
from arguss.lenses import PipelineLens, TrustLens, VulnerabilityLens
from arguss.lenses._osv_client import OsvError
from arguss.lenses._trust_client import TrustClientError
from arguss.lenses._zizmor_client import ZizmorClient, ZizmorClientError
from arguss.lenses.pipeline import fetch_pipeline_snapshot
from arguss.lenses.trust import fetch_delta, fetch_snapshot
from arguss.logging_config import configure_logging
from arguss.scoring import compute_project_score
from arguss.settings import settings, validate_settings

app = typer.Typer(
    name="arguss",
    help="Secure CI/CD & Software Supply Chain Risk Analyzer",
    no_args_is_help=True,
)
console = Console()
_stderr_console = Console(stderr=True)


@app.callback()
def _callback() -> None:
    """Required to force subcommand invocation pattern."""
    configure_logging(settings.log_level)


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

    repo_root = project_path.parent if project_path.is_file() else project_path

    cve = VulnerabilityLens(cache=cache).scan(deps)
    trust = TrustLens(cache=cache).scan(deps)
    pipeline = PipelineLens(repo_path=repo_root).scan(deps)

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

    _print_propose_fixes_hint()


@app.command(name="propose-fixes")
def propose_fixes_cmd(
    lockfile_path: Annotated[
        Path,
        typer.Argument(
            ...,
            help="Path to package-lock.json",
            exists=True,
            dir_okay=False,
            file_okay=True,
        ),
    ],
    repo_path: Annotated[
        Path | None,
        typer.Option(
            "--repo-path",
            help="Path to the repository root (default: lockfile's parent directory)",
            exists=True,
            file_okay=False,
            dir_okay=True,
        ),
    ] = None,
) -> None:
    """Generate fix proposals for vulnerabilities in a lockfile.

    Reads the lockfile, finds vulnerabilities, generates remediation candidates,
    evaluates each one through the fix-confidence engine, and prints the
    structured results as JSON.
    """
    try:
        report = propose_fixes(lockfile_path, repo_path)
    except ParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except ZizmorClientError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    payload = finalize_scan_payload(report, lockfile_path)
    print(json.dumps(payload, indent=2, default=json_default))


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

    payload = asdict(snap)
    print(json.dumps(payload, indent=2, default=json_default))


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

    payload = asdict(delta)
    print(json.dumps(payload, indent=2, default=json_default))


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


@app.command(name="sweep-top-1000")
def sweep_top_1000(
    latest: bool = typer.Option(
        True,
        "--latest/--no-latest",
        help="Run pass 2: npm latest version + versioned OSV query.",
    ),
) -> None:
    """Precompute OSV vulnerability data for the download-ranked top-1000 npm list."""
    validate_settings()
    try:
        count = run_sweep(settings.db_path, latest=latest)
    except OsvError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    console.print(f"Swept {count} packages into top_packages.")


@app.command()
def pipeline_snapshot(
    repo_path: Annotated[
        Path,
        typer.Argument(
            ...,
            help="Path to a repository root (containing package.json, .github/, etc.)",
            exists=True,
            file_okay=False,
            dir_okay=True,
        ),
    ],
) -> None:
    """Print a PipelineSnapshot for a repository, for development inspection."""
    try:
        snapshot = fetch_pipeline_snapshot(repo_path)
    except ZizmorClientError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    payload = asdict(snapshot)
    print(json.dumps(payload, indent=2, default=json_default))


def _print_propose_fixes_hint() -> None:
    """Hint on stderr so default JSON scan output remains machine-parseable on stdout."""
    _stderr_console.print(
        "[dim]For actionable remediation proposals, run: "
        "arguss propose-fixes <path-to-package-lock.json>[/dim]",
    )


def _print_pretty(score) -> None:  # type: ignore[no-untyped-def]
    """Pretty-print a ProjectScore to the terminal."""
    console.print(f"\n[bold]Arguss Scan Result[/bold] - {score.project_path}")
    console.print(f"Overall risk: [bold]{score.overall:.1f}[/bold] / 100\n")
    for lens_name, lens in score.lens_scores.items():
        console.print(
            f"  [cyan]{lens_name}[/cyan]: {lens.score:.1f} ({len(lens.findings)} findings)"
        )


if __name__ == "__main__":
    app()
