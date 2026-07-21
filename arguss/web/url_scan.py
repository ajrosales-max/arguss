"""Reusable Mode A URL scan pipeline for dashboard and permalink recovery."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.concurrency import run_in_threadpool

from arguss.core.parser import ParserError, parse_lockfile
from arguss.core.serialization import attach_executive_summary, finalize_scan_payload
from arguss.engine.propose import propose_fixes
from arguss.explanations.scan_cache import scan_input_hash
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.web.github_fetch import GitHubFetchError, fetch_repo_inputs
from arguss.web.github_url import (
    InvalidGitHubURLError,
    InvalidGitRefError,
    parse_github_url,
    validate_git_ref,
)
from arguss.web.scan_inputs import save_scan_inputs


def _lockfile_deps(lockfile_path: Path) -> list[Any]:
    try:
        return parse_lockfile(lockfile_path)
    except Exception:
        return []


def dep_counts(lockfile_path: Path) -> dict[str, int]:
    deps = _lockfile_deps(lockfile_path)
    return {
        "direct": sum(1 for dep in deps if dep.direct),
        "transitive": sum(1 for dep in deps if not dep.direct),
    }


def serialize_lockfile_deps(lockfile_path: Path) -> list[dict[str, Any]]:
    """Serialize parsed lockfile dependencies for cached scan responses."""
    return [
        {
            "package": dep.name,
            "version": dep.version,
            "is_direct": dep.direct,
            "install_key": dep.install_key,
            "parents": list(dep.parents),
            "path": list(dep.path),
        }
        for dep in _lockfile_deps(lockfile_path)
    ]


def attach_scan_deps(payload: dict[str, Any], lockfile_path: Path) -> None:
    """Attach the full dependency list to a scan payload before caching."""
    payload["deps"] = serialize_lockfile_deps(lockfile_path)


def build_scan_meta(
    *,
    repo_display: str,
    ref: str,
    mode: str,
    lockfile_path: Path,
) -> dict[str, Any]:
    return {
        "repo_display": repo_display,
        "ref": ref or "HEAD",
        "mode": mode,
        "completed_at": datetime.now(UTC).isoformat(),
        "dep_counts": dep_counts(lockfile_path),
    }


async def run_scan_from_url(
    url: str,
    *,
    ref: str = "HEAD",
    mode: str = "A",
    db_path: Path | None = None,
    persist_inputs: bool = False,
) -> dict[str, Any]:
    """Run the URL scan pipeline and return the enriched cached payload shape."""
    parsed = parse_github_url(url)
    validate_git_ref(ref)

    with tempfile.TemporaryDirectory(prefix="arguss-scan-") as tmp:
        tmp_path = Path(tmp)
        clone_target = tmp_path / parsed.name

        inputs = await fetch_repo_inputs(
            owner=parsed.owner,
            repo=parsed.name,
            ref=ref,
            dest=clone_target,
        )

        work_tree = inputs.work_tree
        lockfile_path = inputs.lockfile_path

        report = await run_in_threadpool(
            propose_fixes,
            lockfile_path,
            work_tree,
            repo_identity=parsed.repo_identity,
        )

        payload = finalize_scan_payload(
            report,
            lockfile_path,
            scan_meta=build_scan_meta(
                repo_display=f"{parsed.owner}/{parsed.name}",
                ref=ref,
                mode=mode,
                lockfile_path=lockfile_path,
            ),
        )
        enriched = attach_executive_summary(payload)
        scan_hash = scan_input_hash(enriched)

        if persist_inputs and db_path is not None and mode in ("A", "C"):
            save_scan_inputs(scan_hash, mode, url, ref, db_path)

        return enriched


__all__ = [
    "GitHubFetchError",
    "InvalidGitHubURLError",
    "InvalidGitRefError",
    "ParserError",
    "ZizmorClientError",
    "attach_scan_deps",
    "build_scan_meta",
    "dep_counts",
    "run_scan_from_url",
    "serialize_lockfile_deps",
]
