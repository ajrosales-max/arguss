"""Reusable Mode A URL scan pipeline for dashboard and permalink recovery."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.concurrency import run_in_threadpool

from arguss.core.parser import ParserError, parse_lockfile
from arguss.core.serialization import attach_executive_summary, proposal_report_payload
from arguss.engine.propose import propose_fixes
from arguss.explanations.scan_cache import scan_input_hash
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.web.github_fetch import GitHubFetchError, fetch_repo_inputs
from arguss.web.github_url import InvalidGitHubURLError, parse_github_url
from arguss.web.scan_inputs import save_scan_inputs


def dep_counts(lockfile_path: Path) -> dict[str, int]:
    try:
        deps = parse_lockfile(lockfile_path)
    except Exception:
        return {"direct": 0, "transitive": 0}
    return {
        "direct": sum(1 for dep in deps if dep.direct),
        "transitive": sum(1 for dep in deps if not dep.direct),
    }


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

        payload = proposal_report_payload(report)
        payload["scan_meta"] = build_scan_meta(
            repo_display=f"{parsed.owner}/{parsed.name}",
            ref=ref,
            mode=mode,
            lockfile_path=lockfile_path,
        )
        enriched = attach_executive_summary(payload)
        scan_hash = scan_input_hash(enriched)

        if persist_inputs and db_path is not None and mode in ("A", "C"):
            save_scan_inputs(scan_hash, mode, url, ref, db_path)

        return enriched


__all__ = [
    "GitHubFetchError",
    "InvalidGitHubURLError",
    "ParserError",
    "ZizmorClientError",
    "build_scan_meta",
    "dep_counts",
    "run_scan_from_url",
]
