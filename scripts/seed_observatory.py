#!/usr/bin/env python3
"""Offline Observatory seed: run real Mode A URL scans and write JSON summaries.

Runs a small curated discovery list through ``run_scan_from_url`` (same path as
the dashboard) and maps ``scan_counts`` / ``summary`` to Observatory seed rows.

Run manually from the repo root (not in CI)::

    uv run python scripts/seed_observatory.py
    uv run python scripts/seed_observatory.py --output data/observatory-seed.json

Requires network access to GitHub and OSV (and related lens endpoints).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from arguss.explanations.scan_cache import scan_input_hash
from arguss.web.url_scan import run_scan_from_url

_REPO_ROOT = Path(__file__).resolve().parents[1]

# owner, repo, git ref — curated Alpha-Omega / top-npm style targets with lockfiles
_DISCOVERY: tuple[tuple[str, str, str], ...] = (
    ("axios", "axios", "main"),
    ("moxystudio", "node-cross-spawn", "master"),
    ("node-fetch", "node-fetch", "main"),
    ("webpack", "webpack", "main"),
    ("eslint", "eslint", "main"),
    ("jestjs", "jest", "main"),
    ("tj", "commander.js", "master"),
    ("chalk", "chalk", "main"),
    ("babel", "babel", "main"),
    ("vitejs", "vite", "main"),
    ("prettier", "prettier", "main"),
    ("lodash", "lodash", "main"),
    ("vuejs", "core", "main"),
    ("motdotla", "dotenv", "master"),
    ("minimistjs", "minimist", "main"),
)

_SEED_VERSION = 1


def _is_no_lockfile_error(error: str | None) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return (
        "does not contain a package-lock.json" in lowered
        or "repository does not contain a package-lock" in lowered
    )


def _github_url(owner: str, repo: str) -> str:
    return f"https://github.com/{owner}/{repo}"


def _severity(counts: dict[str, Any], key: str) -> int:
    by_sev = counts.get("findings_by_severity")
    if not isinstance(by_sev, dict):
        return 0
    return int(by_sev.get(key) or 0)


def _zero_row(
    *,
    owner: str,
    repo: str,
    ref: str,
    error: str,
) -> dict[str, Any]:
    return {
        "name": repo,
        "owner": owner,
        "repo": repo,
        "ref": ref,
        "scanned_at": None,
        "crit_count": 0,
        "high_count": 0,
        "med_count": 0,
        "low_count": 0,
        "total_findings": 0,
        "kev_count": 0,
        "auto_fix_count": 0,
        "review_count": 0,
        "decline_count": 0,
        "scan_hash": None,
        "error": error,
    }


def _row_from_payload(
    *,
    owner: str,
    repo: str,
    ref: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    counts = payload.get("scan_counts")
    if not isinstance(counts, dict):
        counts = {}
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        summary = {}

    scan_meta = payload.get("scan_meta")
    scanned_at: str | None = None
    if isinstance(scan_meta, dict):
        raw = scan_meta.get("completed_at")
        if isinstance(raw, str) and raw:
            scanned_at = raw

    return {
        "name": repo,
        "owner": owner,
        "repo": repo,
        "ref": ref,
        "scanned_at": scanned_at,
        "crit_count": _severity(counts, "critical"),
        "high_count": _severity(counts, "high"),
        "med_count": _severity(counts, "medium"),
        "low_count": _severity(counts, "low"),
        "total_findings": int(counts.get("total_findings") or summary.get("total_findings") or 0),
        "kev_count": int(summary.get("kev_count") or 0),
        "auto_fix_count": int(counts.get("candidates_auto_merge") or 0),
        "review_count": int(counts.get("candidates_review_required") or 0),
        "decline_count": int(counts.get("candidates_decline") or 0),
        "scan_hash": scan_input_hash(payload),
        "error": None,
    }


async def _scan_one(owner: str, repo: str, ref: str) -> dict[str, Any]:
    url = _github_url(owner, repo)
    try:
        payload = await run_scan_from_url(url, ref=ref, mode="A")
    except Exception as exc:  # noqa: BLE001 — seed script records all failures
        return _zero_row(owner=owner, repo=repo, ref=ref, error=f"{type(exc).__name__}: {exc}")
    return _row_from_payload(owner=owner, repo=repo, ref=ref, payload=payload)


def _aggregate_stats(scans: list[dict[str, Any]]) -> dict[str, int]:
    ok = [s for s in scans if s.get("error") is None]
    return {
        "projects": len(ok),
        "total_crit": sum(int(s.get("crit_count") or 0) for s in ok),
        "total_kev": sum(int(s.get("kev_count") or 0) for s in ok),
        "total_auto": sum(int(s.get("auto_fix_count") or 0) for s in ok),
    }


async def _run_discovery() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for owner, repo, ref in _DISCOVERY:
        label = f"{owner}/{repo}@{ref}"
        print(f"Scanning {label} …", flush=True)
        row = await _scan_one(owner, repo, ref)
        if row["error"] and _is_no_lockfile_error(row["error"]):
            print(f"  SKIP (no lockfile): {row['error']}", file=sys.stderr)
            continue
        rows.append(row)
        if row["error"]:
            print(f"  FAILED: {row['error']}", file=sys.stderr)
        else:
            print(
                f"  OK: findings={row['total_findings']} "
                f"crit={row['crit_count']} high={row['high_count']} "
                f"kev={row['kev_count']} auto={row['auto_fix_count']} "
                f"hash={row['scan_hash'][:12]}…"
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output path (default: data/observatory-seed.json under repo root)",
    )
    args = parser.parse_args()

    out = args.output or (_REPO_ROOT / "data" / "observatory-seed.json")
    out.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    scans = asyncio.run(_run_discovery())
    stats = _aggregate_stats(scans)

    document: dict[str, Any] = {
        "version": _SEED_VERSION,
        "generated_at": generated_at,
        "last_refreshed": generated_at,
        "total_projects": stats["projects"],
        "scans": scans,
        "stats": stats,
    }

    out.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"\nWrote {len(scans)} scan rows to {out}")
    print(
        f"Stats: projects={stats['projects']} total_crit={stats['total_crit']} "
        f"total_kev={stats['total_kev']} total_auto={stats['total_auto']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
