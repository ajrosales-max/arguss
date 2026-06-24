#!/usr/bin/env python3
"""Offline Observatory seed: shallow-clone repos, generate lockfiles, and scan.

Runs a curated discovery list: for each GitHub (owner, repo, ref), shallow-clone
the repo, generate ``package-lock.json`` from ``package.json``, then run the same
``propose_fixes`` → ``finalize_scan_payload`` chain as Mode A scans.

Run manually from the repo root (not in CI)::

    uv run python scripts/seed_observatory.py
    uv run python scripts/seed_observatory.py --output data/observatory-seed.json

Requires ``git`` and ``npm`` on PATH, network access to GitHub and OSV.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from arguss.core.serialization import finalize_scan_payload, json_default
from arguss.engine.propose import propose_fixes
from arguss.explanations.scan_cache import scan_input_hash
from arguss.web import observatory_seed
from arguss.web.url_scan import build_scan_meta

_REPO_ROOT = Path(__file__).resolve().parents[1]

# owner, repo, git ref — curated Alpha-Omega / top-npm style targets
_DISCOVERY: tuple[tuple[str, str, str], ...] = (
    ("axios", "axios", "main"),
    ("moxystudio", "node-cross-spawn", "master"),
    ("expressjs", "express", "master"),
    ("node-fetch", "node-fetch", "main"),
    ("npm", "node-semver", "main"),
    ("webpack", "webpack", "main"),
    ("vercel", "next.js", "canary"),
    ("eslint", "eslint", "main"),
    ("jestjs", "jest", "main"),
    ("tj", "commander.js", "master"),
    ("motdotla", "dotenv", "master"),
    ("minimistjs", "minimist", "main"),
    ("chalk", "chalk", "main"),
    ("babel", "babel", "main"),
    ("vitejs", "vite", "main"),
    ("prettier", "prettier", "main"),
    ("lodash", "lodash", "main"),
    ("vuejs", "core", "main"),
    ("microsoft", "TypeScript", "main"),
    ("facebook", "react", "main"),
)

_SEED_VERSION = 1


def _github_url(owner: str, repo: str) -> str:
    return f"https://github.com/{owner}/{repo}"


def _shallow_clone(owner: str, repo: str, ref: str) -> Path:
    """Shallow-clone a GitHub repo at ref into a fresh temp directory."""
    dest = Path(tempfile.mkdtemp(prefix="arguss-observatory-"))
    url = _github_url(owner, repo)
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", ref, url, str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def _generate_lockfile(repo_path: Path) -> Path:
    """Generate package-lock.json from package.json without installing node_modules."""
    lockfile_path = repo_path / "package-lock.json"
    subprocess.run(
        [
            "npm",
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
        cwd=repo_path,
        check=True,
        capture_output=True,
        text=True,
    )
    if not lockfile_path.is_file():
        msg = "package-lock.json not created after npm install --package-lock-only"
        raise FileNotFoundError(msg)
    return lockfile_path


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


def _persist_report(payload: dict[str, Any], *, reports_dir: Path | None = None) -> str:
    """Write a finalized scan payload to ``data/observatory-reports/{hash}.json``."""
    scan_hash = scan_input_hash(payload)
    out_dir = reports_dir or observatory_seed.default_reports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / f"{scan_hash}.json"
    report_path.write_text(
        json.dumps(payload, indent=2, default=json_default) + "\n",
        encoding="utf-8",
    )
    return scan_hash


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


def _scan_one(owner: str, repo: str, ref: str) -> dict[str, Any]:
    clone: Path | None = None
    try:
        clone = _shallow_clone(owner, repo, ref)
        lockfile_path = _generate_lockfile(clone)
        report = propose_fixes(
            lockfile_path,
            repo_path=clone,
            repo_identity=f"{owner}/{repo}",
        )
        payload = finalize_scan_payload(
            report,
            lockfile_path,
            scan_meta=build_scan_meta(
                repo_display=f"{owner}/{repo}",
                ref=ref,
                mode="A",
                lockfile_path=lockfile_path,
            ),
        )
        _persist_report(payload)
        return _row_from_payload(owner=owner, repo=repo, ref=ref, payload=payload)
    except Exception as exc:  # noqa: BLE001 — seed script records all failures
        return _zero_row(owner=owner, repo=repo, ref=ref, error=f"{type(exc).__name__}: {exc}")
    finally:
        if clone is not None:
            shutil.rmtree(clone, ignore_errors=True)


def _aggregate_stats(scans: list[dict[str, Any]]) -> dict[str, int]:
    ok = [s for s in scans if s.get("error") is None]
    return {
        "projects": len(ok),
        "total_crit": sum(int(s.get("crit_count") or 0) for s in ok),
        "total_kev": sum(int(s.get("kev_count") or 0) for s in ok),
        "total_auto": sum(int(s.get("auto_fix_count") or 0) for s in ok),
    }


def _run_discovery() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for owner, repo, ref in _DISCOVERY:
        label = f"{owner}/{repo}@{ref}"
        print(f"Scanning {label} …", flush=True)
        row = _scan_one(owner, repo, ref)
        if row["error"] is not None:
            print(f"  SKIP: {row['error']}", file=sys.stderr)
            continue
        rows.append(row)
        print(
            f"  OK: findings={row['total_findings']} "
            f"crit={row['crit_count']} high={row['high_count']} "
            f"kev={row['kev_count']} auto={row['auto_fix_count']} "
            f"hash={row['scan_hash'][:12]}…"
        )
    return rows


def _prune_orphan_reports(
    scans: list[dict[str, Any]],
    *,
    reports_dir: Path | None = None,
) -> int:
    """Delete report files whose hash is not in the successful scan row set."""
    out_dir = reports_dir or observatory_seed.default_reports_dir()
    if not out_dir.is_dir():
        return 0
    keep = {str(row["scan_hash"]) for row in scans if row.get("scan_hash")}
    removed = 0
    for path in out_dir.glob("*.json"):
        if path.stem not in keep:
            path.unlink()
            removed += 1
    return removed


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
    scans = _run_discovery()
    if not scans:
        print(
            "ERROR: discovery produced zero successful scans; "
            "leaving observatory-seed.json and report artifacts unchanged.",
            file=sys.stderr,
        )
        return 1

    _prune_orphan_reports(scans)
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
