#!/usr/bin/env python3
"""Refresh ``data/npm-top-1000-YYYY-MM.txt`` from real download-ranked sources.

Replaces the npm-search-based approach, which ranked by *search relevance*
for two-letter substrings — not by downloads. That produced a list dominated
by ``co-*`` packages and missing most genuinely top packages (``ms``,
``picomatch``, ``lru-cache``, ``type-fest``, ...).

Sources, in priority order:

1. **npm-high-impact** (wooorm/npm-high-impact) — published as an npm package,
   so it is fetched from ``registry.npmjs.org`` (a domain Arguss already
   talks to; no new egress). Built from ecosyste.ms download counts, updated
   regularly. The tarball is extracted locally and the public ``npmTopDownloads``
   export is read via ``node`` (optional; no hard dependency on Node).
2. **npm-rank** (tristan-f-r/npm-rank) — top-10000 list rebuilt by GitHub
   Actions, stable release asset URL. Fallback if (1) fails (including when
   ``node`` is not on ``PATH``).

Run manually from the repo root (not in CI)::

    uv run python scripts/refresh-top-1000.py
    uv run python scripts/refresh-top-1000.py --output data/npm-top-1000-2026-08.txt
    uv run python scripts/refresh-top-1000.py --source npm-rank
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

_REPO_ROOT = Path(__file__).resolve().parents[1]

_NPM_HIGH_IMPACT_META = "https://registry.npmjs.org/npm-high-impact/latest"
_NPM_RANK_RAW = "https://github.com/tristan-f-r/npm-rank/releases/download/latest/raw.json"

_NODE_EXPORT_JS = (
    "import { npmTopDownloads } from './index.js';"
    "process.stdout.write(JSON.stringify(npmTopDownloads));"
)


def _client() -> httpx.Client:
    return httpx.Client(
        headers={
            "User-Agent": "arguss/refresh-top-1000 (+https://github.com/ajrosales-max/arguss)"
        },
        timeout=httpx.Timeout(60.0, connect=10.0),
        follow_redirects=True,
    )


def _read_npm_top_downloads_via_node(package_dir: Path) -> list[str]:
    """Import ``npmTopDownloads`` from the package's public entry via Node."""
    if shutil.which("node") is None:
        raise RuntimeError("node not found on PATH")

    result = subprocess.run(
        ["node", "--input-type=module", "-e", _NODE_EXPORT_JS],
        cwd=str(package_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "(no stderr)"
        raise RuntimeError(f"node export failed (exit {result.returncode}): {stderr}")

    try:
        names = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"node export returned invalid JSON: {exc}") from exc

    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise RuntimeError("npmTopDownloads export is not a list of strings")
    return names


def from_npm_high_impact(client: httpx.Client, count: int) -> list[str]:
    """Top ``count`` package names by downloads, via the npm-high-impact tarball."""
    meta = client.get(_NPM_HIGH_IMPACT_META)
    meta.raise_for_status()
    tarball_url = meta.json()["dist"]["tarball"]

    tgz = client.get(tarball_url)
    tgz.raise_for_status()

    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(fileobj=io.BytesIO(tgz.content), mode="r:gz") as tf:
            tf.extractall(tmp, filter="data")
        package_dir = Path(tmp) / "package"
        if not (package_dir / "index.js").is_file():
            raise RuntimeError("index.js missing from npm-high-impact tarball")

        names = _read_npm_top_downloads_via_node(package_dir)

    if len(names) < count:
        raise RuntimeError(f"only {len(names)} names exported (need {count})")
    return names[:count]


def from_npm_rank(client: httpx.Client, count: int) -> list[str]:
    """Top ``count`` package names from npm-rank's raw.json release asset."""
    r = client.get(_NPM_RANK_RAW)
    r.raise_for_status()
    data = json.loads(r.content)
    names = [p["name"] for p in data if isinstance(p.get("name"), str)]
    if len(names) < count:
        raise RuntimeError(f"only {len(names)} names in npm-rank data (need {count})")
    return names[:count]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument(
        "--source",
        choices=["npm-high-impact", "npm-rank", "auto"],
        default="auto",
        help="Data source (default: npm-high-impact, falling back to npm-rank)",
    )
    args = parser.parse_args()

    stamp = datetime.now(UTC).date().strftime("%Y-%m")
    out = args.output or (_REPO_ROOT / "data" / f"npm-top-1000-{stamp}.txt")
    out.parent.mkdir(parents=True, exist_ok=True)

    with _client() as client:
        names: list[str] | None = None
        errors: list[str] = []
        sources = ["npm-high-impact", "npm-rank"] if args.source == "auto" else [args.source]
        for source in sources:
            try:
                if source == "npm-high-impact":
                    names = from_npm_high_impact(client, args.count)
                else:
                    names = from_npm_rank(client, args.count)
                print(f"Source: {source}")
                break
            except Exception as exc:  # noqa: BLE001 - report and try fallback
                errors.append(f"{source}: {exc}")

    if names is None:
        print("All sources failed:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1

    # Preserve rank order — do NOT sort. Rank order lets typosquat checks
    # weight by popularity later if desired. No header lines: the file format
    # stays one-package-per-line so the existing loader needs no changes.
    out.write_text("\n".join(names) + "\n", encoding="utf-8")
    print(f"Wrote {len(names)} package names to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
