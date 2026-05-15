#!/usr/bin/env python3
"""Refresh ``data/npm-top-1000-YYYY-MM.txt`` using the npm Registry search API.

The upstream `anvaka/npmrank`_ project does not publish versioned release assets
on GitHub (releases list is empty). This script builds a **practical** top list
for Arguss typosquat baselines: a curated seed of widely used packages plus
paginated search results for short two-letter queries (deduped, sorted).

.. _anvaka/npmrank: https://github.com/anvaka/npmrank

Run manually from the repo root (not in CI)::

    uv run python scripts/refresh-top-1000.py
    uv run python scripts/refresh-top-1000.py --output data/npm-top-1000-2026-08.txt

Requires network access to ``registry.npmjs.org``. Uses a conservative delay
between requests to reduce 429 rate limits.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx

# Repo root: parent of ``scripts/``
_REPO_ROOT = Path(__file__).resolve().parents[1]

_SEED_NAMES = (
    "lodash",
    "express",
    "react",
    "typescript",
    "webpack",
    "axios",
    "moment",
    "chalk",
    "semver",
    "debug",
    "commander",
    "glob",
    "mkdirp",
    "rimraf",
    "uuid",
    "inherits",
    "fs-extra",
    "dotenv",
    "yargs",
    "minimist",
    "tslib",
    "class-validator",
    "rxjs",
    "babel-runtime",
    "core-js",
    "handlebars",
    "jquery",
    "async",
    "bluebird",
    "body-parser",
    "cors",
    "ws",
    "socket.io",
    "redis",
    "mongoose",
    "eslint",
    "prettier",
    "@types/node",
    "@babel/core",
    "@types/react",
)

# Two-letter substrings that match many high-traffic package names (npm search
# requires ``text`` length 2–64).
_SEARCH_QUERIES = (
    "co",
    "de",
    "in",
    "lo",
    "no",
    "on",
    "pr",
    "re",
    "te",
    "js",
    "ty",
    "es",
    "io",
    "ui",
    "go",
    "fi",
    "st",
    "at",
    "an",
    "ar",
)


def _user_agent() -> str:
    try:
        ver = importlib.metadata.version("arguss")
    except importlib.metadata.PackageNotFoundError:
        ver = "0.1.0"
    return f"arguss/{ver} (npm top-1000 refresh; +https://github.com/ajrosales-max/arguss)"


def _fetch_search_page(client: httpx.Client, text: str, start: int) -> dict[str, Any]:
    for attempt in range(8):
        r = client.get(
            "https://registry.npmjs.org/-/v1/search",
            params={"text": text, "size": 250, "from": start},
        )
        if r.status_code == 429:
            time.sleep(1.5 * (attempt + 1))
            continue
        r.raise_for_status()
        return cast(dict[str, Any], r.json())
    raise RuntimeError(f"npm search rate-limited (429) for text={text!r} from={start}")


def collect_unique_names(target: int = 1000) -> list[str]:
    """Return ``target`` unique package names, sorted lexicographically."""
    order: dict[str, None] = {}
    for n in _SEED_NAMES:
        order.setdefault(n, None)

    with httpx.Client(
        headers={"User-Agent": _user_agent()},
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
    ) as client:
        for q in _SEARCH_QUERIES:
            if len(order) >= target:
                break
            for start in range(0, 4000, 250):
                if len(order) >= target:
                    break
                data = _fetch_search_page(client, q, start)
                objs = data.get("objects") or []
                if not objs:
                    break
                for o in objs:
                    name = o.get("package", {}).get("name")
                    if isinstance(name, str) and name:
                        order.setdefault(name, None)
                time.sleep(0.55)
            time.sleep(0.75)

    if len(order) < target:
        print(
            f"warning: only collected {len(order)} unique names (target {target}); "
            "add more ``_SEARCH_QUERIES`` or widen pagination.",
            file=sys.stderr,
        )

    seed_set = set(_SEED_NAMES)
    all_sorted = sorted(order.keys())
    if len(all_sorted) <= target:
        return all_sorted

    picked: set[str] = set()
    for name in all_sorted:
        if name in seed_set:
            picked.add(name)
    for name in all_sorted:
        if len(picked) >= target:
            break
        if name not in seed_set:
            picked.add(name)
    return sorted(picked)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output path (default: data/npm-top-1000-YYYY-MM.txt under repo root)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of unique package names to retain (default: 1000)",
    )
    args = parser.parse_args()

    stamp = datetime.now(UTC).date().strftime("%Y-%m")

    out = args.output or (_REPO_ROOT / "data" / f"npm-top-1000-{stamp}.txt")
    out.parent.mkdir(parents=True, exist_ok=True)

    names = collect_unique_names(target=args.count)
    out.write_text("\n".join(names) + "\n", encoding="utf-8")
    print(f"Wrote {len(names)} package names to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
