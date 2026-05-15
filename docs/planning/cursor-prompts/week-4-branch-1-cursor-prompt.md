# Cursor prompt — Week 4, Branch 1: `feature/trust-snapshot`

This is the first of two branches for the Week 4 trust signal lens. Goal: build the npm registry client and the `TrustSnapshot` data model, with the snapshot fetcher and a CLI inspection command. **This branch does not yet wire into the unified scoring system** — the trust lens remains fake until Branch 2 (`feature/trust-delta`) lands.

**Branch name:** `feature/trust-snapshot`

**Estimated time:** 2–3 days of focused work.

**Scope discipline:** This branch produces a working `arguss trust-snapshot <package>@<version>` CLI command that prints a populated `TrustSnapshot`. Everything else is Branch 2 or later.

---

## Before pasting into Cursor

Start from clean main with the pivot docs merged:

```bash
git checkout main
git pull
git log --oneline -10              # verify docs/pivot-marker is merged
git checkout -b feature/trust-snapshot

# Verify existing tests pass
uv run pytest
```

If anything is red, fix before continuing. Don't build new code on top of a broken main.

---

## The prompt to paste into Cursor

I'm working on Week 4 of the Arguss capstone — the trust signal lens, Branch 1 of 2. Arguss is now an autonomous remediation agent for npm supply chain vulnerabilities (see `docs/planning/pivot-rationale.md` and `docs/planning/project-overview.md` for context). The trust lens has two consumers: the existing PRS dashboard (which wants a single subscore) and the Week 6 fix-confidence engine (which wants a delta-with-veto signal between two versions). Branch 1 builds the snapshot infrastructure; Branch 2 will build the delta and wire into the lens system.

## What to build

### 1. The npm registry client — `arguss/lenses/_trust_client.py`

A new HTTP client for the npm registry, parallel to the existing OSV client at `arguss/lenses/_osv_client.py`. Follow the OSV client's structural patterns: httpx-based, configurable timeout, retry on transient failures, SQLite cache layer, error parsing helper.

Public functions:

```python
def fetch_packument(package: str) -> dict:
    """Fetch the full packument from https://registry.npmjs.org/{package}.

    Cache TTL: 24 hours (snapshots are immutable per version but the *set of
    versions* and *current maintainer list* can shift retroactively).

    Returns the parsed JSON. Raises TrustClientError on 4xx/5xx or network
    failures with a clear error message including the package name.
    """

def fetch_weekly_downloads(package: str) -> int | None:
    """Fetch last-week download count from https://api.npmjs.org/downloads/point/last-week/{package}.

    Cache TTL: 24 hours.

    Returns the download count or None if the endpoint reports the package
    has no download data (some packages return {"downloads": 0} which we
    treat as a real zero, distinct from None which means "data unavailable").
    """
```

Implementation notes:

- Use `httpx.Client` with a `User-Agent: arguss/<version>` header. The npm registry rejects unmarked clients with 405.
- Default timeout: 10 seconds for packument, 5 seconds for downloads.
- The packument endpoint returns a large JSON document (sometimes >1MB for popular packages). Stream it but parse it whole — we need maintainer history across all versions.
- Scoped packages: `@scope/name` must be URL-encoded as `@scope%2Fname` in the registry path. Use `urllib.parse.quote(package, safe='@')`.
- Cache key for packument: `npm:packument:{package}`. Cache key for downloads: `npm:downloads:last-week:{package}`.
- Cache implementation: extend or mirror the existing SQLite cache used by the OSV client. Reuse the same database file. Add a `trust_client_cache` table or namespace within the existing cache table if that's how the OSV client did it.

### 2. The TrustSnapshot model — `arguss/models.py`

Add to the existing models file (do NOT duplicate existing models — view the file first):

```python
from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True)
class TrustSnapshot:
    """Static trust profile for a single package@version, captured at a point in time.

    Snapshots are the input to TrustDelta (Branch 2). The subscore field is
    consumed by the existing PRS path; the structured fields are consumed by
    the Week 6 fix-confidence engine.
    """
    package: str
    version: str
    captured_at: datetime

    # Maintainer data (from npm registry)
    maintainer_count: int
    maintainer_logins: tuple[str, ...]   # sorted, for set comparison and frozen-dataclass compatibility

    # Publishing cadence (from npm registry version history)
    published_at: datetime
    days_since_previous_publish: int | None    # None if this is the first published version

    # Typosquat signals (computed)
    typosquat_distance: int | None       # min Levenshtein to top-1000 packages
    typosquat_nearest: str | None        # name of the nearest top-1000 match (None if package IS in top-1000)

    # Population
    weekly_downloads: int | None

    # Raw subscore for the existing PRS path (0-100, higher = riskier)
    subscore: int
```

### 3. The snapshot fetcher — `arguss/lenses/trust.py`

The orchestration layer that combines registry data, downloads data, and typosquat distance into a `TrustSnapshot`:

```python
def fetch_snapshot(package: str, version: str) -> TrustSnapshot:
    """Build a TrustSnapshot for a specific package@version.

    Fetches the packument, locates the version metadata, computes typosquat
    distance against the bundled top-1000 list, fetches weekly downloads,
    and computes a subscore.

    Raises TrustClientError if the package doesn't exist or the version
    isn't in the packument.
    """
```

The subscore computation (0-100, higher = riskier) for v1 should be a simple weighted combination of:

- **Sole maintainer (single maintainer in the list):** +30
- **Very recent first publish (package itself is <90 days old):** +20
- **Typosquat distance 1–2 from a top-1000 package (and not itself in top-1000):** +25 for distance 1, +15 for distance 2
- **Low weekly downloads (<1000 if data available):** +10

Cap at 100. The exact weights are v1 defaults we'll tune in Week 11 evaluation; design the function so the weights are easy to adjust (a `_TrustSubscoreWeights` dataclass at module level is fine).

### 4. The typosquat distance calculator — inside `arguss/lenses/trust.py`

Use Python's standard library `difflib` for Levenshtein-like distance, OR implement a simple Levenshtein function — your call, but pick one and stick with it. Levenshtein is unambiguous and well-defined; if `difflib`'s SequenceMatcher gives a normalized similarity ratio instead, do the explicit Levenshtein implementation to keep the distance metric concrete.

```python
def _typosquat_distance(name: str, top_1000: frozenset[str]) -> tuple[int | None, str | None]:
    """Return (min_distance, nearest_match) against the top-1000 set.

    If name is itself in top-1000, returns (0, name). Otherwise returns the
    minimum Levenshtein distance and the package name that achieves it.

    For efficiency, return early on exact match. For top-1000 we scan all
    1000 entries — Levenshtein of short strings is cheap, and the comparison
    is bounded.
    """
```

### 5. The top-1000 list — committed as a fixture

Pull a snapshot from npmrank (https://github.com/anvaka/npmrank/releases — pick the most recent versioned release at time of writing). Commit it as:

```
data/npm-top-1000-2026-05.txt    # one package name per line, sorted
```

Plus a refresh script at `scripts/refresh-top-1000.py` that downloads the latest npmrank release and writes a new file with the current YYYY-MM stamp. The refresh script is documented in a `data/README.md` but is NOT run in CI — it's a one-time chore the team runs once per semester.

The trust lens loads the top-1000 list at module import time and caches it as a `frozenset[str]` for O(1) lookup. If multiple top-1000 files exist (e.g., `npm-top-1000-2026-05.txt` and a future `npm-top-1000-2026-08.txt`), load the most recent.

### 6. The CLI command — extend `arguss/cli.py`

Add a new subcommand:

```python
@app.command()
def trust_snapshot(
    package: str = typer.Argument(..., help="Package name, e.g. 'express' or '@types/node'"),
    version: str = typer.Argument(..., help="Specific version, e.g. '4.17.21'"),
) -> None:
    """Print a TrustSnapshot for a specific package@version, for development inspection."""
```

Print the snapshot as formatted JSON (the existing CLI pattern). Make sure it handles the error case where the package or version doesn't exist with a clean error message and a non-zero exit code.

### 7. Tests — `tests/test_trust_snapshot.py`

Unit tests using `httpx.MockTransport` to stub the registry responses. Cover:

1. A clean fetch of a well-known package@version produces a populated `TrustSnapshot` with expected field types.
2. Scoped packages (`@types/node`) URL-encode correctly in the registry path.
3. Single-maintainer packages get the +30 subscore contribution.
4. A package whose name is in top-1000 gets `typosquat_distance=0` and `typosquat_nearest=<self>`.
5. A package whose name is Levenshtein-distance-1 from a top-1000 entry gets the right distance and nearest.
6. A package not in top-1000 and far from any popular name gets `typosquat_distance` equal to the actual min distance (sanity check it's a reasonable integer).
7. Missing weekly-downloads data yields `weekly_downloads=None`, not a crash.
8. A nonexistent package raises `TrustClientError` with the package name in the message.
9. Cache hits: a second fetch within the TTL window does not call the mock transport again.
10. The CLI command prints valid JSON and exits 0 on success, non-zero on error.

Plus one **integration test** marked `@pytest.mark.integration` that fetches `lodash@4.17.21` from the real registry — gated by the existing integration marker, excluded from the default test suite. This proves end-to-end against real npm without slowing down the unit suite.

### 8. Documentation — `docs/planning/trust-signal-lens.md`

A short design doc (one page) covering:

- The two consumers (PRS path uses subscore; agent path will use TrustDelta in Branch 2)
- The TrustSnapshot field set with brief justification for each
- The subscore weights table with the v1 defaults
- The cache strategy (24h TTL on packument and downloads; immutable per-key during the TTL)
- What's intentionally out of scope: deps.dev integration, OpenSSF Scorecard direct, GitHub repo metadata (all deferred to Week 10 v2 enrichment)
- Open questions for Branch 2 and Week 6 (e.g., what's the right "publish cadence anomaly" threshold)

## Critical rules

1. **Do not modify the existing lens system to wire trust in.** The trust lens remains a fake placeholder until Branch 2. The CLI command is the only public surface for trust functionality in this branch.

2. **Reuse the OSV client's patterns.** httpx structure, cache layer, error class shape — keep them parallel. Anyone reading both clients should immediately see the family resemblance.

3. **Do not fetch data Branch 1 does not need.** No deps.dev. No OpenSSF Scorecard. No GitHub repo lookup. The Week 10 enrichment list stays in the backlog, not in this branch.

4. **The top-1000 file is checked into the repo, not fetched at runtime.** This is a deliberate design choice. Runtime fetching of the top-1000 would add a startup dependency and a network call that buys us nothing — the list changes slowly.

5. **Do not run the refresh script as part of this branch.** Pull the npmrank file once, commit it, document the refresh process, move on.

6. **Stop after each major step and let me read.** Build in this order, stopping between each: (a) models change, (b) registry client, (c) snapshot fetcher + typosquat, (d) top-1000 fixture + refresh script, (e) CLI command, (f) tests, (g) design doc.

## How to work

Generate code one file at a time. After each file is complete, stop and let me review before proceeding. I want to read the registry client carefully before the snapshot fetcher is written against it — the client's interface shape determines how the fetcher reads.

## Verification commands

After Cursor finishes, I will run:

```bash
uv run pytest tests/test_trust_snapshot.py -v       # unit tests pass
uv run pytest                                         # full suite still green
uv run ruff check arguss/lenses/_trust_client.py arguss/lenses/trust.py
uv run mypy arguss/lenses/_trust_client.py arguss/lenses/trust.py

# CLI sanity checks
uv run arguss trust-snapshot lodash 4.17.21
uv run arguss trust-snapshot express 4.18.2
uv run arguss trust-snapshot @types/node 20.10.0
uv run arguss trust-snapshot does-not-exist-package-xyz 1.0.0   # should exit non-zero

# Integration test (will hit the real npm registry)
uv run pytest tests/test_trust_snapshot.py -v -m integration
```

All of those must produce reasonable output before the PR opens.

## Out of scope for this branch (explicitly)

- `TrustDelta` and the agent veto logic — Branch 2
- Wiring trust into the unified scoring engine — Branch 2
- deps.dev, OpenSSF Scorecard, GitHub metadata — Week 10
- Fetching package source code or running install scripts — Week 10+
- Typosquat distance against scoped vs unscoped variants — v1 keeps it simple, only exact name comparison
