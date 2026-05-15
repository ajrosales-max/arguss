# Cursor prompt — Week 4, Branch 2: `feature/trust-delta`

This is the second of two branches for the Week 4 trust signal lens. Goal: build the `TrustDelta` data model and computation, the conservative `safe_to_auto_merge` veto logic, and wire the trust lens into the unified scoring engine.

**Branch name:** `feature/trust-delta`

**Estimated time:** 2 days of focused work. The conceptual work (snapshot fetching) was Branch 1; this branch is mostly composition and integration.

**Scope discipline:** This branch produces `arguss trust-delta <package> <from-version> <to-version>` printing a populated `TrustDelta`, AND replaces the fake `TrustLens.scan()` with a real implementation that uses snapshot subscores. The agent path (consuming the delta for fix-confidence) is Week 6; the lens emits the delta but nothing consumes it yet.

---

## Before pasting into Cursor

Start from clean main with Branch 1 merged:

```bash
git checkout main
git pull
git log --oneline -10                  # verify feature/trust-snapshot is merged
git checkout -b feature/trust-delta

# Verify existing tests pass
uv run pytest
```

You should see 83+ tests passing (Branch 1 added 10 unit tests plus 1 integration). If anything is red, fix before continuing.

---

## The prompt to paste into Cursor

I'm working on Week 4 Branch 2 of the Arguss capstone — `feature/trust-delta`. Branch 1 (`feature/trust-snapshot`) is merged. The snapshot infrastructure exists: `fetch_snapshot(cache, package, version)` returns a populated `TrustSnapshot`. This branch builds the delta, wires the trust lens into the unified scoring engine, and adds the `arguss trust-delta` CLI command.

Project context: Arguss is an autonomous remediation agent for npm supply chain vulnerabilities (see `docs/planning/pivot-rationale.md` and `docs/planning/project-overview.md`). The `TrustDelta` is the agent's veto signal — Week 7+ agent loop reads `safe_to_auto_merge` to decide whether to auto-merge a fix. Branch 2 emits the delta; no consumer wires into it yet.

## What to build

### 1. The TrustDelta model and TrustFlag enum — `arguss/core/models.py`

Add to the existing models file (view it first, do not duplicate):

```python
from enum import Enum

class TrustFlag(Enum):
    """Specific veto conditions that triggered safe_to_auto_merge=False."""
    OWNERSHIP_TRANSFER = "ownership_transfer"
    NEW_MAINTAINER = "new_maintainer"
    CADENCE_ANOMALY = "cadence_anomaly"
    DOWNLOAD_COLLAPSE = "download_collapse"


@dataclass(frozen=True)
class TrustDelta:
    """What changed about a package's trust profile between two versions.

    Computed from two TrustSnapshots. Emitted by fetch_delta() for development
    inspection and (in Week 6) consumed by the fix-confidence engine as the
    agent's veto signal.
    """
    package: str
    from_version: str
    to_version: str

    # Maintainer deltas
    maintainers_added: tuple[str, ...]      # sorted
    maintainers_removed: tuple[str, ...]    # sorted
    ownership_transferred: bool             # majority of maintainers changed

    # Publish cadence
    days_between_publishes: int             # absolute time elapsed across the window
    publish_cadence_anomaly: bool           # this publish is unusually fast for this package

    # Population change
    weekly_downloads_change_pct: float | None    # None if either snapshot had None

    # The veto bit and its reasons
    flags: tuple[TrustFlag, ...]            # sorted by enum value for determinism
    safe_to_auto_merge: bool                # True iff flags is empty
```

### 2. The delta computation — `arguss/lenses/trust.py`

Add to the existing trust module (do not modify the snapshot fetcher):

```python
def fetch_delta(
    cache: Cache,
    package: str,
    from_version: str,
    to_version: str,
) -> TrustDelta:
    """Build a TrustDelta from two TrustSnapshots.

    Fetches snapshots for from_version and to_version, then computes the delta.
    Snapshots are cached per Branch 1's policy (24h TTL); if both snapshots are
    cache hits, this is a pure computation with no network calls.

    Raises TrustClientError if either version is missing from the registry.
    """
```

The delta logic:

**Maintainer deltas:**
- `maintainers_added = sorted(set(to_snapshot.maintainer_logins) - set(from_snapshot.maintainer_logins))`
- `maintainers_removed = sorted(set(from_snapshot.maintainer_logins) - set(to_snapshot.maintainer_logins))`
- `ownership_transferred = len(intersection) < 0.5 * len(from_snapshot.maintainer_logins)` (more than half of original maintainers gone)

**Cadence anomaly** — separate helper function `_is_cadence_anomaly(packument, from_version, to_version) -> bool`:

```python
# Anomaly if ALL three conditions hold:
#   (a) new gap < 0.3 × median of previous 10 published gaps
#   (b) package has 5+ historical versions before the upgrade window
#   (c) new gap < 7 days (absolute floor — don't flag legitimate weekly cadences)
```

To compute this you need the full packument's `time` map, sorted chronologically, with the gap between `from_version` and `to_version` extracted plus the prior 10 gaps for the median. Reuse `_published_events` from Branch 1.

If the packument has fewer than 5 historical versions before `to_version`, return False (insufficient data — don't flag).

**Download change:**
- `weekly_downloads_change_pct = None if either snapshot has None else (to_downloads - from_downloads) / from_downloads`
- Handle the from_downloads=0 edge case: if from is 0 and to is positive, return None (division undefined); if both 0, return 0.0.

**Flags computation:**
- OWNERSHIP_TRANSFER if `ownership_transferred`
- NEW_MAINTAINER if `len(maintainers_added) > 0` (any new maintainer in the window)
- CADENCE_ANOMALY if `publish_cadence_anomaly`
- DOWNLOAD_COLLAPSE if `weekly_downloads_change_pct is not None and weekly_downloads_change_pct < -0.5`

**`safe_to_auto_merge = len(flags) == 0`**

### 3. Wire the trust lens into the scoring engine — `arguss/lenses/trust.py`

Replace the existing fake `TrustLens.scan()` placeholder with a real implementation. The lens has two responsibilities:

**A. Aggregate per-package subscores into a project-level LensScore.**

For each dependency in the project, call `fetch_snapshot(cache, dep.name, dep.version)`. Then:

```python
# Sort subscores descending, take top-N mean (N=10), fall back to all if fewer
TOP_N = 10
subscores = sorted([s.subscore for s in snapshots], reverse=True)
top_n = subscores[:TOP_N] if len(subscores) >= TOP_N else subscores
lens_score = sum(top_n) / len(top_n) if top_n else 0
```

The lens emits a `LensScore` matching the existing pattern (look at `VulnerabilityLens` for the shape). The score is the top-N mean of subscores. Findings are the underlying snapshots themselves, formatted as Finding objects per the existing convention.

**B. Tolerate snapshot fetch failures gracefully.**

A `TrustClientError` on a single dep (e.g., a package that was unpublished from npm) should NOT crash the lens. Log the failure, skip that dep, continue. The lens score reflects only deps for which a snapshot was successfully fetched. Log a summary at the end: "trust lens: N deps scored, M failed."

Don't go overboard on error handling — three lines of try/except per dep, a logger.warning, move on.

### 4. The CLI command — extend `arguss/cli.py`

Mirror `arguss trust-snapshot`:

```python
@app.command()
def trust_delta(
    package: str = typer.Argument(..., help="Package name, e.g. 'express' or '@types/node'"),
    from_version: str = typer.Argument(..., help="The 'from' version, e.g. '4.17.20'"),
    to_version: str = typer.Argument(..., help="The 'to' version, e.g. '4.17.21'"),
) -> None:
    """Print a TrustDelta between two package versions, for development inspection."""
```

Use the same JSON serialization pattern as `trust_snapshot`. The `TrustFlag` enum serializes via `.value` — make sure `_json_default` handles it.

### 5. Tests — `tests/test_trust_delta.py` (new file)

Build alongside `tests/test_trust_snapshot.py`. Use the same `MockTransport` patterns from that file.

Required tests:

1. **Clean delta with no flags.** Two snapshots with same maintainers, similar publish gap, similar downloads → `safe_to_auto_merge=True`, empty `flags`.

2. **Ownership transfer flag.** Snapshots where >50% of maintainers changed → `OWNERSHIP_TRANSFER` flag, `safe_to_auto_merge=False`.

3. **New maintainer flag (but not ownership transfer).** Snapshots where 1 of 5 maintainers was added → `NEW_MAINTAINER` flag only (not OWNERSHIP_TRANSFER).

4. **Cadence anomaly: all three conditions hold.** Mock a packument with 10+ historical gaps showing median ~30 days, then a new gap of 1 day → `CADENCE_ANOMALY` flag.

5. **Cadence anomaly: insufficient version history.** Package with only 3 historical versions → no `CADENCE_ANOMALY` flag even if gap is short.

6. **Cadence anomaly: gap below ratio but above 7-day floor.** Median 30 days, new gap 8 days → no flag (caught by absolute floor).

7. **Cadence anomaly: gap below floor but not below ratio.** Median 3 days (weekly cadence), new gap 2 days → no flag (caught by ratio check).

8. **Download collapse flag.** From-downloads 1000, to-downloads 400 → `DOWNLOAD_COLLAPSE` flag (60% drop).

9. **Download change with None.** Either snapshot has `weekly_downloads=None` → `weekly_downloads_change_pct=None`, no `DOWNLOAD_COLLAPSE` flag.

10. **Multiple flags.** New maintainer + cadence anomaly → both flags present in sorted order.

11. **Maintainers sorted in deltas.** Verify `maintainers_added` and `maintainers_removed` are alphabetically sorted (deterministic output).

12. **CLI command success and failure exits.** `CliRunner` for both paths.

Plus integration test (marked `@pytest.mark.integration`): real npm fetch of `lodash@4.17.20` and `lodash@4.17.21` (security patch, real-world delta), assert basic structure.

### 6. Tests for the lens integration — extend `tests/test_skeleton.py` or create `tests/test_trust_lens.py`

3-5 tests covering the lens's `scan()` method:

1. Empty deps list → lens score 0, no findings.
2. One dep with high subscore → lens score equals that subscore (top-N degenerates).
3. 20 deps with varied subscores → lens score is top-10 mean.
4. One dep raises `TrustClientError` → lens score reflects only the successful deps, no crash.
5. All deps raise → lens score 0, log message present.

Use `unittest.mock.patch` on `fetch_snapshot` to inject controlled subscores. Don't go to the network in these tests.

### 7. Update the design doc — `docs/planning/trust-signal-lens.md`

The existing doc covers the snapshot side. Add sections for:

- The TrustDelta model and TrustFlag enum
- The four veto conditions and their thresholds
- The cadence-anomaly three-condition rule with justification
- The lens aggregation function (top-N mean, N=10, fallback to all)
- The graceful degradation policy (skip failed deps, log summary)
- Open questions for Week 6: how the delta wires into fix-confidence

## Critical rules

1. **The TrustDelta is emitted but not yet consumed by the agent.** Week 6 wires it into fix-confidence. Don't try to do that now.

2. **The lens integration uses snapshot subscores, not deltas.** The existing PRS path is unchanged in semantics — it gets a trust risk score. Deltas are a parallel output.

3. **No new dependencies on deps.dev, OpenSSF Scorecard, GitHub metadata.** Those are Week 10 v2 enrichment. The Branch 2 delta uses only what Branch 1's snapshots already provide.

4. **The `_is_cadence_anomaly` helper reuses `_published_events` from Branch 1.** Don't reimplement packument time parsing.

5. **The four flag conditions are conservative on purpose.** Don't loosen them based on "would too often false-positive." False positives in v1 escalate to humans, which is recoverable. False negatives (auto-merging a malicious package) is the failure mode we're preventing.

6. **Stop after each major step and let me read.** Build in this order: (a) models change, (b) delta computation + cadence helper, (c) lens scan() replacement + aggregation, (d) CLI command, (e) tests for delta, (f) tests for lens integration, (g) design doc update.

## How to work

Generate code one file at a time. Stop after each step. I want to read the delta logic carefully before the lens integration is written against it — and the lens integration before the CLI is wired.

## Verification commands

After Cursor finishes, I will run:

```bash
uv run pytest tests/test_trust_delta.py -v
uv run pytest tests/test_trust_lens.py -v        # or wherever lens tests live
uv run pytest                                     # full suite still green
uv run ruff check arguss/lenses/trust.py arguss/cli.py
uv run mypy arguss/lenses/trust.py arguss/cli.py

# CLI sanity checks
uv run arguss trust-delta lodash 4.17.20 4.17.21       # real security patch
uv run arguss trust-delta express 4.17.0 4.18.0        # real minor bump
uv run arguss trust-delta @types/node 20.10.0 20.11.0  # scoped + frequent publishes

# Integration test
uv run pytest tests/test_trust_delta.py -v -m integration

# End-to-end: scan a real project, see trust lens in the output
uv run arguss scan tests/fixtures/lockfiles/real-world.json    # trust lens should now show a real score, not the fake stub
```

All of those must produce reasonable output before the PR opens.

## Out of scope for this branch (explicitly)

- Wiring TrustDelta into fix-confidence engine — Week 6
- Configurable `@types/*` namespace allowlist for sole-maintainer false positives — Week 10
- Tuning the four veto thresholds based on real data — Week 11 evaluation
- Multi-version fix simulation (what happens if we have to skip a version) — Week 9
- Replacing the `safe_to_auto_merge` boolean with a graded confidence score — Week 6 fix-confidence engine handles this
