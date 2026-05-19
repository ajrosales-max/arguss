# Cursor prompt — Week 6, PR 2: `feature/propose-fixes-cli`

This is the second of two PRs for Week 6. Goal: build the fix-discovery layer (the bridge from findings to remediation candidates), then add the `arguss propose-fixes` CLI command that ties the lenses and engine together end-to-end. This is the first user-visible artifact that says *"here's what the agent would do."*

**Branch name:** `feature/propose-fixes-cli`

**Estimated time:** 1-2 days of focused work.

**Scope discipline:** This PR produces `arguss propose-fixes <lockfile> [--repo-path PATH]` that reads a lockfile, finds vulnerabilities, generates fix candidates (Option A: one candidate per finding with OSV's `fixed_in` as the target), computes fix-confidence for each, and prints results as JSON. Smart target selection (latest patch within minor, alternative paths, etc.) is **not** in this PR — there's a tracked issue for Week 10+.

---

## Before pasting into Cursor

Start from clean main with Week 6 PR 1 merged:

```bash
git checkout main
git pull
git log --oneline -5              # verify feature/fix-confidence-engine is merged

uv run pytest                      # should be 180 passed, 1 skipped

git checkout -b feature/propose-fixes-cli
```

---

## The prompt to paste into Cursor

I'm working on Week 6 PR 2 of the Arguss capstone — `feature/propose-fixes-cli`. PR 1 (the fix-confidence engine) is merged. This PR builds the fix-discovery layer that turns vulnerability findings into FixCandidates, and adds the `arguss propose-fixes` CLI command that exercises the engine end-to-end against a real lockfile.

Project context: Arguss is an autonomous decision-making system for npm supply chain remediation (see `docs/planning/project-overview.md` — note: a v2 of this doc has been drafted reflecting the web-UI pivot; the planning content is current regardless). The vulnerability lens identifies *what's wrong*. The fix-confidence engine evaluates whether a *specific remediation* is safe to auto-merge. The missing piece between them is **fix discovery**: given a finding, what remediation candidates do we propose? This PR builds that missing piece in its simplest defensible form, plus the CLI that composes the whole pipeline.

## The fix discovery design (Option A)

For each vulnerability finding from OSV.dev, generate **exactly one** `FixCandidate`:
- The target version is OSV's `fixed_in` (the minimum version that addresses the CVE)
- The `fix_kind` is computed via `classify_fix_kind(from_version, fixed_in)`
- The `source_finding_id` is the OSV vulnerability ID (e.g., `GHSA-qwcr-r2fm-qrc7`)
- The `repo_id` is derived from the CLI input (the absolute path to the repo root, or the lockfile parent if no `--repo-path` is given)

If a finding has no `fixed_in` version (some advisories don't), skip it with a warning log — there's no candidate to generate.

If a finding has multiple `fixed_in` versions in OSV's response (unusual but possible — happens when the advisory covers multiple version ranges), use the lowest one that's > `from_version`. This is the conservative choice: the smallest available fix.

Smart target selection (latest patch within minor, alternative upgrade paths, considering all available versions on npm) is **explicitly out of scope for v1**. There's a tracked GitHub issue for Week 10+ enhancement. Build the simple version; reference the issue in code comments.

## What to build

### 1. The fix discovery module — `arguss/engine/fix_discovery.py` (new module)

```python
"""Fix discovery: produce FixCandidates from vulnerability findings.

v1 (Option A): one candidate per finding, target is OSV's fixed_in version.
Smart target selection (latest patch within minor, alternative paths) is
deferred to Week 10+ — see issue [link when filed].
"""

from arguss.core.models import FixCandidate, FixKind, Finding
from arguss.engine.fix_kind import classify_fix_kind


def discover_fix_candidates(
    finding: Finding,
    repo_id: str,
) -> list[FixCandidate]:
    """Generate FixCandidate(s) for a vulnerability finding.

    v1 behavior: produces exactly zero or one candidate per finding.
    - Returns [] if the finding has no fixed_in version
    - Returns [one_candidate] using OSV's fixed_in as the target

    Args:
        finding: a Finding from the vulnerability lens (must have OSV
                 advisory data including fixed_in version)
        repo_id: stable identifier for the repository (absolute path or
                 GitHub URL-like string)

    Returns:
        List of FixCandidates. Empty if no fix is available.
    """
```

Implementation notes:

- The `Finding` model already exists. Look at how the vulnerability lens populates it. The fixed-in version data lives in the OSV advisory record — you may need to look at how the vulnerability lens fetches OSV data to find where `fixed_in` is exposed.

- If `fixed_in` isn't currently surfaced on `Finding`, you may need to either:
  - Add it to the `Finding` model
  - Or pass the OSV record alongside the finding

  The cleaner path is to add it to `Finding` — making the lens output self-describing. But check the existing code first; if `Finding` is shared between lenses, adding OSV-specific fields might not fit. In that case, take the second path (pass the raw OSV data through).

- If a finding has multiple `fixed_in` values (the advisory covers multiple ranges), pick the lowest one that's strictly greater than `from_version`. Use the semver comparison logic from `arguss/engine/fix_kind.py` for the comparison.

- If `fixed_in` exists but is somehow less than or equal to `from_version` (data error from OSV), skip with a warning. This shouldn't happen but defending against it is cheap.

### 2. The propose-fixes orchestration — `arguss/engine/propose.py` (new module)

This is the function that ties everything together: read a lockfile, run lenses, discover fixes, compute confidence per candidate, return the results as structured data.

```python
"""Orchestration: lockfile → findings → candidates → confidence verdicts."""

from dataclasses import dataclass
from pathlib import Path

from arguss.core.models import (
    FixCandidate,
    FixConfidence,
    Finding,
)


@dataclass(frozen=True)
class ProposalEntry:
    """One row in the propose-fixes output: finding + candidate + verdict."""
    finding: Finding
    candidate: FixCandidate
    verdict: FixConfidence


@dataclass(frozen=True)
class ProposalReport:
    """The complete output of arguss propose-fixes."""
    repo_path: str                          # the repo root that was analyzed
    lockfile_path: str                      # the lockfile that was read
    entries: tuple[ProposalEntry, ...]      # one per fix candidate
    skipped_findings: tuple[str, ...]       # finding IDs we couldn't generate candidates for
    summary: ProposalSummary                # aggregate counts


@dataclass(frozen=True)
class ProposalSummary:
    """Tier counts and other summary stats."""
    total_findings: int
    total_candidates: int
    auto_merge_count: int
    review_required_count: int
    decline_count: int


def propose_fixes(
    lockfile_path: Path,
    repo_path: Path | None = None,
) -> ProposalReport:
    """Build the full proposal report for a lockfile.

    Args:
        lockfile_path: path to package-lock.json
        repo_path: optional repo root; if None, uses lockfile_path.parent

    Returns:
        ProposalReport with one ProposalEntry per FixCandidate.

    Pipeline:
        1. Parse the lockfile (Week 3 parser)
        2. Run the vulnerability lens to get findings
        3. For each finding, call discover_fix_candidates() → candidates
        4. Fetch one PipelineSnapshot for the repo (Week 5)
        5. For each candidate's package, fetch TrustDelta for the upgrade
           window (from_version → to_version) (Week 4 fetch_delta)
        6. For each candidate, call compute_fix_confidence() (Week 6 PR 1)
        7. Bundle into ProposalReport
    """
```

Key design choices:

- **One pipeline snapshot per scan, not per candidate.** The pipeline lens analyzes the *repo*, not individual packages. Fetch it once.

- **One trust delta per candidate.** Trust analysis is per-package per-upgrade-window. If two candidates upgrade the same package to the same version, you can cache, but for v1 just fetch per-candidate. Performance optimization is Week 10.

- **Trust fetches can fail.** If `fetch_delta()` raises (network error, registry down), pass `None` to `compute_fix_confidence` — the engine handles `None` as "trust unavailable, escalate." Don't crash the whole propose-fixes call because one trust fetch failed.

- **Order of skipped_findings is deterministic** (sorted lex).

### 3. The CLI command — extend `arguss/cli.py`

```python
@app.command(name="propose-fixes")
def propose_fixes_cmd(
    lockfile_path: Path = typer.Argument(
        ...,
        help="Path to package-lock.json",
        exists=True,
        dir_okay=False,
    ),
    repo_path: Path | None = typer.Option(
        None,
        "--repo-path",
        help="Path to the repository root (default: lockfile's parent directory)",
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
) -> None:
    """Generate fix proposals for vulnerabilities in a lockfile.

    Reads the lockfile, finds vulnerabilities, generates remediation candidates,
    evaluates each one through the fix-confidence engine, and prints the
    structured results as JSON.
    """
```

Output format: a JSON object representing the `ProposalReport`. Serialize via `dataclasses.asdict`. Exit 0 even when findings are present; exit 1 only on unrecoverable errors (lockfile parse failure, OSV unreachable, zizmor binary missing, etc.).

The JSON output should be readable enough for a human to scan but structured enough for tooling to parse. Each entry has the finding context (CVE ID, severity), the candidate (from → to), and the verdict (tier, score, reasons, veto signals).

### 4. Tests — `tests/test_propose_fixes.py` (new file)

Required tests:

**Fix discovery:**
1. `test_discover_fix_with_fixed_in` — Finding with `fixed_in=1.20.3` produces one FixCandidate
2. `test_discover_fix_no_fixed_in` — Finding without a fix version returns empty list
3. `test_discover_fix_kind_classified_correctly` — patch/minor/major delta correctly classified
4. `test_discover_fix_picks_lowest_fixed_in_when_multiple` — multiple `fixed_in` values picks lowest > from_version
5. `test_discover_fix_skips_invalid_fixed_in` — `fixed_in <= from_version` is skipped with warning
6. `test_candidate_id_includes_repo_id` — different repos produce different candidate_ids for the same finding

**Orchestration:**
7. `test_propose_fixes_empty_lockfile` — lockfile with no deps returns empty proposal report
8. `test_propose_fixes_no_vulnerabilities` — lockfile with deps but no CVEs returns empty entries
9. `test_propose_fixes_one_vulnerability` — one CVE produces one entry with the right shape
10. `test_propose_fixes_summary_counts` — summary tier counts match the entries
11. `test_propose_fixes_skipped_findings` — findings without fixed_in appear in skipped_findings
12. `test_propose_fixes_trust_fetch_failure_degrades` — TrustClientError on one package doesn't crash the run; engine sees `trust_delta=None` for that candidate
13. `test_propose_fixes_uses_lockfile_parent_when_no_repo_path` — `repo_path=None` defaults correctly
14. `test_propose_fixes_pipeline_snapshot_fetched_once` — even with N candidates, pipeline lens runs once (mock and assert call count)

**CLI:**
15. `test_cli_propose_fixes_success_against_synthetic_fixture` — runs against a small synthetic fixture, exits 0, produces valid JSON
16. `test_cli_propose_fixes_lockfile_not_found_exits_1` — bad path exits non-zero with clear error
17. `test_cli_propose_fixes_json_output_validates_schema` — output JSON has all required fields

Plus an integration test marked `@pytest.mark.integration` that runs against the existing real-world Express fixture:

```python
@pytest.mark.integration
def test_propose_fixes_integration_real_world_express(tmp_path):
    """End-to-end: real lockfile, real OSV calls, real engine evaluation."""
```

Don't assert specific tier distributions for the integration test (the network responses can vary). Just assert that the report is well-formed and contains some entries.

### 5. Update `arguss scan` to mention propose-fixes

The existing `arguss scan` command prints a unified PRS. Add a hint at the end of its output suggesting `arguss propose-fixes` for actionable remediation. Just a one-line note — don't restructure the scan output.

### 6. Design notes — `docs/planning/fix-confidence-engine.md`

The engine design doc already exists from PR 1. Add a section to it (don't create a new file):

```markdown
## Fix discovery (v1)

The engine consumes FixCandidates. The fix-discovery layer produces them
from vulnerability findings. The v1 implementation (Option A) generates
exactly one candidate per finding, using OSV's `fixed_in` as the target
version.

Known v1 simplifications, all tracked for Week 10+ enhancement:

- **No smart target selection.** We use OSV's `fixed_in` directly rather
  than considering "latest patch within current minor" or other heuristics.
  When OSV says "fixed in 1.20.3," we propose 1.20.3, even if 1.20.6 is
  available and just as safe.

- **No alternative paths.** A single finding maps to a single candidate.
  We don't generate "minimum fix" vs "latest minor" vs "latest major" as
  separate candidates for the user to choose between.

- **No per-package coalescing.** If body-parser 1.19.0 has three CVEs all
  fixed in 1.20.3, we generate three candidates with the same to_version
  rather than one candidate that addresses all three. Display layer can
  dedupe; engine evaluation is wasted on duplicates.

These simplifications are deliberate. The v1 system is the minimum that
proves the engine works end-to-end. Each one above can be relaxed
independently when there's a real need.
```

## Critical rules

1. **Option A only.** One candidate per finding, target is OSV's `fixed_in`. No smart selection, no alternatives, no coalescing. The temptation to be smarter is real; resist it. Smart discovery is Week 10+.

2. **The vulnerability lens already runs.** Don't reimplement it. Don't reparse OSV responses outside the existing client. If `Finding` doesn't have the `fixed_in` data you need, extend `Finding` cleanly (add a field, update the lens to populate it).

3. **The engine is called per-candidate.** Don't try to batch or vectorize. Each `compute_fix_confidence` call is one decision on one candidate.

4. **Trust fetch failures don't crash the run.** The engine handles `trust_delta=None`. Pass it through.

5. **Pipeline snapshot is fetched once.** Not once per candidate. Once for the repo.

6. **The CLI output is JSON.** Not pretty-printed text. JSON. Future UI consumers will parse it.

7. **Stop after each major step:**
   - (a) `Finding` model extension if needed (or confirmation it already has fixed_in)
   - (b) The fix discovery module
   - (c) The orchestration module (ProposalReport, ProposalEntry, propose_fixes function)
   - (d) The CLI command + scan output hint
   - (e) Tests
   - (f) Design doc update

   Let me review between each. Especially after (b) — discovery is the new conceptual piece in this PR and I want to confirm the shape before the orchestration builds on it.

## How to work

Generate code one file at a time. Stop after each step. The `Finding` model extension (step a) and the discovery module (step b) need my review before orchestration is built on top of them.

## Verification commands

After Cursor finishes, I will run:

```bash
uv run pytest tests/test_propose_fixes.py -v
uv run pytest                                              # full suite still green

# CLI sanity checks against the existing real-world Express fixture
uv run arguss propose-fixes tests/fixtures/lockfiles/real-world.json
uv run arguss propose-fixes tests/fixtures/lockfiles/real-world.json --repo-path tests/fixtures/repos/clean-with-tests/

# Integration test
uv run pytest tests/test_propose_fixes.py -v -m integration
```

The first CLI sanity check should produce a JSON output with multiple entries (the Express fixture has 12 real CVEs). Most will likely be REVIEW_REQUIRED because the lockfile's parent directory doesn't have proper repo structure. The second CLI invocation with `--repo-path` pointing at a clean fixture should produce some AUTO_MERGE entries (or at least produce a different result than the first one).

## Out of scope for this PR (explicitly)

- Smart target selection (latest patch within minor, latest available, etc.) — Week 10+
- Multiple candidates per finding (alternative upgrade paths) — Week 10+
- Per-package coalescing of multiple CVEs — Week 10+
- The actual `git`/PR creation work — Week 7 agent loop (Mode C)
- The web UI consumption of this output — Week 9 web UI build
- Caching `TrustDelta` fetches across candidates with the same package — Week 10
- The Claude-backed escalation message generation — separate small PR (Week 7 target)
- Persistent storage of ProposalReports for replay — Week 10
