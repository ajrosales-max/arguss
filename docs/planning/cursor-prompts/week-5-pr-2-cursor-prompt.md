# Cursor prompt — Week 5, PR 2: `feature/pipeline-lens`

This is the second of two PRs for Week 5. Goal: build the test reality assessment, the `PipelineSnapshot` model, replace the fake `PipelineLens.scan()` with a real implementation, and add the `arguss pipeline-snapshot` CLI command. After this PR, the pipeline lens produces real numbers and a real agent veto bit.

**Branch name:** `feature/pipeline-lens`

**Estimated time:** 2-3 days of focused work.

**Scope discipline:** This PR produces `arguss pipeline-snapshot <repo-path>` printing a populated `PipelineSnapshot` with both zizmor findings and test reality assessment, AND replaces the fake `PipelineLens.scan()`. The agent path (consuming the snapshot's veto bit for fix-confidence) is Week 6; the lens emits the veto bit but nothing consumes it yet.

---

## Before pasting into Cursor

Start from clean main with PR 1 merged:

```bash
git checkout main
git pull
git log --oneline -5            # verify feature/zizmor-wrapper is merged

uv run pytest                    # should be 114 passed, 1 skipped
uv run arguss zizmor-scan tests/fixtures/workflows/sample-with-findings/ci.yml   # should exit 0 with JSON

git checkout -b feature/pipeline-lens
```

---

## The prompt to paste into Cursor

I'm working on Week 5 PR 2 of the Arguss capstone — `feature/pipeline-lens`. PR 1 (`feature/zizmor-wrapper`) is merged: `ZizmorClient` is available, the `arguss zizmor-scan` command works, and `ZizmorFinding` is in `arguss/core/models.py`. This PR builds the test reality assessment, the `PipelineSnapshot` model, wires the pipeline lens into the unified scoring engine, and adds the `arguss pipeline-snapshot` CLI command.

Project context: Arguss is an autonomous remediation agent for npm supply chain vulnerabilities (see `docs/planning/pivot-rationale.md` and `docs/planning/project-overview.md`). The pipeline lens has two outputs in the agent framing: a `subscore` (consumed by the existing PRS path, like the trust lens's subscore) and a `safe_to_auto_merge` veto bit (consumed by the Week 6 fix-confidence engine). The veto bit answers: "does this repository's CI verify changes well enough for the agent to safely auto-merge?" Same shape as the trust lens — two outputs serving two consumers.

## What to build

### 1. The TestReality and PipelineSnapshot models — `arguss/core/models.py`

Add to the existing models file (view it first; do not duplicate):

```python
@dataclass(frozen=True)
class TestReality:
    """Heuristic assessment: does this repo's CI actually verify changes?

    Four boolean conditions evaluated against the repo on disk. All four
    must hold for safe_to_auto_merge=True. This is intentionally conservative:
    false negatives (we say 'no tests' when there are) escalate to human review
    (recoverable). False positives (we say 'yes tests' when there aren't) would
    let the agent auto-merge into a repo with no verification (not recoverable).
    """
    has_test_script: bool           # package.json has a non-empty scripts.test
    test_script_is_no_op: bool      # scripts.test matches a no-op pattern
    has_test_files: bool            # at least one *.test.*, *.spec.*, or test/ dir file
    test_count: int                 # rough count of test files found (for visibility)
    workflow_runs_tests: bool       # at least one workflow has a step running tests
    safe_to_auto_merge: bool        # = has_test_script AND not test_script_is_no_op
                                    #   AND has_test_files AND workflow_runs_tests
    reasons_blocked: tuple[str, ...]  # human-readable reasons safe_to_auto_merge=False
                                      # empty tuple when safe_to_auto_merge=True


@dataclass(frozen=True)
class PipelineSnapshot:
    """Pipeline trust profile for a repository, captured at scan time."""
    repo_path: str                          # absolute path to the repo root
    workflow_files: tuple[str, ...]         # sorted repo-relative paths of discovered workflows
    zizmor_findings: tuple[ZizmorFinding, ...]
    test_reality: TestReality
    subscore: int                           # 0-100 for the existing PRS path
```

### 2. The pipeline lens module — `arguss/lenses/pipeline.py`

Replace the existing fake `PipelineLens.scan()` with a real implementation. The module needs to expose two things publicly:

```python
def fetch_pipeline_snapshot(repo_path: Path) -> PipelineSnapshot:
    """Build a PipelineSnapshot for a repository.

    Walks repo_path/.github/workflows/ for workflow files, runs zizmor against
    that directory, reads package.json, scans for test files, and parses
    workflow YAML to determine if tests are actually executed.

    Does not raise on missing inputs. A repo with no .github/workflows/, no
    package.json, or no test files produces a snapshot with appropriate
    flags set; PipelineSnapshot is always returned successfully.

    Raises ZizmorClientError only if zizmor itself fails (binary missing, etc).
    """


class PipelineLens(Lens):
    """The pipeline lens: workflow misconfigurations + test reality."""

    def __init__(self, repo_path: Path | None = None) -> None:
        """repo_path is the path that arguss scan was invoked against.
        If None, the lens degrades to the existing stubbed behavior.
        """

    def scan(self, deps: list[Dependency]) -> LensScore:
        """Returns the lens score and findings for the unified scoring engine.

        Wraps fetch_pipeline_snapshot and converts to the LensScore shape
        the existing scoring engine expects. Findings emitted:
        - One per ZizmorFinding (severity from zizmor, title from desc,
          source_url from audit_url)
        - One TestReality finding if not safe_to_auto_merge (severity = high,
          description includes reasons_blocked)
        """
```

The `Dependency` list passed to `scan()` is ignored — pipeline analysis is per-repo, not per-dependency. (The lens interface was designed for dependency-based lenses; pipeline doesn't fit that mold cleanly. Document this in the lens docstring.)

The `repo_path` is provided by `arguss scan` based on what the user invoked it against. See section 8 below for the CLI wiring.

### 3. The four-condition test reality logic

Implement these four checks as helper functions for testability:

```python
def _has_test_script(package_json: dict) -> bool:
    """package_json has scripts.test as a non-empty string."""

def _test_script_is_no_op(test_script: str) -> bool:
    """Returns True for known no-op patterns. Conservative: assume real
    unless it matches a known sentinel.

    Patterns that should match (case-insensitive):
    - 'echo' anything followed by 'no tests' or 'no test'
    - 'exit 0' alone or after 'echo'
    - '' (empty string) — though that's already caught by has_test_script
    - 'true' (the Unix true command, no-op success)

    Patterns that should NOT match:
    - 'jest', 'mocha', 'vitest', 'ava' — real test runners
    - 'npm run test:something' — delegating to another script (assume real)
    - 'tsc --noEmit' — type check, NOT a test, but per our discipline we
      do NOT count this as a no-op either. It's just not a real test. The
      static heuristic can't distinguish 'tsc --noEmit' from a real runner.
      We accept this false-positive case for v1.
    """


def _has_test_files(repo_path: Path) -> tuple[bool, int]:
    """Returns (has_any, count).

    Walks repo_path looking for files matching any of:
    - *.test.js, *.test.jsx, *.test.ts, *.test.tsx, *.test.mjs
    - *.spec.js, *.spec.jsx, *.spec.ts, *.spec.tsx, *.spec.mjs
    - Files directly under test/, tests/, __tests__/, spec/ directories

    Ignores node_modules/, dist/, build/, .git/, coverage/. Caps at 1000
    files scanned to avoid pathological repos.
    """


def _workflow_runs_tests(workflows_dir: Path) -> bool:
    """Parse each workflow YAML and check whether any step runs tests.

    Recognizes test invocations (case-insensitive, with optional 'run'):
        npm test
        npm run test
        yarn test
        yarn run test
        pnpm test
        pnpm run test
        bun test
        bun run test

    Match the pattern via regex on each step's 'run:' value, or in the case
    of steps using actions/setup-node + a separate run step, on the run step.

    Returns True if any step in any workflow matches. False if no workflows
    exist, or workflows exist but none run tests.
    """
```

The regex for `_workflow_runs_tests` should be approximately:

```python
_TEST_INVOCATION_RE = re.compile(
    r'\b(npm|yarn|pnpm|bun)\s+(?:run\s+)?test\b',
    re.IGNORECASE,
)
```

### 4. The TestReality.reasons_blocked field

When `safe_to_auto_merge=False`, populate `reasons_blocked` with the specific failure modes. This is the human-readable explanation that will surface in the escalation message later. Possible reasons:

- `"no package.json in your submission"`
- `"package.json has no scripts.test"`
- `"test script is a no-op (matches sentinel pattern)"`
- `"no test files in your project"`
- `"no GitHub Actions workflow runs tests"`

Multiple reasons can be present simultaneously. Sort them deterministically (lexicographic is fine).

When `safe_to_auto_merge=True`, `reasons_blocked` is the empty tuple.

### 5. Subscore aggregation: severity-weighted sum + test reality penalty

The pipeline subscore for the existing PRS path is computed as:

```python
_PIPELINE_SUBSCORE_WEIGHTS = {
    "informational": 2,
    "low": 5,
    "medium": 15,
    "high": 30,
}
_TEST_REALITY_PENALTY = 40
_SUBSCORE_CAP = 100


def _compute_subscore(
    findings: list[ZizmorFinding],
    test_reality: TestReality,
) -> int:
    """Pipeline subscore for the PRS path.

    Severity-weighted sum of zizmor findings, plus a fixed penalty when test
    reality fails. Capped at 100. This is the human-facing risk score
    displayed in the dashboard; the agent's veto bit (test_reality.safe_to_auto_merge)
    is exposed separately and not redundant with this number.
    """
    weights_sum = sum(_PIPELINE_SUBSCORE_WEIGHTS[f.severity] for f in findings)
    penalty = _TEST_REALITY_PENALTY if not test_reality.safe_to_auto_merge else 0
    return min(weights_sum + penalty, _SUBSCORE_CAP)
```

The separate `safe_to_auto_merge` boolean on `TestReality` is what the agent reads for the veto decision. The subscore is for the dashboard. Document this in the pipeline lens design doc as the "two outputs serving two consumers" pattern, paralleling the trust lens.

### 6. The CLI command — extend `arguss/cli.py`

Mirror `arguss trust-snapshot`:

```python
@app.command()
def pipeline_snapshot(
    repo_path: Path = typer.Argument(
        ...,
        help="Path to a repository root (containing package.json, .github/, etc.)",
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
) -> None:
    """Print a PipelineSnapshot for a repository, for development inspection."""
```

Use the same JSON serialization pattern as `arguss trust-snapshot`. Findings serialize via `dataclasses.asdict`. Exit 0 on success (even with findings); exit 1 on `ZizmorClientError` (or any other unrecoverable error).

### 7. Wire the lens into `arguss scan`

Currently `arguss scan` constructs `PipelineLens()` without any arguments because it was a stub. The scan command needs to:

1. Determine the repo path from its argument. If the user passed a `package-lock.json` directly, the repo root is the parent directory. If they passed a directory, the repo root is that directory.
2. Pass the repo path to `PipelineLens(repo_path=repo_root)`.
3. The lens uses this to find `.github/workflows/`, `package.json`, etc.

If the repo path doesn't contain a `.github/` or `package.json`, the lens degrades gracefully — empty workflow files list, `has_test_script=False`, etc. The snapshot is still produced; it just contains lots of `False` values and high `reasons_blocked`.

### 8. The six test fixtures

Create `tests/fixtures/repos/` with six subdirectories. Each is a minimal repo skeleton — just `package.json`, optionally `.github/workflows/ci.yml`, and optionally test files.

**Fixture 1: `clean-with-tests/`** — passes all four conditions.
```
package.json:
{
  "name": "clean-fixture",
  "scripts": {"test": "jest"}
}

.github/workflows/ci.yml:
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

__tests__/sample.test.js:
test('placeholder', () => {});
```

**Fixture 2: `no-test-script/`** — `scripts.test` is missing.
```
package.json:
{
  "name": "no-script",
  "scripts": {"build": "tsc"}
}
.github/workflows/ci.yml: (same as fixture 1)
__tests__/sample.test.js: (same as fixture 1)
```

**Fixture 3: `noop-test-script/`** — `scripts.test` is a no-op.
```
package.json:
{
  "name": "noop-script",
  "scripts": {"test": "echo 'no tests' && exit 0"}
}
.github/workflows/ci.yml: (same as fixture 1)
__tests__/sample.test.js: (same as fixture 1)
```

**Fixture 4: `no-test-files/`** — script and workflow look right, but no test files exist.
```
package.json:
{
  "name": "no-files",
  "scripts": {"test": "jest"}
}
.github/workflows/ci.yml: (same as fixture 1)
(no test files anywhere)
```

**Fixture 5: `workflow-skips-tests/`** — has tests and a test script, but workflow doesn't run them.
```
package.json:
{
  "name": "skip-workflow",
  "scripts": {"test": "jest"}
}
.github/workflows/ci.yml:
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run build      # builds but doesn't test
__tests__/sample.test.js: (same as fixture 1)
```

**Fixture 6: `yarn-tests/`** — passes all conditions using yarn instead of npm.
```
package.json:
{
  "name": "yarn-fixture",
  "scripts": {"test": "jest"}
}
.github/workflows/ci.yml:
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: yarn test
__tests__/sample.test.js: (same as fixture 1)
```

### 9. Tests — `tests/test_pipeline_lens.py` (new file)

Required tests:

**Test reality assessment (one test per fixture):**
1. `test_clean_fixture_safe_to_auto_merge` — fixture 1, expects `safe_to_auto_merge=True`
2. `test_no_test_script_blocks_auto_merge` — fixture 2, expects False with reason "no scripts.test"
3. `test_noop_test_script_blocks_auto_merge` — fixture 3, expects False with reason "no-op"
4. `test_no_test_files_blocks_auto_merge` — fixture 4, expects False with reason "no test files"
5. `test_workflow_not_running_tests_blocks_auto_merge` — fixture 5, expects False with reason "workflow does not run tests"
6. `test_yarn_test_recognized` — fixture 6, expects `safe_to_auto_merge=True`

**Subscore aggregation:**
7. `test_subscore_no_findings_clean_ci` — empty findings + good test reality → 0
8. `test_subscore_findings_only` — 3 medium findings + good test reality → 45 (3 × 15)
9. `test_subscore_test_reality_penalty` — empty findings + bad test reality → 40
10. `test_subscore_both_combined` — 2 high findings + bad test reality → min(2×30 + 40, 100) = 100
11. `test_subscore_caps_at_100` — many findings → exactly 100

**No-op script pattern matching (unit tests on `_test_script_is_no_op`):**
12. Match: `"echo 'no tests'"`, `"echo \"no test\" && exit 0"`, `"exit 0"`, `"true"`
13. No match: `"jest"`, `"jest --coverage"`, `"npm run test:unit"`, `"vitest"`, `"tsc --noEmit"` (intentional FP)

**Workflow regex (unit tests on `_workflow_runs_tests`):**
14. Match `npm test`, `npm run test`, `yarn test`, `yarn run test`, `pnpm test`, `pnpm run test`, `bun test`, `bun run test`
15. No match: `npm install`, `npm run build`, `npm run lint`, `python test.py`

**Snapshot integration:**
16. `test_fetch_pipeline_snapshot_clean_fixture` — calls `fetch_pipeline_snapshot` on fixture 1, asserts the snapshot is fully populated with the right fields
17. `test_fetch_pipeline_snapshot_no_dot_github` — calls on a directory with no `.github/`, expects `workflow_files=()`, `workflow_runs_tests=False`, but doesn't crash

**Lens integration:**
18. `test_pipeline_lens_scan_clean_fixture` — `PipelineLens(repo_path=fixture_1).scan([])` returns a `LensScore` with subscore from the snapshot
19. `test_pipeline_lens_scan_no_repo_path` — `PipelineLens()` (no path) returns the existing stubbed behavior, doesn't crash
20. `test_pipeline_lens_findings_include_test_reality` — when test reality fails, the lens emits an additional high-severity finding describing why

**CLI:**
21. CLI success and failure exits (using `CliRunner`)

Plus one integration test marked `@pytest.mark.integration` that runs the full snapshot pipeline against fixture 1 with the real zizmor binary.

### 10. Design doc — `docs/planning/pipeline-lens.md` (new file)

Cover:
- The two-consumer pattern (subscore for PRS, `safe_to_auto_merge` veto bit for the agent — same as trust lens)
- The four-condition test reality rule with justifications for each
- The known false-positive case: `tsc --noEmit` passes our heuristic but isn't really testing. Document and accept for v1.
- The yarn/pnpm/bun alias recognition (regex) and why
- The subscore formula (weights table, test reality penalty, cap)
- Why we ignore the `Dependency` list in `scan()` (pipeline is per-repo, not per-dep)
- Out of scope: code coverage analysis, test framework detection beyond invocation, GitHub Actions security audits we don't run via zizmor, CI theater detection (e.g., `|| true` in workflows)
- Open questions for Week 6: how the veto bit threads through fix-confidence; whether the lens score should weight in CI-quality signal differently from misconfiguration signal

## Critical rules

1. **The TestReality assessment is binary at the boundary.** All four conditions hold → safe. Anything fails → not safe. Don't introduce partial credit ("3 of 4 conditions hold → 0.75 safe"). The agent needs a clean yes/no.

2. **The yarn/pnpm/bun recognition is mandatory.** The whole pipeline lens should pass fixture 6. If Cursor implements npm-only matching, that's a bug.

3. **`tsc --noEmit` is a known false positive** that we accept. Don't try to detect it. The design doc records this as a documented limitation.

4. **The lens degrades gracefully on missing inputs.** Repo with no `.github/`, no `package.json`, no test files — still produces a `PipelineSnapshot`, just with lots of `False` and high `reasons_blocked`. Never raise on missing structure.

5. **The `PipelineLens(repo_path=None)` case preserves the stub behavior.** This isn't dead code — it's the fallback for cases where `arguss scan` is invoked on something that isn't a real repo (just a lockfile in isolation, etc.).

6. **Reuse `ZizmorClient` from PR 1.** Don't reimplement zizmor invocation. Don't add new subprocess wrappers.

7. **Stop after each major step.** Suggested order:
   - (a) Models change (TestReality, PipelineSnapshot)
   - (b) Test reality helpers (the four `_has_*` and `_workflow_runs_tests` functions)
   - (c) `fetch_pipeline_snapshot` and subscore aggregation
   - (d) `PipelineLens.scan()` replacement + integration with `arguss scan`
   - (e) CLI command
   - (f) Test fixtures (the six repo directories)
   - (g) Tests (`tests/test_pipeline_lens.py`)
   - (h) Design doc

Let me review between each.

## How to work

Generate code one file at a time. Stop after each step. The test reality helpers (step b) and the snapshot+subscore logic (step c) are the most consequential and most subject to subtle bugs. Read those carefully before tests are written against them.

## Verification commands

After Cursor finishes, I will run:

```bash
uv run pytest tests/test_pipeline_lens.py -v
uv run pytest                                              # full suite still green
uv run ruff check arguss/lenses/pipeline.py arguss/cli.py arguss/core/models.py
uv run mypy arguss/lenses/pipeline.py arguss/cli.py

# CLI sanity checks
uv run arguss pipeline-snapshot tests/fixtures/repos/clean-with-tests/
uv run arguss pipeline-snapshot tests/fixtures/repos/noop-test-script/
uv run arguss pipeline-snapshot tests/fixtures/repos/yarn-tests/
uv run arguss pipeline-snapshot tests/fixtures/repos/workflow-skips-tests/

# Integration test
uv run pytest tests/test_pipeline_lens.py -v -m integration

# End-to-end: real scan now shows real pipeline lens output
uv run arguss scan tests/fixtures/lockfiles/real-world.json
# Pipeline lens previously: score=50, fake stub. Now: real number from
# the parent directory of the lockfile (which contains no .github/ or
# package.json, so test reality will fail with appropriate reasons).
```

All of those must produce reasonable output before the PR opens.

## Out of scope for this PR (explicitly)

- Wiring the `safe_to_auto_merge` bit into the fix-confidence engine — Week 6
- Code coverage analysis — Week 10+
- CI theater detection (e.g., workflow steps with `|| true` masking failures) — Week 10+
- Detecting `tsc --noEmit` as "not really testing" — documented limitation, accepted
- Multi-CI-platform support — out of scope entirely
- Test framework introspection (parsing jest/vitest configs) — out of scope for the lens
- Configurable test reality conditions via a config file — Week 10+
