# Cursor prompt — Week 3, Step 7: integration test cleanup

This is the final cleanup branch for Week 3's vulnerability lens work. Most of the integration testing infrastructure is already in place from the OSV client branch. This branch:

1. Adds a lens-level integration test (vulnerability lens end-to-end against real OSV)
2. Adds short documentation explaining the integration testing pattern
3. Verifies the integration story is coherent across `pyproject.toml`, the test files, and CI

**Branch name:** `feature/integration-tests`
**Estimated time:** 30-60 minutes. Smallest branch of Week 3.

---

## Before pasting into Cursor

Start from clean main with the vulnerability lens merged:

```bash
git checkout main
git pull
git checkout -b feature/integration-tests

# Verify what already exists from previous branches
ls tests/test_integration_osv.py    # exists (from OSV client branch)
grep -A 2 "integration" pyproject.toml    # marker registered
grep -A 5 "integration" .github/workflows/ci.yml    # CI step exists
```

---

## The prompt to paste into Cursor

I'm completing Week 3 Step 7 — integration test cleanup. Most of the infrastructure is already in place from the OSV client branch (`tests/test_integration_osv.py`, the `integration` pytest marker, the CI step). This branch adds a lens-level integration test and documentation.

**The work:**

1. **Add a vulnerability lens integration test** at `tests/test_integration_lens.py`. This test:
   - Uses a real `OsvClient` (not mocked) talking to real OSV.dev
   - Uses an in-memory SQLite cache (`get_connection(":memory:")`) so it doesn't pollute the developer's local cache
   - Scans a small known-vulnerable dep list (e.g., `lodash@4.17.20` plus `express@4.17.0`)
   - Asserts the lens returns real findings with reasonable scores
   - Marked with `@pytest.mark.integration` so it's skipped by default

2. **Create `docs/qanda/integration-testing.md`** documenting:
   - What integration tests are in this project (and what they are NOT — they're not full system tests)
   - When to write a unit test vs an integration test
   - How to run integration tests locally (`uv run pytest -m integration`)
   - How CI handles integration tests (`continue-on-error: true` — flaky external services don't fail the build)
   - What to do when an integration test fails (check OSV status, check cache, check API contract)

3. **Verify coherence across the project:**
   - `pyproject.toml` has the `integration` marker registered AND `addopts = "-m 'not integration'"` (or equivalent) so the default `pytest` run skips them
   - The CI workflow runs integration tests in a separate step after the main test step
   - Both existing integration tests (the OSV client one, the new lens one) pass when explicitly run with `-m integration`
   - The default `pytest` run shows the integration tests as "deselected" (not failed, not skipped — deselected by marker)

**Files to create:**

1. `tests/test_integration_lens.py` — the new lens-level integration test
2. `docs/qanda/integration-testing.md` — the documentation

**Files to verify but probably not modify:**

1. `pyproject.toml` — confirm marker and addopts are configured
2. `.github/workflows/ci.yml` — confirm integration step exists and uses `continue-on-error`
3. `tests/test_integration_osv.py` — confirm it still works (no changes needed)

**Test design specifics for `test_integration_lens.py`:**

```python
"""Integration tests for the vulnerability lens against real OSV.dev.

These tests hit the live OSV API. They are skipped by default and run
separately via `pytest -m integration`. They prove the full lens pipeline
(parser → OSV client → CVSS parsing → finding generation) works against
real production data.
"""

import sqlite3

import pytest

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import Dependency
from arguss.lenses._osv_client import OsvClient
from arguss.lenses.vulnerability import VulnerabilityLens


@pytest.mark.integration
def test_lens_finds_real_cves_against_known_vulnerable_deps() -> None:
    """Scanning a known-vulnerable dep produces real CVE findings.

    Uses lodash@4.17.20 (multiple known CVEs) and a clean reference dep
    (`is-array@1.0.1`) to verify both the positive and negative cases.
    """
    conn = get_connection(":memory:")
    init_db(conn)
    cache = Cache(conn)
    osv = OsvClient(cache=cache)
    lens = VulnerabilityLens(cache=cache, osv_client=osv)

    deps = [
        Dependency(name="lodash", version="4.17.20", direct=True),
        Dependency(name="is-array", version="1.0.1", direct=True),
    ]

    score = lens.scan(deps)

    # Lodash should produce findings; is-array (a stable obscure package)
    # should not (or shouldn't dominate).
    assert score.score > 0, "Expected real CVE findings from lodash@4.17.20"
    assert len(score.findings) >= 1

    # Findings should be against lodash, not is-array.
    lodash_findings = [f for f in score.findings if f.dependency.name == "lodash"]
    assert len(lodash_findings) >= 1

    # Lens score should reflect the worst finding.
    assert score.score == max(f.score for f in score.findings)

    # At least one finding should have remediation advice with a specific version.
    findings_with_advice = [
        f for f in score.findings if f.remediation and "Upgrade lodash" in f.remediation
    ]
    assert len(findings_with_advice) >= 1
```

**The Q&A doc structure:**

```markdown
# Integration testing

## What integration tests are

In Arguss, an integration test is one that talks to a real external service
(OSV.dev today; deps.dev and other services in the future). These are NOT
full end-to-end system tests — they verify a specific component or pipeline
against a real upstream rather than a mock.

## Where integration tests live

All integration tests are in `tests/test_integration_*.py` and marked with
`@pytest.mark.integration`. Currently:

- `tests/test_integration_osv.py` — verifies the OSV client talks to real OSV
- `tests/test_integration_lens.py` — verifies the full vulnerability lens
  pipeline against real OSV

## When to write a unit test vs an integration test

**Unit test (default):** the component is internally consistent. Use mocks
for external services. Fast, deterministic, runs on every commit.

**Integration test:** the component depends on an external service's
behavior — response shape, version handling, edge cases that mocks can't
reliably reproduce. One integration test per external service is usually
enough.

## How to run

```bash
# Default — skips integration tests
uv run pytest

# Just integration tests
uv run pytest -m integration

# Everything including integration
uv run pytest -m ""
```

## How CI handles integration tests

The CI workflow runs unit tests first (must pass). Integration tests run
in a separate step with `continue-on-error: true` — if OSV is having a
bad day, the build still succeeds. The integration step's pass/fail is
visible on the PR but doesn't block the merge.

## What to do when an integration test fails

In order:

1. Check OSV status: https://status.osv.dev or visit https://api.osv.dev/v1
2. Check whether your local cache is up to date — `rm arguss.db` and re-run
3. Check whether OSV's response shape has changed by inspecting a real
   record (see the parser-qanda.md for the inspection one-liner)
4. If the integration test fails consistently while OSV is healthy, the
   issue is in our code — fix forward
```

**Verification:**

```bash
# Unit tests still green by default
uv run pytest

# Integration tests pass when explicitly run
uv run pytest -m integration -v

# Both together
uv run pytest -m "" -v

# Lint and types
uv run ruff format --check .
uv run ruff check .
uv run mypy arguss
```

**Don't add:**

- A test runner script or shell wrapper (`uv run pytest -m integration` is simple enough)
- A new pytest plugin or fixture for integration setup
- Live network mocking via responses/httpretty
- Async support
- A separate CI workflow file for integration

---

## How to work through this with Cursor

This is a small branch. The pause-and-verify rhythm is less critical here than for the parser or lens, but still:

1. Cursor writes `test_integration_lens.py`
2. Verify it: `uv run pytest -m integration -v` — should show 2 passing tests now (the existing OSV client one + the new lens one)
3. Cursor writes the Q&A doc
4. Skim it; make sure the "when to write a unit test vs integration test" section makes sense for your team
5. Commit, push, PR, merge

**One thing to call out before Cursor starts:** the test uses `is-array@1.0.1` as a clean reference dep. If that package happens to have a published CVE since I last checked, the test's assumption breaks. If the verification step shows findings for is-array, pick a different obscure stable package (e.g., `left-pad@1.3.0` — well-known to be vuln-free historically) and update the test.

---

## After the work is done

```bash
uv run pytest -v          # default: green
uv run pytest -m integration -v   # integration: 2 tests pass

git add -A
git commit -m "week3: lens-level integration test + integration testing docs"
git push -u origin feature/integration-tests

gh pr create --base main --head feature/integration-tests \
  --title "Week 3 Step 7: integration test cleanup" \
  --body "Adds a lens-level integration test (vulnerability lens end-to-end against real OSV) and documents the integration testing pattern. The OSV client integration test already exists from the previous branch; this completes the integration testing story for Week 3.

Default pytest run still excludes integration tests. CI runs them in a separate step with continue-on-error so transient OSV issues don't block builds.

Tests cover:
- OSV client: query_single against lodash@4.17.20 (existing)
- Vulnerability lens: full pipeline against lodash@4.17.20 (new)

This is the last branch of the Week 3 core deliverables. Week 4 (trust signal lens) starts next."
```

---

## What you should have at the end of this branch

1. `tests/test_integration_lens.py` exists with one passing integration test
2. `docs/qanda/integration-testing.md` exists and is coherent
3. Default `pytest` run still passes (integration tests deselected)
4. `pytest -m integration` passes 2 tests (OSV client + lens)
5. CI passes (with integration tests running but `continue-on-error`)

When all of that's true, you've completed the core Week 3 deliverables. The SBOM generator (Step 8) is optional from here — useful but not required for the syllabus.

Ping me when:

- Both integration tests pass when run with `-m integration`
- Default test suite is still green
- Anything Cursor surprised you with

Then we'll decide together whether to do Step 8 (SBOM) or move into Week 4 (trust signals).
