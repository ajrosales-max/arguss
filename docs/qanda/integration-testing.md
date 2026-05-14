# Integration testing

## What integration tests are

In Arguss, an integration test is one that talks to a real external service (OSV.dev today; deps.dev and other services in the future). These are **not** full end-to-end system tests — they verify a specific component or pipeline against a real upstream rather than a mock.

## Where integration tests live

All integration tests are in `tests/test_integration_*.py` and marked with `@pytest.mark.integration`. Currently:

- `tests/test_integration_osv.py` — verifies the OSV client talks to real OSV
- `tests/test_integration_lens.py` — verifies the full vulnerability lens pipeline against real OSV

## When to write a unit test vs an integration test

**Unit test (default):** the component is internally consistent. Use mocks for external services. Fast, deterministic, runs on every commit.

**Integration test:** the component depends on an external service's behavior — response shape, version handling, edge cases that mocks can't reliably reproduce. One integration test per external service is usually enough.

## How to run

```bash
# Default — integration tests are deselected (see addopts in pyproject.toml)
uv run pytest

# Just integration tests
uv run pytest -m integration -v

# Everything including integration (clears the marker filter; needs network)
uv run pytest -m "" -v

# Same full suite, overriding addopts explicitly (needs network for integration)
uv run pytest -o addopts="-v --tb=short"
```

## How CI handles integration tests

The CI workflow runs unit tests first (must pass). Integration tests run in a separate step with `continue-on-error: true` — if OSV is having a bad day, the build still succeeds. The integration step's pass/fail is visible on the PR but doesn't block the merge.

## What to do when an integration test fails

In order:

1. Check OSV status: [https://status.osv.dev](https://status.osv.dev) or visit [https://api.osv.dev/v1](https://api.osv.dev/v1)
2. Check whether your local cache is skewed — remove `./arguss.db` (or your `ARGUSS_DB_PATH`) and re-run
3. Check whether OSV's response shape has changed by inspecting a real record (see `docs/qanda/parser-qanda.md` for inspection patterns)
4. If the integration test fails consistently while OSV is healthy, the issue is in our code — fix forward
