# Cursor prompt — Week 3, Step 4+5: OSV.dev API client

This branch implements the OSV.dev API client — the component that knows how to fetch vulnerability data for npm packages. The vulnerability lens (next branch) will use this client.

**Branch name:** `feature/osv-client`
**Estimated time:** 2-3 hours of focused work.
**Steps combined:** Step 4 (client scaffolding + single query) and Step 5 (batching). Both in one branch because they share the same module.

---

## What this branch does NOT do

To be clear up front:

- It doesn't change the existing vulnerability lens (still returns fake data — replaced in the next branch)
- It doesn't touch the CLI (no user-facing changes yet)
- It doesn't add any real CVE findings to scans (those land in `feature/vulnerability-lens`)

This is **infrastructure work**. The client is a building block; the lens that uses it is the next branch.

---

## Before pasting into Cursor

Verify the branch is clean and rooted at current main:

```bash
git status                    # should show "On branch feature/osv-client" and "nothing to commit"
git log --oneline -5          # confirm parser PR is merged into main and on this branch
ls arguss/lenses/             # should show __init__.py, vulnerability.py, trust.py, pipeline.py
```

---

## The prompt to paste into Cursor

I'm starting Week 3 Step 4-5: implementing the OSV.dev API client. The full spec is in `docs/planning/week-3-plan.md` under Steps 4 and 5.

**The goal:** an `OsvClient` class in `arguss/lenses/_osv_client.py` that can query OSV.dev for vulnerabilities affecting npm packages. It caches all responses in SQLite via the existing `Cache` class.

**Two query methods:**

1. `query_single(name, version, ecosystem="npm")` — looks up vulns for a single package@version. Returns list of vulnerability IDs. Uses OSV's `POST /v1/query` endpoint.
2. `query_batch(deps)` — looks up vulns for many deps at once via OSV's `POST /v1/querybatch`. Returns dict mapping `"name@version"` → list of full vulnerability records. Internally dedupes by (ecosystem, name, version), fetches unique vuln IDs via `fetch_vuln`, and assembles the result.

**One fetch method:**

3. `fetch_vuln(vuln_id)` — fetches a full vulnerability record by ID via OSV's `GET /v1/vulns/{id}`. Cached for 7 days (records change rarely once published).

**Caching:**

- Batch query results cached for 24h, keyed by a hash of the (ecosystem, name, version) set
- Single query results cached for 24h, keyed by (ecosystem, name, version)
- Full vuln records cached for 7 days, keyed by vuln ID
- All caching uses the existing `arguss.core.cache.Cache` class — don't add a new cache implementation

**Files to create:**

1. `arguss/lenses/_osv_client.py` — the `OsvClient` class plus helper functions
2. `tests/test_osv_client.py` — unit tests using `httpx.MockTransport` (no live network)
3. `tests/test_integration_osv.py` — one integration test marked `@pytest.mark.integration` that hits real OSV (skipped by default, run with `pytest -m integration`)

**Files to modify:**

1. `pyproject.toml` — add the `integration` marker to pytest config
2. `.github/workflows/ci.yml` — add an integration test step that runs after the regular tests (with `continue-on-error: true` so OSV flakes don't break the build)

**Use the exact code from Steps 4-5 of the week-3-plan.md as the starting point.** Two adjustments I want compared to that spec:

1. The HTTP client should use a longer timeout for batch queries (15 seconds instead of 10), because batch queries can be slower than single queries when OSV is busy.

2. The `User-Agent` header should include the project URL: `arguss/0.1.0 (https://github.com/<your-org>/arguss)` — this is polite OSV API etiquette and makes the traffic identifiable if OSV's operators ever need to debug something.

**Don't add:**

- A separate connection pool, retry library, or backoff logic (httpx's defaults are fine for capstone)
- Pydantic models for OSV responses (the response shape is too heterogeneous — keep `dict[str, Any]`)
- A "warmup" or "ping" method (not needed)
- Async HTTP support (not needed for capstone scope)
- A "real" OSV API wrapper for production use cases (we're consuming the API directly)

**The integration test:**

The integration test should call `OsvClient.query_single("lodash", "4.17.20")` and assert that at least one vulnerability ID is returned. `lodash@4.17.20` has multiple known CVEs, so this is a stable test target. The test verifies our code talks to OSV correctly at runtime — different from unit tests, which only verify our code is internally consistent.

**Verification commands I'll run after you finish:**

```bash
# Unit tests pass with no network
uv run pytest tests/test_osv_client.py -v

# Full suite still green (including all 17+ existing tests)
uv run pytest

# Lint and types
uv run ruff check .
uv run mypy arguss

# Integration test against real OSV (one-off check)
uv run pytest -m integration -v

# Manual smoke test: query OSV for known-vulnerable lodash
uv run python -c "
from arguss.core.cache import Cache, get_connection, init_db
from arguss.lenses._osv_client import OsvClient
from arguss.settings import settings, validate_settings
validate_settings()
conn = get_connection(settings.db_path)
init_db(conn)
client = OsvClient(Cache(conn))
ids = client.query_single('lodash', '4.17.20')
print('lodash@4.17.20 vulns:', ids[:3])
"
```

**Start by:** Showing me the `OsvClient` class skeleton with just `__init__` and `query_single`. Don't implement `query_batch` or `fetch_vuln` yet. I want to review the class structure (HTTP client setup, cache integration, error handling pattern) before you build out the rest.

After my review, implement `fetch_vuln`, then `query_batch`, then helpers (`_hash_query_set`, any others needed).

Finally, write the unit tests (`tests/test_osv_client.py`), then the integration test (`tests/test_integration_osv.py`), then update `pyproject.toml` and `.github/workflows/ci.yml`.

---

## How to work through this with Cursor

The same pause-and-verify rhythm. For this branch specifically:

**After Cursor shows the class skeleton with `query_single`:**

- Read the HTTP client setup. Is the timeout reasonable? Is the User-Agent set?
- Read the cache key construction. Is the key unique enough? Stable across runs?
- Read the error handling. What happens if OSV returns 500? 404? Times out?
- **Test it before continuing.** Run the manual smoke test from the verification commands. Real OSV traffic, real cache write, real response. If this works, the rest of the client is straightforward.

**After `fetch_vuln` and `query_batch` are added:**

- Read `query_batch` carefully — it does two-phase querying (batch IDs, then individual records). The dedup logic matters; same package@version appearing multiple times in the dep tree should only fire one query.
- Mentally trace through: 10 deps, 3 unique (name, version), 5 vulns total → how many OSV calls? Answer: 1 batch call + 5 record fetches = 6 calls. (First run; cache makes subsequent runs free.)

**After unit tests are written:**

- Run them. They should all pass with no network access.
- Run `pytest -m integration` — that's the one test that does hit the network. Should also pass.

**Before opening the PR:**

- Run the manual smoke test from the verification list above
- Confirm `pytest` (with default marker exclusion) still has 17+ tests green
- Confirm `pytest -m integration` has at least 1 passing test

---

## Q&A doc

After the work is done, create `docs/qanda/osv-client.md` with these questions answered. Cursor can draft this; you should review and adjust:

1. **Why is the OSV client separate from the vulnerability lens?**
   (Hint: separation of concerns — client knows about HTTP and OSV's API; lens knows about scoring and Findings. Each can be tested in isolation. If OSV ever changes its API, only the client changes.)

2. **Why are batch queries cached separately from individual records?**
   (Hint: different cache lifetimes. Batch results are queries against a specific dep set; records are stable identifiers. Caching them together would waste cache space or invalidate too aggressively.)

3. **Why does `query_batch` dedupe by (ecosystem, name, version) before querying?**
   (Hint: same package can appear at multiple paths in a transitive tree. The lockfile lists `lodash` once per installation location, but they're all the same package as far as OSV is concerned.)

4. **What happens if OSV is down?**
   (Hint: `OsvError` raised. The vulnerability lens catches it and returns an empty `LensScore` so the scan can continue with other lenses.)

5. **How does the client handle a malformed OSV response?**
   (Hint: today, it doesn't — JSON parse failure would propagate as an exception. Acceptable for capstone scope; future work would add response schema validation.)

---

## Common pitfalls and how to spot them

**Tests pass but the manual smoke test returns an empty list.** Either OSV is genuinely down (rare), `lodash@4.17.20` was renamed/deleted (unlikely), or your User-Agent / request format is off. Check by running `curl -s 'https://api.osv.dev/v1/query' -d '{"package":{"ecosystem":"npm","name":"lodash"},"version":"4.17.20"}'` — if curl returns vulns and your code doesn't, the bug is in the client.

**Mocked tests pass but integration tests fail.** Your mock's response shape doesn't match OSV's real response shape. Compare your test fixtures to a real OSV response. The common mismatch is fields nested differently than expected.

**Cache key collisions.** Two different queries returning the same cached result. Unlikely with the spec'd key format `f"single:{ecosystem}:{name}:{version}"`, but worth verifying. The key must be unique per query input.

**Mypy complains about `dict[str, Any]` returns.** The OSV response is genuinely unstructured (heterogeneous schema). Use `dict[str, Any]` deliberately. Don't let Cursor add `TypedDict` or Pydantic models — they'll be wrong for at least some OSV records.

**The integration test takes 30+ seconds.** OSV's batch endpoint can be slow on first query. Either bump the timeout in the test or accept the slowness (it's run separately, not in normal CI).

---

## Commit, PR, merge

```bash
uv run pytest -v
uv run ruff format .
uv run mypy arguss
uv run pytest -m integration -v  # one-off, may take 10-30 seconds

git add arguss/lenses/_osv_client.py tests/test_osv_client.py tests/test_integration_osv.py pyproject.toml .github/workflows/ci.yml docs/qanda/osv-client.md
git commit -m "week3: osv.dev api client with batching and caching"
git push -u origin feature/osv-client

gh pr create --base main --head feature/osv-client \
  --title "Week 3 Step 4-5: OSV.dev API client" \
  --body "Implements OsvClient with single-query, batch-query, and vuln-record-fetch methods. All responses cached in SQLite (batch: 24h, records: 7 days). Unit tests use httpx.MockTransport (no network). One integration test hits real OSV.dev API, marked separately so it doesn't block normal CI. Vulnerability lens still returns fake data — real integration lands in next branch."
```

Wait for CI green. The integration test in CI might or might not pass on any given day depending on OSV's availability — the `continue-on-error: true` means it won't block the merge.

After merge:

```bash
git checkout main
git pull
git checkout -b feature/vulnerability-lens
```

Then come back for the lens prompt.

---

## What you should have at the end of this branch

1. `arguss/lenses/_osv_client.py` with the `OsvClient` class
2. `tests/test_osv_client.py` with 6-10 unit tests, all passing offline
3. `tests/test_integration_osv.py` with one integration test, passing against real OSV
4. `pyproject.toml` updated with the `integration` marker
5. `.github/workflows/ci.yml` running integration tests in CI with `continue-on-error`
6. `docs/qanda/osv-client.md` documenting the design decisions
7. Manual smoke test returns real vuln IDs for `lodash@4.17.20`
8. Full test suite (default) at 23+ tests, all green
9. Cache populated with real OSV data after first run

When all of that is true, ping me with:

- The output of the manual smoke test (how many vulns did lodash@4.17.20 have?)
- The number of unit tests added
- Anything Cursor surprised you with, good or bad
