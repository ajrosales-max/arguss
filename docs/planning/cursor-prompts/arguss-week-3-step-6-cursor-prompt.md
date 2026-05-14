# Cursor prompt — Week 3, Step 6: real vulnerability lens

This branch replaces the fake vulnerability lens with a real implementation backed by the OSV client. After this merges, `arguss scan` produces real CVE findings against real packages — the parser feeds real dependencies, the OSV client finds real vulnerabilities, and the lens converts them into the Findings the dashboard will eventually render.

**Branch name:** `feature/vulnerability-lens`
**Estimated time:** 3-4 hours of focused work.
**Step from Week 3 plan:** Step 6.

---

## What this branch does

1. Rewrites `arguss/lenses/vulnerability.py` to use the OSV client instead of returning fake data
2. Wires the SQLite cache into the CLI so the lens can use it
3. Extracts CVSS scores from heterogeneous OSV records (the OSV schema is messy — different upstream sources include different fields)
4. Maps severity to the Arguss 0-100 scale
5. Generates human-readable remediation advice from OSV's `affected.ranges.events` fixed-version data
6. Computes a lens sub-score from the worst finding

## What this branch does NOT do

- The trust signal lens stays fake (Week 4)
- The pipeline lens stays fake (Week 5)
- EPSS and CISA KEV enrichment are out of scope (Week 10)
- No web UI changes; this is CLI work only

After this merges, your CLI output goes from this:

```
cve: 75.0 (1 findings)        ← fake hardcoded
trust: 40.0 (1 findings)      ← fake
pipeline: 50.0 (1 findings)   ← fake
```

To this:

```
cve: 92.5 (12 findings)       ← real CVEs against real express@4.17.0 tree
trust: 40.0 (1 findings)      ← fake (still)
pipeline: 50.0 (1 findings)   ← fake (still)
```

---

## Before pasting into Cursor

Confirm the OSV client branch is merged and your branch is fresh:

```bash
git status                                # On branch feature/vulnerability-lens, nothing to commit
git log --oneline -3                      # confirm OSV client PR is in the history
ls arguss/lenses/                         # see __init__.py, _osv_client.py, vulnerability.py, trust.py, pipeline.py
uv run pytest                             # full suite green, 46+ tests
```

---

## The prompt to paste into Cursor

I'm starting Week 3 Step 6: replacing the fake vulnerability lens with a real one. The full spec is in `docs/planning/week-3-plan.md` under Step 6.

**The goal:** rewrite `arguss/lenses/vulnerability.py` so that `VulnerabilityLens.scan(deps)` queries OSV for each dep via the `OsvClient` from the previous branch, converts OSV vulnerability records into `Finding` objects, and returns a `LensScore` with a real sub-score.

**Class signature stays the same**, but the constructor changes:

```python
class VulnerabilityLens:
    def __init__(self, cache: Cache, osv_client: OsvClient | None = None) -> None: ...
    def scan(self, deps: list[Dependency]) -> LensScore: ...
```

`cache` is required (the lens needs it to construct an `OsvClient` if one isn't provided). `osv_client` is injectable for testing.

**The scan algorithm:**

```
1. If deps is empty, return LensScore(lens="cve", score=0.0, findings=[]).
2. Call osv.query_batch(deps) — returns dict[name@version → list of full vuln records].
   If OsvError is raised (network down, etc.), return empty LensScore — degrade gracefully.
3. For each dep, get the list of vulns from the result dict.
4. For each vuln record, convert it to a Finding via _vuln_to_finding.
5. Compute the lens sub-score: max(finding.score) across all findings.
6. Return LensScore(lens="cve", score=lens_score, findings=findings).
```

**Helper: `_vuln_to_finding(vuln_record, dep)`**

Builds a Finding from an OSV record. The OSV schema is heterogeneous — different upstream sources (GHSA, NVD, PyPA) put data in different fields. Implement the helper to:

1. Extract the vuln ID from `vuln["id"]`
2. Extract summary from `vuln["summary"]`, falling back to "No summary provided"
3. Extract description from `vuln["details"]`, falling back to summary
4. Extract CVSS via `_extract_cvss(vuln)` — see below
5. Map CVSS to severity via `_cvss_to_severity(cvss)`
6. Normalize CVSS 0-10 to Arguss 0-100 via `_normalize_cvss_to_100(cvss)`
7. Extract fix advice via `_extract_fix_advice(vuln, dep)`
8. Source URL: `f"https://osv.dev/vulnerability/{vuln_id}"`

**Helper: `_extract_cvss(vuln)` — the tricky one**

OSV records can have CVSS in multiple places. The extraction order:

1. `vuln["severity"][i]["score"]` — looks like `"CVSS:3.1/AV:N/AC:L/..."` (the CVSS vector). We don't parse the vector to get the base score (that's a whole algorithm). Skip for now and try the next location.

2. `vuln["database_specific"]["cvss_score"]` — sometimes a direct numeric score. If it's a `int | float`, return as float.

3. `vuln["database_specific"]["cvss"]["score"]` — alternative nesting. Same check.

4. `vuln["database_specific"]["severity"]` — a string like `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`/`"MODERATE"`, `"LOW"`. Map to representative CVSS values:
   - `CRITICAL` → 9.5
   - `HIGH` → 7.5
   - `MEDIUM` or `MODERATE` → 5.0
   - `LOW` → 2.5

5. If nothing found, return `None`.

**Helper: `_cvss_to_severity(cvss)`**

Maps CVSS score to Arguss severity literal:
- None → "medium" (unknown defaults to medium)
- 9.0+ → "critical"
- 7.0-8.9 → "high"
- 4.0-6.9 → "medium"
- 0-3.9 → "low"

**Helper: `_normalize_cvss_to_100(cvss)`**

Maps CVSS 0-10 to Arguss 0-100 scale:
- None → 50.0 (unknown defaults to medium-50)
- Else: `min(100.0, max(0.0, cvss * 10.0))`

**Helper: `_extract_fix_advice(vuln, dep)`**

Walks `vuln["affected"][i]["ranges"][j]["events"][k]` looking for an event with a `"fixed"` key. The first such event tells us the version where the vulnerability was fixed. Match only entries where `affected.package.name == dep.name`.

If found: `f"Upgrade {dep.name} from {dep.version} to {fixed_version} or later"`.

If not found: `f"Check OSV advisory for upgrade guidance: {vuln_id}"`.

**Helper: `_compute_cve_score(findings)`**

Takes the list of findings, returns max score (or 0.0 if empty). This is the lens sub-score.

**CLI wiring (`arguss/cli.py`):**

The `scan` function currently does:

```python
cve = VulnerabilityLens().scan(deps)
```

Update it to:

```python
validate_settings()
conn = get_connection(settings.db_path)
init_db(conn)
cache = Cache(conn)

cve = VulnerabilityLens(cache=cache).scan(deps)
```

Add the needed imports:

```python
from arguss.core.cache import Cache, get_connection, init_db
from arguss.settings import settings, validate_settings
```

The trust and pipeline lenses don't need the cache yet (they're still fake-stubbed).

**Tests (`tests/test_vulnerability_lens.py`):**

Cover:

1. Empty deps → score 0.0, no findings, no OSV calls.
2. No vulns in result → score 0.0, no findings.
3. One critical CVE in result → finding with severity="critical", score ≥ 95, remediation contains the fixed version.
4. Multiple CVEs → lens score = max(finding scores).
5. OSV unreachable (OsvError raised) → returns empty LensScore, doesn't crash.
6. Vuln record with CVSS as a vector string → severity defaults to "medium" (since we don't parse vectors).
7. Vuln record with `database_specific.severity = "HIGH"` → severity is "high", score is 75.0.

Use `MagicMock` for the `OsvClient` in unit tests — these never hit the real OSV API. The integration test from the previous branch already verifies real connectivity.

**Don't add:**

- EPSS or KEV enrichment (Week 10)
- CVSS vector parsing (out of scope for v1; we don't need exact CVSS scores, just severity buckets)
- Async scans (capstone scope is synchronous)
- A "deep" mode that fetches additional metadata per finding (overkill)

**Verification commands I'll run:**

```bash
# Unit tests pass without network
uv run pytest tests/test_vulnerability_lens.py -v

# Full suite green
uv run pytest

# Lint and types
uv run ruff check .
uv run ruff format --check .
uv run mypy arguss

# THE MONEY SHOT — real CVEs in scan output
uv run arguss scan tests/fixtures/lockfiles/real-world.json --format pretty

# JSON form for inspection
uv run arguss scan tests/fixtures/lockfiles/real-world.json | python -m json.tool | head -100
```

After Step 6 lands, the pretty output should look something like:

```
Arguss Scan Result — tests/fixtures/lockfiles/real-world.json
Overall risk: 75.4 / 100   (numbers will vary)
  cve: 92.5 (12 findings)     ← REAL findings, real GHSA IDs
  trust: 40.0 (1 findings)    ← still fake
  pipeline: 50.0 (1 findings) ← still fake
```

The overall score changes meaningfully because the CVE score went from a hardcoded 75 to a real ~92 (express's tree has critical-severity CVEs).

**Start by:** Showing me the rewritten `arguss/lenses/vulnerability.py` with all helpers. Don't update the CLI yet. I want to review the lens in isolation before integration.

After my review, update `arguss/cli.py` (just the lens instantiation).

Then write `tests/test_vulnerability_lens.py`.

Finally, update `docs/qanda/` with a new file `vulnerability-lens.md` documenting the design.

---

## How to work through this with Cursor

The same pause-and-verify rhythm. For this branch specifically:

**After Cursor shows you `vulnerability.py`:**

- Read `_vuln_to_finding` — this is where the OSV-to-Finding translation lives, and where most subtle bugs would hide
- Read `_extract_cvss` carefully — the fallback chain is the part most likely to be wrong
- Make sure `_extract_fix_advice` matches against `dep.name` (without matching, it would attribute fix versions to the wrong package)

**After Cursor updates `cli.py`:**

Before running tests, manually run a scan to see the real output:

```bash
uv run arguss scan tests/fixtures/lockfiles/real-world.json --format pretty
```

This is the **payoff moment of the week**. You should see real findings, real GHSA IDs, real severity scores. If something's off, you'll see it instantly.

**After tests are written:**

Run them. They should all pass with mocked OSV. The integration test from the previous branch still works against real OSV.

---

## What I'd expect the scan output to look like

After this branch, scanning `real-world.json` (the express@4.17.0 fixture) should produce something close to:

- **Overall score:** ~75-85 (weighted average of high CVE + fake-40 trust + fake-50 pipeline)
- **CVE sub-score:** ~90-100 (because path-to-regexp has a critical ReDoS, qs has critical issues)
- **Total findings:** 12 (matches the OSV batch query you ran earlier)
- **Critical findings:** 2-4 (the ones with CVSS 9.0+)
- **Remediation advice:** explicit upgrade suggestions per vulnerable package

The exact numbers depend on what OSV's database has for those CVEs today. Don't worry about matching specific numbers — just verify the *shape* makes sense.

---

## Q&A doc

After the work is done, create `docs/qanda/vulnerability-lens.md`. Suggested questions:

1. **Why does the lens take a `Cache` in the constructor, not just an `OsvClient`?**
   (Hint: dependency injection. The lens creates an OsvClient internally if none is provided, which needs the cache. Tests pass an explicit OsvClient.)

2. **Why doesn't the lens parse CVSS vectors directly?**
   (Hint: the CVSS calculation is its own algorithm (not just a string lookup). For capstone v1, severity buckets are enough — we don't need exact CVSS values.)

3. **What happens if a CVE has no severity data at all?**
   (Hint: defaults to "medium" severity, score 50. Documented because it's a real edge case in OSV data.)

4. **Why does OSV being unreachable degrade gracefully instead of crashing?**
   (Hint: a multi-lens scanner should keep producing useful output even if one data source is down. Returning an empty LensScore lets the other lenses still run.)

5. **What does the lens NOT do today that production tools would?**
   (Hint: EPSS exploit prediction, CISA KEV enrichment, reachability analysis, version-aware suppressions, etc. Document the gaps so reviewers see we considered them.)

---

## Common pitfalls

**Findings have severity="medium" everywhere.** OSV's `severity` field structure varies; if all your findings are medium/50, `_extract_cvss` is hitting the fallback at the end. Inspect a real OSV vuln record:

```bash
uv run python -c "
from arguss.core.cache import Cache, get_connection, init_db
from arguss.lenses._osv_client import OsvClient
from arguss.settings import settings, validate_settings
import json
validate_settings()
conn = get_connection(settings.db_path)
init_db(conn)
client = OsvClient(Cache(conn))
v = client.fetch_vuln('GHSA-rhx6-c78j-4q9w')  # path-to-regexp ReDoS
print(json.dumps(v, indent=2))
"
```

Look at where the severity data lives. Adjust `_extract_cvss` to read the right field.

**Findings have score=50 even when CVSS is set.** `_normalize_cvss_to_100` is using the wrong input. Check that the CVSS value being passed in is the numeric one, not a string.

**Remediation advice says "Check OSV advisory" for everything.** `_extract_fix_advice` isn't walking the affected array correctly. Verify the structure — `affected` is a list, each item has `ranges`, each range has `events`, each event might have `fixed`.

**A test fails on the empty-deps case.** This is the early-return path. The function should return `LensScore(lens="cve", score=0.0, findings=[])` without calling OSV at all.

**The CLI crashes on first scan.** Make sure `validate_settings()` is called before `get_connection()`. The DB path needs to be set up.

---

## Commit, PR, merge

```bash
uv run pytest -v
uv run ruff format .
uv run ruff check .
uv run mypy arguss
uv run arguss scan tests/fixtures/lockfiles/real-world.json --format pretty

# If all green:
git add -A
git commit -m "week3: real vulnerability lens backed by OSV.dev integration"
git push -u origin feature/vulnerability-lens

gh pr create --base main --head feature/vulnerability-lens \
  --title "Week 3 Step 6: real vulnerability lens" \
  --body "Replaces the fake vulnerability lens with a real OSV-backed implementation. Converts OSV vulnerability records into Arguss Finding objects with severity mapping (CRITICAL/HIGH/MEDIUM/LOW), CVSS-derived 0-100 scoring, and fix-version remediation advice. Real-world fixture (express@4.17.0) now produces 12 real CVE findings instead of 1 fake one. Trust and pipeline lenses remain fake-stubbed until Week 4 and Week 5."
```

Wait for CI green. Once merged, the week's biggest engineering milestone is done.

After merge:

```bash
git checkout main
git pull
git checkout -b feature/integration-tests
```

Then come back for Step 7 (which is small — just adding integration test infrastructure that's already partially in place from the OSV client branch). Or `feature/sbom-generator` for Step 8 (CycloneDX SBOM generation), which is more meaty.

---

## What you should have at the end of this branch

1. `arguss/lenses/vulnerability.py` rewritten — no more fake data
2. `arguss/cli.py` updated to wire the cache to the lens
3. `tests/test_vulnerability_lens.py` with 7+ tests, all passing
4. `docs/qanda/vulnerability-lens.md` documenting the design
5. Full test suite at 53+ tests, all green
6. **Real CVE findings in scan output against real-world.json**
7. The pretty-formatted scan output looks like a real security tool, not a skeleton

When all of that's true, ping me with:

- A screenshot or paste of the pretty-formatted scan output (this is the milestone)
- How long it took
- Any tricky OSV record shapes you had to handle in `_extract_cvss`
- Anything else worth flagging

Then we move on to either the SBOM generator or the integration test cleanup.
