# Arguss — Week 3 Cursor Plan

**Goal:** Replace the fake vulnerability lens with a real implementation backed by a real npm package-lock.json parser and the OSV.dev API. Add a CycloneDX SBOM generator as a side-deliverable that reuses the same parser output.

**Syllabus context:** Week 3 (May 20, 2026). 1-2 page Project Overview is due before live session; this build work happens alongside.

**Prereqs:** Day 1 skeleton is complete. `arguss scan` produces JSON. All 8 canary tests are green. Live URL is up at https://arguss-*.fly.dev. SQLite cache module is wired up.

---

## Working with Cursor for this plan

This plan has 10 steps. Each step is independently mergeable — when one is done, commit and move to the next. Don't let Cursor combine steps. The pattern that worked on Day 1 still applies: paste one step into Cursor's chat or composer, review what it generates, run the verification command, commit, move on.

A few principles specific to this week:

**No live network calls in unit tests.** Every test that touches the OSV client uses a mock. The real OSV API is only hit in a single integration test marked `@pytest.mark.integration`, run separately. This keeps the test suite fast (under 2 seconds) and offline-safe.

**The data model is fixed.** The `Dependency`, `Finding`, and `LensScore` types from Day 1 don't change. The whole point of the skeleton was that swapping fake implementations for real ones doesn't require touching the contracts. If Cursor wants to "improve" the models, push back.

**Resist OSV schema scope creep.** OSV's vulnerability records are heterogeneous (GHSA, CVE, NVD, PyPA all have different shapes). v1 of the lens handles the common case (CVSS in `severity[]`, version ranges in `affected[].ranges[]`) and treats edge cases as "medium severity, score 50" with a comment. Don't try to handle every OSV quirk this week.

**Cache aggressively.** Every external API call goes through the SQLite cache. Tests verify this. A cached scan should never hit the network.

---

## Step 1 — Test fixtures (real lockfiles)

Before writing any parser code, get real `package-lock.json` files into the repo as test data. The parser is much easier to write when you can run it against known inputs.

**Cursor prompt:**

> I need three test fixtures in `tests/fixtures/lockfiles/`. Don't generate these from scratch — instead, write a small Python script at `tests/fixtures/fetch_fixtures.py` that downloads them from public repos. The script should be re-runnable. Then run it.

Or, do this manually (which is simpler):

### Fixture 1: `tests/fixtures/lockfiles/minimal.json`

Construct by hand. Minimal valid lockfile with 3-4 deps:

```json
{
  "name": "minimal-test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "minimal-test",
      "version": "1.0.0",
      "dependencies": {
        "left-pad": "1.3.0"
      }
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
    }
  }
}
```

**Acceptance:** 1 direct dep (`left-pad`), 0 transitive deps. Total: 1 dep.

### Fixture 2: `tests/fixtures/lockfiles/with-transitive.json`

A real lockfile with transitive deps. Easiest way to get one:

```bash
mkdir /tmp/arguss-fixture-2
cd /tmp/arguss-fixture-2
npm init -y
npm install chalk@4.1.2
cp package-lock.json /Users/arosales_restore/Documents/MICS/C295/arguss/tests/fixtures/lockfiles/with-transitive.json
```

`chalk@4.1.2` pulls in `ansi-styles`, `supports-color`, etc. — a small but real transitive tree.

**Acceptance:** ~5-10 deps total, 1 direct (`chalk`), the rest transitive. Document the exact count by inspecting the file.

### Fixture 3: `tests/fixtures/lockfiles/real-world.json`

Same approach but bigger. A package known to have CVEs in old versions is best for later OSV testing:

```bash
mkdir /tmp/arguss-fixture-3
cd /tmp/arguss-fixture-3
npm init -y
npm install express@4.17.0    # Known to have some old CVEs in its tree
cp package-lock.json /Users/arosales_restore/Documents/MICS/C295/arguss/tests/fixtures/lockfiles/real-world.json
```

**Acceptance:** 40-60 deps. At least one transitive dep has a known historical CVE. Document approximate dep count.

### Add a README to the fixtures folder

**File:** `tests/fixtures/lockfiles/README.md`

```markdown
# Test lockfile fixtures

| File | Source | Direct deps | Total deps | Known CVEs |
|---|---|---|---|---|
| `minimal.json` | hand-crafted | 1 | 1 | none |
| `with-transitive.json` | `npm install chalk@4.1.2` | 1 | ~5-10 | none |
| `real-world.json` | `npm install express@4.17.0` | 1 | ~50 | yes (qs, body-parser, etc.) |

To regenerate: see `tests/fixtures/fetch_fixtures.py` or follow steps in the Week 3 plan.

Do NOT modify these by hand. If a fixture needs updating, regenerate from the source command and commit the new file as a single atomic change.
```

**Verification:**

```bash
ls tests/fixtures/lockfiles/
# Should show: README.md, minimal.json, real-world.json, with-transitive.json

# Check the lockfile versions
for f in tests/fixtures/lockfiles/*.json; do
  echo "$f:"; python3 -c "import json; print('  v' + str(json.load(open('$f'))['lockfileVersion']))"
done
```

All three should report `v3`. If `real-world.json` came out as v2, your `npm` version is older; either upgrade npm or regenerate with `--lockfile-version=3`.

**Commit:**

```bash
git add tests/fixtures/lockfiles/
git commit -m "week3: add three lockfile test fixtures"
```

---

## Step 2 — Parser module

**Goal:** A `parse_lockfile(path)` function that turns a `package-lock.json` v3 into `list[Dependency]` objects with full transitive paths.

**Cursor prompt:**

> Implement `arguss/core/parser.py` with the function `parse_lockfile(path: str | Path) -> list[Dependency]` per the spec below. Don't add any features beyond what's specified.
>
> **What it does:**
> 1. Accept either a path to a `package-lock.json` file OR a path to a directory containing one. If a directory, look for `package-lock.json` in it.
> 2. Load and parse the JSON.
> 3. Validate `lockfileVersion == 3`. If not, raise `ParserError` with a message naming the version found.
> 4. Read the root package at `packages[""]`. Its `dependencies` and `devDependencies` keys list direct deps.
> 5. For each entry in `packages` (excluding the empty-key root):
>    - The key is a path like `node_modules/foo` or `node_modules/foo/node_modules/bar`.
>    - The package name is the segment after the last `node_modules/`.
>    - The transitive chain is the sequence of `node_modules/X` segments.
>    - Build a `Dependency` with:
>      - `name` = last segment
>      - `version` = entry's `version` field
>      - `ecosystem` = "npm"
>      - `direct` = True if `name` is in the root's `dependencies` or `devDependencies`
>      - `path` = `["root", ...chain]` ending with this package's name
>      - `parents` = direct parents (the package one level up in the chain, or `["root"]` if top-level)
> 6. Skip entries with `link: true`, `extraneous: true`, or paths not starting with `node_modules/`.
> 7. Return the list. Order doesn't matter functionally but sorting by name then version makes diffs cleaner.
>
> **Don't include:**
> - Lockfile v1 or v2 support (raise on these for now)
> - npm workspaces support (skip workspace entries silently with a one-line comment noting future work)
> - `peerDependencies` resolution (these aren't in `packages`)
> - Resolution of version ranges to specific versions (lockfile already did that)
>
> Use the contents below as the starting structure.

**File: `arguss/core/parser.py`**

```python
"""Parser for npm package-lock.json files.

Supports lockfile version 3 only. v1 and v2 are out of scope for capstone v1.
npm workspaces are out of scope; workspace entries are skipped silently.

The parser produces Dependency objects with full transitive path information,
which feeds both the vulnerability lens (for blast radius analysis) and the
CycloneDX SBOM generator.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from arguss.core.models import Dependency


class ParserError(Exception):
    """Raised when a lockfile is missing, unreadable, or unsupported."""


def parse_lockfile(path: str | Path) -> list[Dependency]:
    """Parse an npm package-lock.json (v3) into Dependency objects.

    Args:
        path: Path to a package-lock.json file, OR a directory containing one.

    Returns:
        A list of Dependency objects, sorted by (name, version). The root
        package itself is excluded. Each Dependency has a fully-populated
        transitive path.

    Raises:
        ParserError: If the file is missing, unreadable, or not lockfile v3.
    """
    lockfile_path = _resolve_lockfile_path(path)
    data = _load_lockfile(lockfile_path)
    _validate_lockfile_version(data, lockfile_path)

    direct_dep_names = _extract_direct_dep_names(data)
    packages = data.get("packages", {})

    deps: list[Dependency] = []
    for pkg_path, pkg_data in packages.items():
        if pkg_path == "":
            continue  # root package
        if not pkg_path.startswith("node_modules/"):
            continue  # workspace or other non-standard entry
        if pkg_data.get("link") or pkg_data.get("extraneous"):
            continue

        dep = _build_dependency(pkg_path, pkg_data, direct_dep_names)
        if dep is not None:
            deps.append(dep)

    deps.sort(key=lambda d: (d.name, d.version))
    return deps


def _resolve_lockfile_path(path: str | Path) -> Path:
    """Accept either a file path or a directory; return the lockfile path."""
    p = Path(path).resolve()
    if p.is_dir():
        candidate = p / "package-lock.json"
        if not candidate.exists():
            raise ParserError(f"No package-lock.json found in {p}")
        return candidate
    if not p.exists():
        raise ParserError(f"Lockfile not found: {p}")
    return p


def _load_lockfile(path: Path) -> dict[str, Any]:
    """Load and JSON-parse the lockfile, raising ParserError on any issue."""
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ParserError(f"Invalid JSON in {path}: {e}") from e
    except OSError as e:
        raise ParserError(f"Cannot read {path}: {e}") from e


def _validate_lockfile_version(data: dict[str, Any], path: Path) -> None:
    """Ensure the lockfile is v3. v1 and v2 are not supported in capstone v1."""
    version = data.get("lockfileVersion")
    if version != 3:
        raise ParserError(
            f"{path}: lockfile version {version!r} is not supported. "
            "Arguss v1 supports lockfileVersion 3 only. "
            "Run `npm install` with npm 7+ to generate v3 lockfiles."
        )


def _extract_direct_dep_names(data: dict[str, Any]) -> set[str]:
    """Get the set of direct dep names from the root package entry."""
    root = data.get("packages", {}).get("", {})
    names: set[str] = set()
    for key in ("dependencies", "devDependencies"):
        names.update((root.get(key) or {}).keys())
    return names


def _build_dependency(
    pkg_path: str,
    pkg_data: dict[str, Any],
    direct_dep_names: set[str],
) -> Dependency | None:
    """Build a Dependency from a packages-entry path and its data."""
    version = pkg_data.get("version")
    if not version:
        return None  # weird entry, skip

    chain = _parse_package_path(pkg_path)
    if not chain:
        return None

    name = chain[-1]
    return Dependency(
        name=name,
        version=version,
        ecosystem="npm",
        direct=(name in direct_dep_names),
        path=["root", *chain],
        parents=[chain[-2]] if len(chain) > 1 else ["root"],
    )


def _parse_package_path(pkg_path: str) -> list[str]:
    """Split a node_modules path into its package-name chain.

    'node_modules/foo' → ['foo']
    'node_modules/foo/node_modules/bar' → ['foo', 'bar']
    'node_modules/@scope/pkg' → ['@scope/pkg']
    'node_modules/foo/node_modules/@scope/bar' → ['foo', '@scope/bar']
    """
    if not pkg_path.startswith("node_modules/"):
        return []

    # Split on /node_modules/ to separate the chain
    parts = pkg_path.split("/node_modules/")
    # First part starts with "node_modules/" — strip it
    parts[0] = parts[0].removeprefix("node_modules/")
    return [p for p in parts if p]
```

**File: `tests/test_parser.py`**

**Cursor prompt:**

> Create the test suite at `tests/test_parser.py` covering: minimal lockfile parsing, transitive path tracing, scoped package names (`@scope/pkg`), rejection of v1/v2 lockfiles, directory-input support, and the real-world fixture's expected counts.

```python
"""Tests for the package-lock.json parser."""

from pathlib import Path

import pytest

from arguss.core.parser import ParserError, parse_lockfile

FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"


def test_parses_minimal_lockfile() -> None:
    deps = parse_lockfile(FIXTURES / "minimal.json")
    assert len(deps) == 1
    assert deps[0].name == "left-pad"
    assert deps[0].direct is True
    assert deps[0].path == ["root", "left-pad"]
    assert deps[0].parents == ["root"]


def test_handles_directory_input(tmp_path: Path) -> None:
    """Passing a directory finds package-lock.json inside it."""
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {"name": "x", "version": "1.0.0"}}}'
    )
    deps = parse_lockfile(tmp_path)
    assert deps == []


def test_rejects_v1_lockfile(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text('{"lockfileVersion": 1, "dependencies": {}}')
    with pytest.raises(ParserError, match="version"):
        parse_lockfile(bad)


def test_rejects_v2_lockfile(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text('{"lockfileVersion": 2, "packages": {}}')
    with pytest.raises(ParserError, match="version"):
        parse_lockfile(bad)


def test_missing_lockfile_raises(tmp_path: Path) -> None:
    with pytest.raises(ParserError, match="not found"):
        parse_lockfile(tmp_path / "does-not-exist.json")


def test_directory_without_lockfile_raises(tmp_path: Path) -> None:
    with pytest.raises(ParserError, match="No package-lock.json"):
        parse_lockfile(tmp_path)


def test_transitive_path_correctly_traced() -> None:
    deps = parse_lockfile(FIXTURES / "with-transitive.json")
    # chalk should be the direct dep
    chalk = next((d for d in deps if d.name == "chalk"), None)
    assert chalk is not None
    assert chalk.direct is True

    # ansi-styles is a transitive dep of chalk
    ansi = next((d for d in deps if d.name == "ansi-styles"), None)
    assert ansi is not None
    assert ansi.direct is False
    assert "root" in ansi.path


def test_scoped_packages() -> None:
    """Scoped packages like @types/node are parsed correctly."""
    deps = parse_lockfile(FIXTURES / "with-transitive.json")
    # At least verify the parser doesn't crash on real-world inputs.
    # If chalk@4.1.2's tree includes any scoped packages, this verifies them.
    for dep in deps:
        if dep.name.startswith("@"):
            assert "/" in dep.name, f"Scoped name must include slash: {dep.name}"


def test_real_world_fixture_has_many_deps() -> None:
    """Sanity-check the real-world fixture produces a meaningful tree."""
    deps = parse_lockfile(FIXTURES / "real-world.json")
    assert len(deps) > 20, f"Expected many deps in real-world fixture, got {len(deps)}"
    direct = [d for d in deps if d.direct]
    assert len(direct) >= 1
```

**Verification:**

```bash
uv run pytest tests/test_parser.py -v
```

All tests green. If `real-world.json` test fails with wrong dep count, adjust the assertion to match what your specific fixture produced.

**Commit:**

```bash
git add arguss/core/parser.py tests/test_parser.py
git commit -m "week3: package-lock.json v3 parser with transitive path tracing"
```

---

## Step 3 — Wire parser into CLI

**Goal:** `arguss scan ./real-project` uses the real parser instead of `_fake_deps()`. The two other lenses stay fake for now.

**Cursor prompt:**

> Update `arguss/cli.py` to use `parse_lockfile` instead of `_fake_deps`. Delete `_fake_deps` entirely. Handle the case where the parser raises `ParserError` (print the message and exit 1).

**Change in `arguss/cli.py`:**

Find the `scan` function. Replace this:

```python
    # WEEK 3: Replace with real parser.parse_lockfile(project_path)
    deps = _fake_deps()
```

With this:

```python
    try:
        deps = parse_lockfile(project_path)
    except ParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
```

Add the imports at the top of `cli.py`:

```python
from arguss.core.parser import ParserError, parse_lockfile
```

Delete the `_fake_deps()` function entirely.

**Update the canary test in `tests/test_skeleton.py`:**

The existing `test_cli_runs_end_to_end` passes a minimal lockfile but the test still works because the parser handles it. Verify by running the existing tests — they should still pass.

**Verification:**

```bash
# All existing tests still pass
uv run pytest

# Real scan against the minimal fixture
uv run arguss scan tests/fixtures/lockfiles/minimal.json
# Should show overall ~57 (CVE still fake), but with real deps in the output

# Real scan against the transitive fixture
uv run arguss scan tests/fixtures/lockfiles/with-transitive.json --format pretty

# Scan against a directory works
uv run arguss scan tests/fixtures/lockfiles  # should fail — no package-lock.json there
```

**Commit:**

```bash
git add arguss/cli.py tests/test_skeleton.py
git commit -m "week3: cli uses real parser, removes _fake_deps"
```

---

## Step 4 — OSV.dev client (scaffolding)

**Goal:** A class that knows how to talk to OSV.dev, with caching but no batching yet. Get a single working query first.

**Cursor prompt:**

> Create `arguss/lenses/_osv_client.py` with the class skeleton below. Implement only `query_single(name, version)` for now — batching comes in the next step. Wire up httpx with sensible timeouts and a user agent. Cache responses using the existing `Cache` class.

**File: `arguss/lenses/_osv_client.py`**

```python
"""Client for the OSV.dev API.

OSV.dev (Open Source Vulnerabilities) is a free, well-maintained vulnerability
database aggregating from NVD, GHSA, PyPA, and others.

API docs: https://osv.dev/docs/

Two endpoints used:
- POST /v1/querybatch  : look up vulnerability IDs by package+version (batched)
- GET  /v1/vulns/{id}  : fetch a full vulnerability record by ID

All responses are cached via the SQLite Cache. The batch query cache is keyed
by a hash of the query set; individual vuln records are cached by ID.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import httpx

from arguss.core.cache import Cache
from arguss.core.models import Dependency
from arguss.settings import settings

OSV_API_BASE = "https://api.osv.dev"
DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class OsvError(Exception):
    """Raised when OSV API calls fail in a way the lens should report."""


class OsvClient:
    """Client for the OSV.dev vulnerability database."""

    def __init__(
        self,
        cache: Cache,
        http_client: httpx.Client | None = None,
        api_base: str | None = None,
    ) -> None:
        self.cache = cache
        self.api_base = api_base or settings.osv_api_base or OSV_API_BASE
        self._http = http_client or httpx.Client(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "arguss/0.1.0 (capstone)"},
        )

    def query_single(self, name: str, version: str, ecosystem: str = "npm") -> list[str]:
        """Query OSV for a single package+version. Returns list of vuln IDs.

        Cached for 24h.
        """
        cache_key = f"single:{ecosystem}:{name}:{version}"
        cached = self.cache.get_api_response("osv", cache_key)
        if cached is not None:
            return cached.get("ids", [])

        payload = {
            "package": {"ecosystem": ecosystem, "name": name},
            "version": version,
        }
        try:
            resp = self._http.post(f"{self.api_base}/v1/query", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise OsvError(f"OSV API call failed for {name}@{version}: {e}") from e

        data = resp.json()
        vuln_ids = [v["id"] for v in data.get("vulns", [])]
        self.cache.set_api_response(
            "osv", cache_key, {"ids": vuln_ids}, ttl_hours=settings.cache_ttl_hours
        )
        return vuln_ids

    def fetch_vuln(self, vuln_id: str) -> dict[str, Any]:
        """Fetch a full vulnerability record by ID. Cached for 7 days."""
        cache_key = f"vuln:{vuln_id}"
        cached = self.cache.get_api_response("osv", cache_key)
        if cached is not None:
            return cached

        try:
            resp = self._http.get(f"{self.api_base}/v1/vulns/{vuln_id}")
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise OsvError(f"OSV API call failed for vuln {vuln_id}: {e}") from e

        data: dict[str, Any] = resp.json()
        self.cache.set_api_response("osv", cache_key, data, ttl_hours=24 * 7)
        return data

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self) -> OsvClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _hash_query_set(deps: list[Dependency]) -> str:
    """Stable hash of a dep set for caching batch query results."""
    fingerprint = sorted((d.ecosystem, d.name, d.version) for d in deps)
    return hashlib.sha256(json.dumps(fingerprint).encode()).hexdigest()[:16]
```

**File: `tests/test_osv_client.py`**

```python
"""Tests for the OSV client. Uses httpx MockTransport — no live network calls."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from arguss.core.cache import Cache, get_connection, init_db
from arguss.lenses._osv_client import OsvClient, OsvError


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    conn = get_connection(tmp_path / "test.db")
    init_db(conn)
    return Cache(conn)


def _mock_transport(handler):  # type: ignore[no-untyped-def]
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_query_single_returns_vuln_ids(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"vulns": [{"id": "GHSA-1111-2222-3333"}, {"id": "CVE-2024-0001"}]},
        )

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    ids = client.query_single("lodash", "4.17.20")
    assert ids == ["GHSA-1111-2222-3333", "CVE-2024-0001"]


def test_query_single_uses_cache(cache: Cache) -> None:
    """Second call with same args returns cached result without HTTP."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"vulns": [{"id": "X"}]})

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    client.query_single("foo", "1.0.0")
    client.query_single("foo", "1.0.0")
    assert call_count == 1


def test_query_single_no_vulns(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    assert client.query_single("clean", "1.0.0") == []


def test_query_single_raises_on_http_error(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    with pytest.raises(OsvError):
        client.query_single("anything", "1.0.0")


def test_fetch_vuln_returns_record(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "GHSA-X", "summary": "fake CVE"})

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    record = client.fetch_vuln("GHSA-X")
    assert record["id"] == "GHSA-X"
    assert record["summary"] == "fake CVE"
```

**Verification:**

```bash
uv run pytest tests/test_osv_client.py -v
# All tests pass with no network calls

# Then a quick smoke test against the live API (one-off, doesn't run in CI)
uv run python -c "
from arguss.core.cache import Cache, get_connection, init_db
from arguss.lenses._osv_client import OsvClient
from arguss.settings import settings, validate_settings
validate_settings()
conn = get_connection(settings.db_path)
init_db(conn)
client = OsvClient(Cache(conn))
ids = client.query_single('lodash', '4.17.20')
print('lodash 4.17.20 vulns:', ids)
"
# Should print a real list of vulnerability IDs from OSV
```

**Commit:**

```bash
git add arguss/lenses/_osv_client.py tests/test_osv_client.py
git commit -m "week3: osv client scaffolding with single-package query and caching"
```

---

## Step 5 — OSV.dev client (batching)

**Goal:** Add `query_batch` for efficiency. OSV's batch endpoint accepts up to ~1000 queries in one HTTP call — way faster than individual queries for a large dep tree.

**Cursor prompt:**

> Add a `query_batch(deps)` method to `OsvClient`. Use OSV's `POST /v1/querybatch` endpoint. The response contains only vulnerability IDs per query — call `fetch_vuln` for each unique ID to get the full records. Return a dict mapping `"name@version"` to a list of full vuln records. Use the existing cache.

**Add to `arguss/lenses/_osv_client.py`:**

```python
def query_batch(
    self,
    deps: list[Dependency],
) -> dict[str, list[dict[str, Any]]]:
    """Query OSV for vulnerabilities affecting many dependencies at once.

    Returns:
        Dict mapping "name@version" → list of full vulnerability records.
    """
    if not deps:
        return {}

    # Dedupe by (ecosystem, name, version) — same package@version appearing
    # multiple times in the tree should only count once for the query.
    seen: dict[tuple[str, str, str], Dependency] = {}
    for d in deps:
        seen[(d.ecosystem, d.name, d.version)] = d
    unique_deps = list(seen.values())

    # Check the batch cache first
    batch_cache_key = f"batch:{_hash_query_set(unique_deps)}"
    cached = self.cache.get_api_response("osv", batch_cache_key)
    if cached is not None:
        vuln_id_map: dict[str, list[str]] = cached
    else:
        # Call the batch API
        queries = [
            {
                "package": {"ecosystem": d.ecosystem, "name": d.name},
                "version": d.version,
            }
            for d in unique_deps
        ]
        try:
            resp = self._http.post(
                f"{self.api_base}/v1/querybatch", json={"queries": queries}
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise OsvError(f"OSV batch query failed: {e}") from e

        results = resp.json().get("results", [])
        vuln_id_map = {
            f"{d.name}@{d.version}": [v["id"] for v in r.get("vulns", [])]
            for d, r in zip(unique_deps, results, strict=False)
        }
        self.cache.set_api_response(
            "osv", batch_cache_key, vuln_id_map, ttl_hours=settings.cache_ttl_hours
        )

    # Resolve each unique vuln ID to a full record (cached individually)
    all_ids: set[str] = {vid for ids in vuln_id_map.values() for vid in ids}
    vuln_records: dict[str, dict[str, Any]] = {}
    for vid in all_ids:
        vuln_records[vid] = self.fetch_vuln(vid)

    # Build the final result: name@version → list of full vuln records
    return {
        pkg_key: [vuln_records[vid] for vid in ids]
        for pkg_key, ids in vuln_id_map.items()
    }
```

**Add tests:**

```python
def test_query_batch_returns_vulns_per_dep(cache: Cache) -> None:
    """A batch query returns vulnerability records keyed by name@version."""
    from arguss.core.models import Dependency

    def handler(request: httpx.Request) -> httpx.Response:
        if "querybatch" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-1"}]},
                        {"vulns": []},
                    ]
                },
            )
        if "vulns/GHSA-1" in str(request.url):
            return httpx.Response(200, json={"id": "GHSA-1", "summary": "test"})
        return httpx.Response(404)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    deps = [
        Dependency(name="vulnerable", version="1.0.0", direct=True),
        Dependency(name="safe", version="2.0.0", direct=True),
    ]
    result = client.query_batch(deps)
    assert result["vulnerable@1.0.0"][0]["id"] == "GHSA-1"
    assert result["safe@2.0.0"] == []


def test_query_batch_empty_input(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("Should not make HTTP calls for empty input")

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    assert client.query_batch([]) == {}


def test_query_batch_dedupes_same_package_version(cache: Cache) -> None:
    """Same package@version appearing multiple times queries once."""
    from arguss.core.models import Dependency

    queries_received = []

    def handler(request: httpx.Request) -> httpx.Response:
        if "querybatch" in str(request.url):
            import json
            body = json.loads(request.content)
            queries_received.append(len(body["queries"]))
            return httpx.Response(
                200, json={"results": [{"vulns": []} for _ in body["queries"]]}
            )
        return httpx.Response(404)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    # Three "deps" but only two unique (name, version)
    deps = [
        Dependency(name="a", version="1.0.0", direct=True),
        Dependency(name="a", version="1.0.0", direct=False, path=["root", "x", "a"]),
        Dependency(name="b", version="2.0.0", direct=True),
    ]
    client.query_batch(deps)
    assert queries_received == [2]  # 2 unique, not 3
```

**Verification:**

```bash
uv run pytest tests/test_osv_client.py -v
```

**Commit:**

```bash
git add arguss/lenses/_osv_client.py tests/test_osv_client.py
git commit -m "week3: osv client batching with dedup and per-vuln caching"
```

---

## Step 6 — Real vulnerability lens

**Goal:** Replace the stub `VulnerabilityLens.scan()` with a real implementation. Takes deps, queries OSV, converts records to Findings, computes the sub-score.

**Cursor prompt:**

> Rewrite `arguss/lenses/vulnerability.py` to do real OSV-backed analysis. Use the contents below. The class signature stays the same — `scan(deps: list[Dependency]) -> LensScore` — so nothing else in the codebase changes.

**File: `arguss/lenses/vulnerability.py`** (replace existing contents)

```python
"""Vulnerability lens — known CVEs from OSV.dev.

Queries OSV for each dependency, converts vulnerability records into Finding
objects, computes a normalized sub-score 0-100.

WEEK 10: Add EPSS exploit-prediction and CISA KEV enrichment.
"""

from __future__ import annotations

import re
from typing import Any

from arguss.core.cache import Cache
from arguss.core.models import Dependency, Finding, LensScore, Severity
from arguss.lenses._osv_client import OsvClient, OsvError


class VulnerabilityLens:
    """Scans dependencies for known vulnerabilities via OSV.dev."""

    def __init__(self, cache: Cache, osv_client: OsvClient | None = None) -> None:
        self.cache = cache
        self.osv = osv_client or OsvClient(cache=cache)

    def scan(self, deps: list[Dependency]) -> LensScore:
        """Return a LensScore for the given dependencies."""
        if not deps:
            return LensScore(lens="cve", score=0.0, findings=[])

        try:
            vuln_map = self.osv.query_batch(deps)
        except OsvError:
            # If OSV is completely unavailable, return an empty score rather
            # than crashing the whole scan. The other lenses still run.
            return LensScore(lens="cve", score=0.0, findings=[])

        findings: list[Finding] = []
        for dep in deps:
            key = f"{dep.name}@{dep.version}"
            for vuln_record in vuln_map.get(key, []):
                findings.append(_vuln_to_finding(vuln_record, dep))

        score = _compute_cve_score(findings)
        return LensScore(lens="cve", score=score, findings=findings)


def _vuln_to_finding(vuln: dict[str, Any], dep: Dependency) -> Finding:
    """Convert an OSV vulnerability record into a Finding."""
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = vuln.get("summary", "").strip() or "No summary provided"
    details = vuln.get("details", "").strip() or summary

    cvss = _extract_cvss(vuln)
    severity = _cvss_to_severity(cvss)
    score = _normalize_cvss_to_100(cvss)

    return Finding(
        dependency=dep,
        lens="cve",
        severity=severity,
        score=score,
        title=f"{vuln_id}: {summary[:120]}",
        description=details[:1000],
        remediation=_extract_fix_advice(vuln, dep),
        source_url=f"https://osv.dev/vulnerability/{vuln_id}",
    )


def _extract_cvss(vuln: dict[str, Any]) -> float | None:
    """Pull a CVSS base score out of an OSV record, if present.

    OSV records have a `severity` array with entries like:
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/.../A:H"}
    The score is a vector; we parse out the base score from it.
    """
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS vectors look like CVSS:3.1/AV:N/AC:L/...
        # We need the "base score" which isn't always in the vector — fall back
        # to the database_specific.cvss_score if present.
        m = re.search(r"CVSS:\d\.\d/", score_str)
        if m:
            # We don't compute CVSS from the vector — that's a whole algorithm.
            # Fall through to database_specific below.
            pass

    db_spec = vuln.get("database_specific", {})
    cvss_score = db_spec.get("cvss_score") or db_spec.get("cvss", {}).get("score")
    if isinstance(cvss_score, int | float):
        return float(cvss_score)

    # GitHub-style severity string fallback
    severity_str = db_spec.get("severity", "").upper()
    if severity_str == "CRITICAL":
        return 9.5
    if severity_str == "HIGH":
        return 7.5
    if severity_str == "MEDIUM" or severity_str == "MODERATE":
        return 5.0
    if severity_str == "LOW":
        return 2.5

    return None


def _cvss_to_severity(cvss: float | None) -> Severity:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _normalize_cvss_to_100(cvss: float | None) -> float:
    """Map CVSS 0-10 to Arguss's 0-100 scale."""
    if cvss is None:
        return 50.0  # unknown severity → assume medium
    return min(100.0, max(0.0, cvss * 10.0))


def _extract_fix_advice(vuln: dict[str, Any], dep: Dependency) -> str:
    """Generate human-readable remediation advice."""
    affected = vuln.get("affected", [])
    for entry in affected:
        if entry.get("package", {}).get("name") != dep.name:
            continue
        for r in entry.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return f"Upgrade {dep.name} from {dep.version} to {event['fixed']} or later"
    return f"Check OSV advisory for upgrade guidance: {vuln.get('id', 'unknown')}"


def _compute_cve_score(findings: list[Finding]) -> float:
    """Lens score = highest normalized CVSS across all findings."""
    if not findings:
        return 0.0
    return max(f.score for f in findings)
```

**Update `arguss/cli.py` to instantiate the lens with a cache:**

```python
# Near the top, add:
from arguss.core.cache import Cache, get_connection, init_db
from arguss.settings import settings, validate_settings

# Inside scan(), replace:
#     cve = VulnerabilityLens().scan(deps)
# with:
    validate_settings()
    conn = get_connection(settings.db_path)
    init_db(conn)
    cache = Cache(conn)

    cve = VulnerabilityLens(cache=cache).scan(deps)
```

The trust and pipeline lenses don't need the cache yet — they're still fake.

**Add tests:**

**File: `tests/test_vulnerability_lens.py`**

```python
"""Tests for the vulnerability lens."""

from pathlib import Path
from unittest.mock import MagicMock

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import Dependency
from arguss.lenses.vulnerability import VulnerabilityLens


def _make_cache(tmp_path: Path) -> Cache:
    conn = get_connection(tmp_path / "test.db")
    init_db(conn)
    return Cache(conn)


def test_empty_deps_returns_zero_score(tmp_path: Path) -> None:
    cache = _make_cache(tmp_path)
    mock_osv = MagicMock()
    lens = VulnerabilityLens(cache=cache, osv_client=mock_osv)
    score = lens.scan([])
    assert score.score == 0.0
    assert score.findings == []
    mock_osv.query_batch.assert_not_called()


def test_no_vulns_returns_zero_score(tmp_path: Path) -> None:
    cache = _make_cache(tmp_path)
    mock_osv = MagicMock()
    mock_osv.query_batch.return_value = {"clean@1.0.0": []}
    lens = VulnerabilityLens(cache=cache, osv_client=mock_osv)

    deps = [Dependency(name="clean", version="1.0.0", direct=True)]
    score = lens.scan(deps)
    assert score.score == 0.0
    assert score.findings == []


def test_critical_vuln_produces_critical_finding(tmp_path: Path) -> None:
    cache = _make_cache(tmp_path)
    mock_osv = MagicMock()
    mock_osv.query_batch.return_value = {
        "bad@1.0.0": [
            {
                "id": "GHSA-XXXX",
                "summary": "Critical RCE",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [
                    {
                        "package": {"name": "bad"},
                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
                    }
                ],
            }
        ]
    }
    lens = VulnerabilityLens(cache=cache, osv_client=mock_osv)

    deps = [Dependency(name="bad", version="1.0.0", direct=True)]
    score = lens.scan(deps)
    assert score.score >= 95.0
    assert len(score.findings) == 1
    assert score.findings[0].severity == "critical"
    assert "1.0.1" in (score.findings[0].remediation or "")


def test_osv_error_returns_empty_score(tmp_path: Path) -> None:
    """If OSV is unreachable, the lens degrades gracefully."""
    from arguss.lenses._osv_client import OsvError

    cache = _make_cache(tmp_path)
    mock_osv = MagicMock()
    mock_osv.query_batch.side_effect = OsvError("network down")
    lens = VulnerabilityLens(cache=cache, osv_client=mock_osv)

    deps = [Dependency(name="x", version="1.0.0", direct=True)]
    score = lens.scan(deps)
    assert score.score == 0.0
    assert score.findings == []
```

**Verification:**

```bash
# Unit tests pass
uv run pytest tests/test_vulnerability_lens.py -v

# Full suite still green
uv run pytest

# Real scan with real CVE data
uv run arguss scan tests/fixtures/lockfiles/real-world.json --format pretty
# Should now show real CVE findings against the express@4.17.0 tree
```

The first time you run against `real-world.json`, it'll take 5-15 seconds (cache cold, hitting the OSV API). Subsequent runs against the same file should be sub-second (cache warm).

**Commit:**

```bash
git add arguss/lenses/vulnerability.py arguss/cli.py tests/test_vulnerability_lens.py
git commit -m "week3: real vulnerability lens with OSV.dev integration"
```

---

## Step 7 — Integration test marker

**Goal:** A separate "integration" test class that hits the real OSV API. Skipped by default in local dev; runs in CI.

**Cursor prompt:**

> Add an integration marker to `pyproject.toml` and one integration test that hits the real OSV API. The local default should skip integration tests; CI runs them explicitly.

**Update `pyproject.toml`:**

In the `[tool.pytest.ini_options]` block:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
addopts = "-v --tb=short -m 'not integration'"
markers = [
    "integration: tests that hit live external APIs (run separately in CI)",
]
```

**File: `tests/test_integration_osv.py`**

```python
"""Integration tests that hit the real OSV.dev API.

Skipped by default. Run with:
    uv run pytest -m integration
"""

from pathlib import Path

import pytest

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import Dependency
from arguss.lenses._osv_client import OsvClient
from arguss.lenses.vulnerability import VulnerabilityLens


@pytest.mark.integration
def test_lodash_old_version_has_known_vulns(tmp_path: Path) -> None:
    """lodash 4.17.20 has known CVEs — verify we find them against the real API."""
    conn = get_connection(tmp_path / "test.db")
    init_db(conn)
    cache = Cache(conn)
    osv = OsvClient(cache=cache)
    lens = VulnerabilityLens(cache=cache, osv_client=osv)

    deps = [Dependency(name="lodash", version="4.17.20", direct=True)]
    score = lens.scan(deps)

    assert score.score > 0, "Expected real CVEs for old lodash version"
    assert len(score.findings) >= 1
    assert any("CVE" in f.title or "GHSA" in f.title for f in score.findings)
```

**Update `.github/workflows/ci.yml`** to run integration tests in CI:

In the `test` job, after the regular test step, add:

```yaml
      - name: Test (integration)
        run: uv run pytest -m integration
        continue-on-error: true  # network flakes shouldn't fail the build
```

The `continue-on-error: true` is important — OSV could be temporarily down, and your build failing because of someone else's infrastructure would be annoying. The build still publishes the test results so you can see if they pass.

**Verification:**

```bash
# Local default — integration tests skip
uv run pytest

# Explicit integration run — hits OSV
uv run pytest -m integration -v
```

**Commit:**

```bash
git add pyproject.toml tests/test_integration_osv.py .github/workflows/ci.yml
git commit -m "week3: integration test marker, lodash CVE integration test"
```

---

## Step 8 — CycloneDX SBOM generator

**Goal:** Generate a CycloneDX SBOM from the parsed dependency graph. Reuses the parser output, no new external data needed. Provides a CLI subcommand `arguss sbom <path>` and an API endpoint later.

**Cursor prompt:**

> Create `arguss/core/sbom.py` with a function `generate_sbom(deps: list[Dependency], project_name: str = "unknown") -> dict` that produces a CycloneDX 1.5 JSON document. Don't pull in any new dependencies — CycloneDX is just structured JSON, build it by hand. Then add an `arguss sbom <path>` CLI subcommand that runs the parser and writes the SBOM to stdout or a file.

**File: `arguss/core/sbom.py`**

```python
"""CycloneDX SBOM generation.

Produces CycloneDX 1.5 JSON documents from the parsed dependency graph.
Spec: https://cyclonedx.org/docs/1.5/json/

No external library dependency — CycloneDX is just structured JSON, and
hand-rolling the document keeps our deps minimal and the output auditable.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from arguss.core.models import Dependency

CYCLONEDX_SPEC_VERSION = "1.5"
ARGUSS_TOOL = {
    "vendor": "Arguss",
    "name": "arguss",
    "version": "0.1.0",
}


def generate_sbom(
    deps: list[Dependency],
    project_name: str = "unknown",
    project_version: str = "0.0.0",
) -> dict[str, Any]:
    """Generate a CycloneDX 1.5 SBOM from parsed dependencies.

    Returns a JSON-serializable dict ready to write to disk or send as an
    HTTP response.
    """
    serial = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(UTC).isoformat()
    root_bom_ref = f"pkg:project/{project_name}@{project_version}"

    components: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    for d in deps:
        ref = _purl(d)
        if ref in seen_refs:
            continue  # dedupe — same package@version may appear in multiple paths
        seen_refs.add(ref)
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": d.name,
                "version": d.version,
                "purl": ref,
                "scope": "required",
            }
        )

    dependency_graph = _build_dependency_graph(deps, root_bom_ref)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", **ARGUSS_TOOL}]},
            "component": {
                "type": "application",
                "bom-ref": root_bom_ref,
                "name": project_name,
                "version": project_version,
            },
        },
        "components": components,
        "dependencies": dependency_graph,
    }


def _purl(dep: Dependency) -> str:
    """Construct a Package URL (purl) for the dependency.

    See: https://github.com/package-url/purl-spec
    """
    if dep.name.startswith("@"):
        # Scoped npm packages: @scope/name → pkg:npm/%40scope/name@version
        namespace, _, name = dep.name.partition("/")
        return f"pkg:npm/{namespace.replace('@', '%40')}/{name}@{dep.version}"
    return f"pkg:npm/{dep.name}@{dep.version}"


def _build_dependency_graph(
    deps: list[Dependency], root_ref: str
) -> list[dict[str, Any]]:
    """Build the CycloneDX `dependencies` array.

    Each entry is {ref: <bom-ref>, dependsOn: [<bom-ref>, ...]}.
    We model the project root as depending on direct deps; each transitive
    relationship is inferred from each dep's `parents` field.
    """
    # Group children by parent name. Parents are package names (from chain),
    # not bom-refs, so we have to resolve names → refs.
    name_to_ref: dict[str, str] = {}
    for d in deps:
        name_to_ref[d.name] = _purl(d)

    children_of: dict[str, set[str]] = {}
    for d in deps:
        ref = _purl(d)
        for parent_name in d.parents:
            if parent_name == "root":
                parent_ref = root_ref
            else:
                parent_ref = name_to_ref.get(parent_name, root_ref)
            children_of.setdefault(parent_ref, set()).add(ref)

    return [
        {"ref": parent, "dependsOn": sorted(children)}
        for parent, children in sorted(children_of.items())
    ]
```

**Add CLI subcommand in `arguss/cli.py`:**

```python
@app.command()
def sbom(
    path: str = typer.Argument(..., help="Path to project root or package-lock.json"),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write SBOM to this file. Default: stdout.",
    ),
) -> None:
    """Generate a CycloneDX SBOM for the given project."""
    from pathlib import Path as _Path

    from arguss.core.parser import ParserError, parse_lockfile
    from arguss.core.sbom import generate_sbom

    project_path = _Path(path).resolve()
    if not project_path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {project_path}")
        sys.exit(1)

    try:
        deps = parse_lockfile(project_path)
    except ParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    project_name = project_path.name if project_path.is_dir() else project_path.parent.name
    doc = generate_sbom(deps, project_name=project_name)

    import json as _json

    if output:
        _Path(output).write_text(_json.dumps(doc, indent=2))
        console.print(f"[green]SBOM written to[/green] {output}")
    else:
        print(_json.dumps(doc, indent=2))
```

**Tests: `tests/test_sbom.py`**

```python
"""Tests for the CycloneDX SBOM generator."""

from pathlib import Path

from arguss.core.models import Dependency
from arguss.core.parser import parse_lockfile
from arguss.core.sbom import generate_sbom

FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"


def test_sbom_basic_shape() -> None:
    deps = [Dependency(name="left-pad", version="1.3.0", direct=True)]
    doc = generate_sbom(deps, project_name="test")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["component"]["name"] == "test"
    assert len(doc["components"]) == 1
    assert doc["components"][0]["purl"] == "pkg:npm/left-pad@1.3.0"


def test_sbom_dedupes_components() -> None:
    """Same package@version at different paths produces one component."""
    deps = [
        Dependency(name="foo", version="1.0.0", direct=True, path=["root", "foo"]),
        Dependency(
            name="foo",
            version="1.0.0",
            direct=False,
            path=["root", "bar", "foo"],
            parents=["bar"],
        ),
    ]
    doc = generate_sbom(deps, project_name="test")
    refs = [c["bom-ref"] for c in doc["components"]]
    assert refs.count("pkg:npm/foo@1.0.0") == 1


def test_sbom_scoped_packages_purl() -> None:
    deps = [Dependency(name="@types/node", version="20.0.0", direct=True)]
    doc = generate_sbom(deps)
    assert doc["components"][0]["purl"] == "pkg:npm/%40types/node@20.0.0"


def test_sbom_from_real_fixture() -> None:
    """End-to-end: parse a real lockfile, generate an SBOM, sanity-check."""
    deps = parse_lockfile(FIXTURES / "with-transitive.json")
    doc = generate_sbom(deps, project_name="test-project")
    assert len(doc["components"]) == len(deps)
    assert len(doc["dependencies"]) > 0
    # Every component has a purl
    assert all(c["purl"].startswith("pkg:npm/") for c in doc["components"])
```

**Verification:**

```bash
# Tests pass
uv run pytest tests/test_sbom.py -v

# Generate an SBOM from the CLI
uv run arguss sbom tests/fixtures/lockfiles/with-transitive.json -o /tmp/test-sbom.json

# Validate against CycloneDX spec (optional — uses the upstream validator)
python -m json.tool /tmp/test-sbom.json | head -50
```

If you want to be thorough, validate against the official CycloneDX schema:

```bash
pip install cyclonedx-bom  # one-off, just for validation
cyclonedx validate --input-file /tmp/test-sbom.json
```

**Commit:**

```bash
git add arguss/core/sbom.py arguss/cli.py tests/test_sbom.py
git commit -m "week3: cyclonedx 1.5 sbom generator + arguss sbom subcommand"
```

---

## Step 9 — Final integration: full scan with real data

**Goal:** End-to-end verification that everything works together against a real npm project.

**Commands to run:**

```bash
# Real scan, real OSV data, real CVE findings
uv run arguss scan tests/fixtures/lockfiles/real-world.json --format pretty

# Same project, SBOM generation
uv run arguss sbom tests/fixtures/lockfiles/real-world.json -o /tmp/express.sbom.json
wc -l /tmp/express.sbom.json  # Should be a substantial document, hundreds of lines

# Full test suite green
uv run pytest

# Lint and types
uv run ruff check .
uv run mypy arguss

# Cached re-scan is fast
time uv run arguss scan tests/fixtures/lockfiles/real-world.json > /dev/null
# First run: 5-15s. Second run: <1s.
```

**Expected output on the pretty scan:**

You should see:
- A non-zero overall score
- The `cve` panel showing real findings (probably several from express@4.17.0's old dependency tree)
- The `trust` and `pipeline` panels still showing fake data (replaced in Weeks 4-5)
- The unified score reflects the new real CVE scores

This is your first "real" output. Screenshot it — it'll be useful in the Week 4 Milestone Report and the Week 12 webpage.

---

## Step 10 — Deploy and verify in production

**Goal:** Push to main, watch the auto-deploy, confirm the live URL still works.

```bash
git push
# Watch GitHub Actions: ci.yml, secret-scan.yml, deploy.yml all run
```

After deploy completes:

```bash
curl https://<your-app>.fly.dev/health
# Still healthy

# (Week 7 will add a real scan endpoint to the web UI;
#  for now, just confirm the app still serves)
curl -s https://<your-app>.fly.dev/ | grep -i arguss
```

If the deploy fails, check `flyctl logs` for the cause. Most likely cause this week: the OSV client tries to write to a cache file that doesn't exist on the volume yet. The cache module auto-creates the file, so this should "just work," but verify.

**Commit a marker for end-of-week:**

```bash
git tag week3-done
git push --tags
```

Tagging gives you a labeled commit to roll back to if Week 4 work breaks something.

---

## What you should have at the end of Week 3

1. **Three lockfile fixtures** in `tests/fixtures/lockfiles/` covering minimal, transitive, and real-world scenarios
2. **A working parser** that produces `Dependency` objects from `package-lock.json` v3 with full transitive paths
3. **An OSV client** with single and batch query methods, fully cached, fully unit-tested
4. **A real vulnerability lens** producing real CVE findings against real packages
5. **A CycloneDX SBOM generator** producing valid CycloneDX 1.5 JSON
6. **A new `arguss sbom` subcommand** that writes SBOMs to stdout or a file
7. **Integration test infrastructure** that hits the real OSV API but is skipped by default
8. **All Day 1 work still green** — every test from the skeleton phase still passes
9. **The live URL still serves** the hello-world page (real dashboard lands in Week 7)
10. **A `week3-done` git tag** marking this milestone

---

## What's deliberately out of scope this week

These show up in later weeks; don't let Cursor sneak them in early:

- **EPSS exploit-prediction scores** — Week 10
- **CISA KEV catalog enrichment** — Week 10
- **Trust signals** (maintainer data, typosquatting) — Week 4
- **Pipeline analysis** (zizmor) — Week 5
- **The remediation ranker's "which upgrade helps most" logic** — Week 6
- **AI-generated remediation explanations** — Week 10
- **Web dashboard UI** — Week 7
- **GitHub Action wrapper** — Week 9
- **Cytoscape.js blast radius graph** — Week 9
- **Lockfile v1/v2 support** — future work
- **npm workspaces support** — future work
- **pip, Maven, or other ecosystems** — future work

If something in this list comes up, write it as an issue on the project board with the right week label and move on.

---

## Troubleshooting

**OSV returns 429 (rate limited):** OSV's free tier is generous but not infinite. The batch endpoint significantly reduces calls. Cache is the second line of defense. If you hit this repeatedly during development, add `time.sleep(0.5)` between queries or wait an hour.

**Mypy complains about httpx types:** Add to `pyproject.toml`:

```toml
[[tool.mypy.overrides]]
module = ["httpx.*"]
ignore_missing_imports = true
```

**Real-world fixture has fewer CVEs than expected:** `express@4.17.0` has had most of its known CVEs patched in newer transitive deps. If you want a denser CVE example, try `npm install lodash@4.17.20 marked@0.3.6` — both versions have known vulnerabilities.

**Tests pass locally but fail in CI:** Most often a hardcoded path or environment difference. Check that fixture paths use `Path(__file__).parent` (relative to the test file), not absolute paths.

**The CLI hangs:** OSV timeout. The httpx client has a 10-second timeout per request; a hang means something deeper. Check `flyctl logs` (in production) or add `httpx.LogConfig` for verbose output.

---

## Pacing guidance

If you split Steps 1-10 across the week:

- **Day 1 (Tue):** Steps 1-3 (fixtures + parser + CLI wiring). The parser is the bulk of the work.
- **Day 2 (Wed):** Steps 4-5 (OSV client scaffolding + batching)
- **Day 3 (Thu):** Step 6 (real vulnerability lens). This is where it gets satisfying — real CVEs in your output.
- **Day 4 (Fri):** Steps 7-8 (integration tests + SBOM generator)
- **Day 5 (Sat/Sun):** Steps 9-10 (end-to-end verification + deploy + Project Overview writeup)

If you're going faster, great — bank the time for Week 4 (trust signals are harder than they look). If slower, the SBOM generator (Step 8) is the most droppable item. The vulnerability lens is the must-have; SBOM can slide a week if needed.
