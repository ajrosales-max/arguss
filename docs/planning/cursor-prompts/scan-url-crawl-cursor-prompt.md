# Cursor prompt — `feature/scan-url-crawl`

This PR replaces the git clone in Mode A (`/scan/url`) with a targeted GitHub Contents API fetcher. The result: faster scans, no clone bottleneck, and a new `ref` parameter that lets users scan any tag, branch, or commit of any public GitHub repo. Mode C (which needs a writable working tree to commit changes) keeps its existing clone path. Mode B (upload) is unchanged.

**Branch name:** `feature/scan-url-crawl`

**Estimated time:** 1–1.5 days.

**Scope discipline:** Mode A only. Do NOT touch `/scan/with-action`, `/scan/upload`, the engine, the lenses, or the CLI. The `shallow_clone` function in `arguss/web/git_clone.py` stays — it's still used by Mode C.

---

## Before pasting into Cursor

```bash
git checkout main
git pull
git log --oneline -3                       # confirm the Claude explanation work is at top

uv run pytest                              # baseline: should be 290 passed
```

No new dependencies needed — `httpx` is already in the project.

```bash
git checkout -b feature/scan-url-crawl
```

---

## The prompt to paste into Cursor

I'm replacing the git clone in Arguss Mode A with a targeted GitHub Contents API fetcher. Goal: faster scans, no clone bottleneck, ability to scan any tag/branch/commit of any public repo without forking. The ground rules below are critical — the architecture hinges on them.

### Ground rules (non-negotiable)

1. **The engine doesn't change.** `propose_fixes(lockfile_path, work_tree)` continues to take a filesystem path. The new fetcher builds a work_tree containing the same files Mode B already assembles (lockfile + workflows + package.json + stub test files for counting), but the engine surface stays identical.

2. **Mode C still uses `shallow_clone`.** Do NOT touch `scan_with_action` or `arguss/web/git_clone.py`. Mode C needs a writable tree to commit changes; the clone is correct there.

3. **Mode B (`scan_upload`) is unchanged.** Don't touch it.

4. **Test files: existence, not contents.** The pipeline lens's `test_reality.has_test_files` checks "at least one `*.test.*` or `*.spec.*` exists." The fetcher creates zero-byte stub files at the discovered test paths so the existence check works. Do NOT fetch test file contents — that would balloon network usage to no benefit.

5. **Optional GitHub token.** Read `ARGUSS_GITHUB_TOKEN` from env. If set, use Bearer auth (5000 req/hr). If not, work unauthenticated at 60 req/hr per IP. Never accept a token via HTTP request body or query — it's service-level config only.

6. **Failure modes have clean HTTP codes:**
   - Repo or ref not found → 404
   - Rate limit hit (403 + `X-RateLimit-Remaining: 0`) → 429
   - No `package-lock.json` in repo → 422
   - GitHub API timeout or network error → 504
   - Any unexpected error → 500 with the existing `_INTERNAL_DETAIL` message

### What to build

#### 1. `arguss/web/github_fetch.py` (new file)

A module providing GitHub Contents API access:

```python
"""GitHub Contents API client for fetching repo inputs without cloning."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import httpx


class GitHubFetchError(Exception):
    """Base for fetch errors. Carries a status_code for HTTP translation."""

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class RepoInputs:
    """Files assembled into a temp working tree, ready for propose_fixes."""

    work_tree: Path
    lockfile_path: Path


async def fetch_repo_inputs(
    owner: str,
    repo: str,
    ref: str,
    dest: Path,
    timeout: float = 30.0,
) -> RepoInputs:
    """Fetch the files propose_fixes needs into `dest`.

    Steps:
    - GET /repos/{owner}/{repo}/git/trees/{ref}?recursive=1 to list paths
    - For each needed file, GET /repos/{owner}/{repo}/contents/{path}?ref={ref}
      and decode the base64 `content` field
    - Required: package-lock.json (else raise GitHubFetchError(422))
    - Optional: package.json, .github/workflows/*.yml, .github/workflows/*.yaml
    - Test files: create zero-byte stubs at discovered *.test.* / *.spec.* paths

    Raises GitHubFetchError on any non-success outcome.
    """
    ...
```

Implementation notes:

- Use `httpx.AsyncClient` with the passed `timeout`.
- Base URL: `https://api.github.com`
- Auth: read `os.environ.get("ARGUSS_GITHUB_TOKEN")`. If present, set `Authorization: Bearer {token}` on every request.
- Use the Git Trees API for the tree listing (`GET /repos/{owner}/{repo}/git/trees/{ref}?recursive=1`) — single call, returns all paths in the repo.
- Use the Contents API for individual files (`GET /repos/{owner}/{repo}/contents/{path}?ref={ref}`). The response has a base64-encoded `content` field; decode it to bytes.
- Status code mapping (GitHub → GitHubFetchError):
  - 404 → status_code=404
  - 403 with header `X-RateLimit-Remaining: 0` → status_code=429
  - 401 → status_code=401 (only happens with a bad token)
  - other 4xx/5xx → status_code=500
  - `httpx.TimeoutException` → status_code=504
- Tree listing is fetched first. If `package-lock.json` is not in the tree → raise `GitHubFetchError("Repository does not contain a package-lock.json", 422)`.
- Test file detection: from the tree, find paths whose basename matches the glob `*.test.*` or `*.spec.*`. Create the parent directories under `dest` and write empty bytes to each path. Do NOT fetch their contents.
- Assemble files into `dest`:
  - Write lockfile bytes to `dest / "package-lock.json"`
  - Write `package.json` (if present) to `dest / "package.json"`
  - Create `dest / ".github" / "workflows"` and write each workflow file
  - Create empty stubs at discovered test paths
- Return `RepoInputs(work_tree=dest, lockfile_path=dest / "package-lock.json")`

Path-safety reminder: every path written under `dest` must stay under `dest`. Reject any tree entry whose path contains `..` or starts with `/`. (Defense in depth — GitHub shouldn't return such paths, but trust nothing.)

#### 2. Update `arguss/web/routes.py`

**Add `ref` to `ScanUrlRequest`:**

```python
class ScanUrlRequest(BaseModel):
    """Request body for /scan/url."""

    url: str = Field(
        ...,
        description="A public GitHub repository URL",
        examples=["https://github.com/expressjs/express"],
    )
    ref: str = Field(
        default="HEAD",
        description=(
            "Branch, tag, or commit SHA to scan. Defaults to the repo's "
            "default branch."
        ),
        examples=["main", "4.17.0", "a3b1c0..."],
    )
```

**Replace the `shallow_clone` block in `scan_url`:**

The current block:

```python
try:
    work_tree = shallow_clone(parsed.clone_url, clone_target)
except GitCloneError as exc:
    code = _clone_error_status(exc)
    detail = (
        "Clone took too long; repository may be too large"
        if code == status.HTTP_504_GATEWAY_TIMEOUT
        else "Repository not found or not accessible"
    )
    raise HTTPException(status_code=code, detail=detail) from exc

lockfile_path = work_tree / "package-lock.json"
if not lockfile_path.is_file():
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail="Repository does not contain a package-lock.json",
    )
```

Becomes:

```python
try:
    inputs = await fetch_repo_inputs(
        owner=parsed.owner,
        repo=parsed.name,
        ref=request.ref,
        dest=clone_target,
    )
except GitHubFetchError as exc:
    raise HTTPException(
        status_code=exc.status_code,
        detail=str(exc),
    ) from exc

work_tree = inputs.work_tree
lockfile_path = inputs.lockfile_path
```

The `if not lockfile_path.is_file():` block is now redundant — `fetch_repo_inputs` raises `GitHubFetchError(422)` if the lockfile isn't in the tree. Remove it.

Don't touch `scan_with_action` or `scan_upload`.

#### 3. Tests

**Unit tests** — `tests/test_github_fetch.py`:

Use `respx` or `pytest-httpx` (add as a dev dep if not already present) to mock httpx responses. Test:
- Successful fetch: lockfile + workflows + package.json + test stubs all assembled
- Successful fetch: only lockfile (no workflows, no package.json)
- 404 from tree listing → `GitHubFetchError` with status_code 404
- Tree present but no `package-lock.json` → `GitHubFetchError(422)`
- 403 with `X-RateLimit-Remaining: 0` → `GitHubFetchError(429)`
- `httpx.TimeoutException` → `GitHubFetchError(504)`
- Token included in headers when `ARGUSS_GITHUB_TOKEN` is set (use `monkeypatch.setenv`)
- No Authorization header when env var unset (use `monkeypatch.delenv`)
- Test file stubs created at discovered `*.test.*` / `*.spec.*` paths
- Test file *contents* NOT fetched (verify only listing + needed files appear in mock call log)
- Path traversal in a tree entry (e.g. `../etc/passwd`) is rejected

**Integration test** — `tests/test_github_fetch_integration.py` (mark `@pytest.mark.integration`):
- Real call against a small known-good public repo (suggest `sindresorhus/is`)
- Verify the assembled work_tree contains the expected files
- Not run in default CI; runs in the integration job

**Endpoint tests** — extend `tests/test_scan_url_endpoint.py`:
- `ref` parameter accepted in request body
- Default `HEAD` works (no ref provided)
- Explicit tag ref works (mocked)
- 404 propagates from fetcher
- 422 (missing lockfile) propagates from fetcher
- 429 (rate limit) propagates from fetcher
- 504 (timeout) propagates from fetcher

Any existing scan_url tests that mocked `shallow_clone` need to mock `fetch_repo_inputs` instead. Update them.

### Acceptance criteria

1. `uv run pytest` passes. The previous baseline was 290 tests; this PR adds tests, so the count goes up.
2. A live `curl` against `localhost:8000/scan/url` with body `{"url": "https://github.com/expressjs/express", "ref": "4.17.0"}` returns the same number of findings the CLI `propose-fixes` produces against `tests/fixtures/lockfiles/real-world.json` (12 findings, per Week 5 verification).
3. Cold-cache wall time on the above curl is under 4 seconds (down from 8.6s on the clone path).
4. Error paths return clean HTTP codes — verify with curl against: a nonexistent repo (404), a bad ref (404), a repo with no lockfile (422).
5. With `ARGUSS_GITHUB_TOKEN` set, the request includes the Authorization header (covered by unit test).
6. `shallow_clone` is still used by `scan_with_action`. Verify: `grep shallow_clone arguss/web/routes.py` shows exactly one match, inside `scan_with_action`.

### What NOT to do

- Don't make the GitHub API client an app-level singleton. Instantiate per request — it's a few hundred bytes.
- Don't add caching for tree listings or file contents. The existing SQLite cache is for OSV/npm/deps.dev; GitHub API caching is a separate decision and out of scope.
- Don't touch the CLI, the engine, the lenses, or `arguss/api.py`.
- Don't add a webhook, polling, or job queue. The fetcher is awaited in the async handler; no background work.
- Don't fetch test file contents — only existence matters for the lens.
- Don't change the response shape — `proposal_report_payload(report)` continues to be the response body for Mode A. Any UI work that depends on the response shape is unaffected.

---

## After Cursor finishes

1. **Run the full test suite:** `uv run pytest`. All previous tests pass, new tests pass.
2. **Run the live verification:**
   ```bash
   uvicorn arguss.api:app --reload
   # in another terminal:
   time curl -s -X POST http://localhost:8000/scan/url \
     -H 'Content-Type: application/json' \
     -d '{"url":"https://github.com/expressjs/express","ref":"4.17.0"}' \
     -o /tmp/arguss-crawl.json
   jq '.summary' /tmp/arguss-crawl.json
   ```
   Expect `total_findings: 12`, cold-cache wall time under 4s.
3. **Optionally run with token:** `export ARGUSS_GITHUB_TOKEN=ghp_...` and re-run; should be the same result, just doesn't count against the 60/hr limit.
4. **Tag the milestone** when merged: `git tag milestone/scan-url-crawl`.

If the live verification produces fewer than 12 findings, something has diverged between the crawl path and the lockfile fixture — investigate before merging.
