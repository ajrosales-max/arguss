# Web service architecture — scan modes and HTTP layer (Week 7)

This document describes how the Arguss **hosted web service** exposes the same remediation engine as the CLI (`arguss propose-fixes`). **Mode A** (`POST /scan/url`) and **Mode B** (`POST /scan/upload`) are shipped; **Mode C** remains deferred.

**Related docs:** `project-overview-v2.md` (product framing), `fix-confidence-engine.md` (engine and `ProposalReport` shape).

**Code map:**

| Concern | Module |
|---------|--------|
| FastAPI app | `arguss/api.py` |
| Scan routes | `arguss/web/routes.py` |
| GitHub URL parsing | `arguss/web/github_url.py` |
| Shallow clone | `arguss/web/git_clone.py` |
| Safe workflow zip extraction | `arguss/web/zip_safe.py` |
| JSON payloads | `arguss/core/serialization.py` |
| Orchestration (unchanged) | `arguss/engine/propose.py` |

**Runtime dependency:** `python-multipart` (required by FastAPI for `UploadFile` / multipart forms).

---

## Three input modes (shared engine)

All modes run the same pipeline: parse lockfile → vulnerability lens → fix discovery → trust delta per candidate → pipeline snapshot → fix-confidence engine → `ProposalReport`.

| Mode | Input | Credentials | Mutates repo? | Status |
|------|--------|-------------|---------------|--------|
| **A — Repo URL** | Public `https://github.com/{owner}/{repo}` | None | No (read-only shallow clone) | **Shipped** — `POST /scan/url` |
| **B — File upload** | `package-lock.json` (+ optional workflows zip / `package.json`) | None | No | **Shipped** — `POST /scan/upload` |
| **C — URL + PAT** | Repo URL + GitHub token | User PAT (session-scoped) | Yes (open PRs, merge in-envelope) | Deferred |

Modes A and B differ only in how inputs are assembled; they must not fork the engine. Mode C adds credentialed GitHub write APIs.

---

## Mode A endpoint — `POST /scan/url`

**Request:** `{ "url": "https://github.com/owner/repo" }`
**Response:** `200` with a `ProposalReport`-shaped JSON object (same keys as `arguss propose-fixes` on stdout).

**Workflow:**

1. Validate and parse the URL (`parse_github_url`).
2. Create a per-request `tempfile.TemporaryDirectory(prefix="arguss-scan-")`.
3. Shallow-clone into `{tmpdir}/{repo_name}` (`shallow_clone`).
4. Require `package-lock.json` at the **repository root**.
5. Run `propose_fixes(lockfile_path, repo_root)` off the event loop.
6. Return `JSONResponse(content=proposal_report_payload(report))`.
7. Temp directory is removed when the `with` block exits.

Read-only: no branches, commits, or PRs.

---

## Mode B endpoint — `POST /scan/upload`

**Request:** `multipart/form-data` with three fields:

| Field | Required | Max size | Purpose |
|-------|----------|----------|---------|
| `lockfile` | Yes | **10 MiB** | `package-lock.json` at repo root |
| `workflows_zip` | No | **1 MiB** | `.github/workflows/` contents as a zip |
| `package_json` | No | **1 MiB** | Root `package.json` |

Limits are enforced during **chunked reads** (64 KiB chunks); the handler raises **413** as soon as a field would exceed its cap. OpenAPI route description documents these limits.

Optional file fields use `if upload is not None and upload.filename` so an unselected optional part (FastAPI may send an empty `UploadFile` rather than `None`) is ignored.

**Response:** `200` with the same `ProposalReport` JSON shape as Mode A.

**Workflow:**

1. Read `lockfile` with size limit → validate JSON (`json.loads`) → **422** if malformed (before any disk write).
2. If `workflows_zip` present: read with 1 MiB limit (bytes held in memory until step 4).
3. If `package_json` present: read with 1 MiB limit → validate JSON → **422** if malformed.
4. `tempfile.TemporaryDirectory(prefix="arguss-upload-")`.
5. Write `{tmpdir}/package-lock.json`.
6. If `package_json` bytes present: write `{tmpdir}/package.json`.
7. If `workflows_zip` bytes present: `extract_workflows_zip(bytes, {tmpdir}/.github/workflows/)` — **422** with `str(ZipExtractionError)` on safety failure.
8. `await run_in_threadpool(propose_fixes, lockfile_path, tmp_path)` — **`tmp_path` is the repo root**.
9. Return `JSONResponse(content=proposal_report_payload(report))`.
10. Temp directory removed on `with` exit.

**Tempdir layout (what `propose_fixes` sees):**

```text
{tmpdir}/
  package-lock.json          # required
  package.json               # optional
  .github/workflows/
    ci.yml                   # flat inside workflows/ (zip prefixes stripped)
    deploy.yaml
```

The pipeline lens expects workflows under `.github/workflows/`; lockfile and `package.json` must sit at the **root** of the upload (no monorepo subpath handling in v1).

**Why these size limits:** 10 MiB covers large but realistic lockfiles; 1 MiB for workflows zip and `package.json` bounds memory and zip-bomb surface while fitting typical CI YAML trees.

---

## Zip safety (`arguss/web/zip_safe.py`)

Mode B is the first surface where the server **extracts user-supplied archives**. Extraction is isolated in `extract_workflows_zip()`; routes never import `zipfile` directly.

### Design: validate before extract

1. **Pass 1 — validation:** Walk `ZipFile.infolist()`. Every rule must pass for every file entry before any byte is written. One bad entry rejects the whole archive (no partial extraction).
2. **Pass 2 — extraction:** `zf.read()` each approved entry, optional post-read size check, `write_bytes` to `dest_dir/{basename}` only.

### Rules (summary)

| Check | Behavior |
|-------|----------|
| Valid zip | Reject non-zip bytes / `BadZipFile` |
| Entry count | ≤ 200 entries in `infolist()` (includes directory entries) |
| Per-file size | `ZipInfo.file_size` (uncompressed) ≤ 2 MiB — **not** `compress_size` (zip-bomb defense) |
| Total uncompressed | Sum of `file_size` for file entries ≤ 10 MiB |
| Path traversal | Reject `..`, leading `/`, `\` in entry names; `resolve()` + `is_relative_to(dest_dir)` on target |
| Symlinks / non-regular | Reject `S_IFLNK`; reject non-regular Unix types (allow `S_IFREG` or `0`) |
| File type | Basename must end with `.yml` or `.yaml` (case-insensitive suffix) |
| Duplicate basenames | Reject two entries that flatten to the same basename |
| Directory entries | Names ending in `/` are skipped (not counted as workflow files) |
| Empty archive | Reject if no extractable workflow files remain |
| Post-read cross-check | After `zf.read()`, compare `len(data)` to `info.file_size` (lying central directory) |

Files are written **flat** under `dest_dir`: `workflows/ci.yml` in the zip becomes `dest_dir/ci.yml`, not `dest_dir/workflows/ci.yml`.

### v1 limitations (documented behavior)

- **Duplicate basename check is case-sensitive.** A zip containing both `ci.yml` and `CI.YML` passes validation but yields filesystem-dependent overwrite behavior. Acceptable for v1.
- **`dest_dir` is created before validation** (`mkdir(parents=True)` at the start of `extract_workflows_zip`). A failed validation still leaves an empty (or partially populated, if that were possible — it is not, given validate-before-extract) directory. Fine for Mode B because each request uses a fresh `TemporaryDirectory`; worth knowing for any future reuse of the extractor outside that pattern.

---

## Sync/async pattern

`propose_fixes` is **synchronous** and performs blocking I/O (SQLite cache, HTTP to OSV/npm, subprocess for zizmor). The HTTP handler is `async def` but **must not** call `propose_fixes` directly on the event loop.

```python
report = await run_in_threadpool(propose_fixes, lockfile_path, repo_root)
```

An async refactor of `propose_fixes` or the lenses was considered for v1 and **rejected**. The threadpool wrapper keeps the engine unchanged and avoids blocking other requests. Future endpoints that call sync engine code should use the same pattern.

---

## Per-request isolation (`TemporaryDirectory`)

- One temp directory **per HTTP request** — no cross-request reuse or caching.
- Mode A: `prefix="arguss-scan-"`; clone target `{tmpdir}/{repo_name}`.
- Mode B: `prefix="arguss-upload-"`; repo root is `{tmpdir}` itself.
- Concurrent requests never share tempdirs.

---

## Shallow clone pattern (Mode A)

Implemented in `arguss/web/git_clone.py`:

- Verify `git` on `PATH` via `shutil.which`.
- `subprocess.run([...], timeout=60)` — **list form only**, never `shell=True` (URL is user-influenced).
- Args: `git clone --depth 1 --single-branch --no-tags <clone_url> <dest>`.
- Raises `GitCloneError` on missing git, timeout, or non-zero exit (stderr in the exception message).

---

## URL parsing and normalization (Mode A)

`parse_github_url` (`arguss/web/github_url.py`) accepts common GitHub HTTPS forms (with or without `https://`, optional `.git`, optional `/tree/branch` suffix ignored).

**User-visible normalization:**

- The parser **silently drops port and userinfo** from the input URL. For example, `https://user:pass@github.com:8443/owner/repo` is treated like a normal `github.com` repo URL.
- The clone URL is **always** `https://github.com/{owner}/{name}.git`.
- Only host `github.com` (case-insensitive). No SSH, `git://`, `http://`, or GitHub Enterprise in v1.

---

## Lockfile requirements (v3 only)

Arguss v1 supports **`lockfileVersion` 3** only (`arguss/core/parser.py`). Lockfiles v1 and v2 raise `ParserError` with an actionable message (e.g. run `npm install` with npm 7+).

Supporting older lockfile formats is **out of scope** for v1. Both endpoints surface that as **422** with `Could not parse lockfile: {exc}`, not 500.

---

## Serialization pattern

HTTP and CLI must emit the **same JSON shape** for `ProposalReport`.

- `proposal_report_payload(report)` in `arguss/core/serialization.py` builds the dict and runs **`_to_json_value()`** recursively so the result contains only JSON primitives (enums → `.value`, datetimes → ISO strings).
- **CLI:** `json.dumps(proposal_report_payload(report), indent=2, default=json_default)`.
- **HTTP:** `JSONResponse(content=proposal_report_payload(report))`.

**Convention for future endpoints:** reuse `proposal_report_payload` (or extend `serialization.py` with the same `_to_json_value` pattern). Do not reinvent enum/datetime handling per handler.

---

## Error mapping

### Principle: fault attribution, not exception type

Statuses reflect **who can fix the problem**, not merely which exception was raised:

| Category | Meaning | HTTP style | Client `detail` |
|----------|---------|------------|-----------------|
| **User input** | Bad URL, bad upload, unsafe zip, unsupported lockfile | **4xx** | **Actionable** where possible |
| **Server / environment** | Clone/infra failures, zizmor/tooling failures, bugs | **5xx** | **Generic** — `"Internal error during analysis"`; traceback logged server-side |

`HTTPException` raised inside a handler is **re-raised** (`except HTTPException: raise`) so 4xx responses are not converted to 500 by the outer catch-all.

### `POST /scan/url`

| Condition | HTTP | Client `detail` | Log |
|-----------|------|-----------------|-----|
| `InvalidGitHubURLError` | **400** | `str(exc)` | — |
| `GitCloneError` (non-timeout) | **404** | Repository not found or not accessible | — |
| `GitCloneError` (timeout) | **504** | Clone took too long… | — |
| No root `package-lock.json` | **422** | Repository does not contain a package-lock.json | — |
| `ParserError` | **422** | `Could not parse lockfile: {exc}` | warning |
| `ZizmorClientError` / unexpected | **500** | Internal error during analysis | exception |

### `POST /scan/upload`

| Condition | HTTP | Client `detail` | Log |
|-----------|------|-----------------|-----|
| Missing `lockfile` field | **422** | FastAPI validation error | — |
| Any field over size limit | **413** | `{field} exceeds maximum size of N bytes` | — |
| Lockfile / `package_json` not JSON | **422** | `{field} is not valid JSON` | — |
| `ZipExtractionError` | **422** | `str(exc)` (specific safety message) | — |
| `ParserError` | **422** | `Could not parse lockfile: {exc}` | warning |
| `ZizmorClientError` / unexpected | **500** | Internal error during analysis | exception |

---

## Testing

### Suites

| Suite | Command | Scope |
|-------|---------|--------|
| Mode A unit | `uv run pytest tests/test_scan_url_endpoint.py -v` | URL parser, git clone, `/scan/url` (mocked clone + `propose_fixes`) |
| Mode B unit | `uv run pytest tests/test_scan_upload_endpoint.py -v` | `zip_safe`, `/scan/upload` (mocked `propose_fixes` where needed) |
| Mode A integration | `pytest …/test_scan_url_endpoint.py -m integration` | Real git + OSV against **axios/axios** |
| Mode B integration | `pytest …/test_scan_upload_endpoint.py -m integration` | Real OSV/npm; **`tests/fixtures/lockfiles/real-world.json`** as upload bytes |

**Mode A integration note:** `expressjs/express` no longer has a root `package-lock.json` on its default branch. **`real-world.json`** is a historical `npm install express@4.17.0` snapshot for engine tests, not a live clone of Express.

**Zip unit tests:** Construct small archives inline with `zipfile` in each test — no opaque binary fixtures under `tests/fixtures/`.

### TempDirectory testing pattern

`TemporaryDirectory` is destroyed when the handler’s `with` block exits — **before** `TestClient.post()` returns to the test. Asserting on paths **after** the response (e.g. `(repo_root / "package.json").is_file()`) will fail even when the handler behaved correctly.

**Documented pattern for endpoint tests:** capture filesystem state **inside** a mocked `propose_fixes` (or record paths passed to it), then assert on that captured state. Example: read `package.json` and `.github/workflows/ci.yml` from `repo_path` in the mock’s `side_effect` before returning a fake `ProposalReport`. The same pattern applies to Mode A tempdir cleanup tests (record `repo_path` in the mock, assert `not repo_path.exists()` after the response — the repo root should be gone).

Use this for any future endpoint that assembles state under a per-request tempdir.

---

## Threat surface (Mode B)

Mode B adds risks Mode A does not have:

- **Oversized uploads** — mitigated by per-field byte limits and chunked reads.
- **Malformed JSON** — validated before disk write.
- **Zip bombs / path traversal / symlinks** — mitigated by `zip_safe` (validate-before-extract, uncompressed size limits, path rules).
- **No authentication** — open endpoint for v1 (same as Mode A).

**TODO:** Revise `docs/planning/threat-model.md` after **Mode C** lands to document PAT handling, credentialed GitHub actions, and the cumulative upload + zip surface. Do not fold Mode B zip threats into that doc in the Mode B PR alone — capture them here until the threat model pass.

---

## Follow-up TODOs (not blocking Mode B)

| Item | Notes |
|------|--------|
| **HTTP_413 rename** | Starlette deprecates `HTTP_413_REQUEST_ENTITY_TOO_LARGE` in favor of `HTTP_413_CONTENT_TOO_LARGE` (same class of cleanup as `HTTP_422_UNPROCESSABLE_CONTENT` in the Mode A PR). |
| **Threat model revision** | After Mode C: zip handling, upload limits, session PATs, and credentialed action. |

---

## Deferred

| Item | Notes |
|------|--------|
| **Mode C** — scan with PAT + GitHub Actions | Opt-in credentialed action; session-scoped token handling. |
| **Claude escalation messages** | Structured copy when tier is `REVIEW_REQUIRED` / `DECLINE`. |
| **Request rate limiting** | Fly.io / reverse-proxy; per-IP quotas. |
| **Cache injection into `propose_fixes`** | Shared DB across requests. |
| **Async refactor** of `propose_fixes` or lenses | Rejected for v1. |
| **Landing page** discoverability for `/scan/url` and `/scan/upload` | Small follow-up on `GET /`. |
| **Lockfile v1/v2 support** | Out of scope. |
| **Tarball / non-zip workflow archives** | Zip only in v1. |

---

## Operational entrypoint

Local dev:

```bash
uv run uvicorn arguss.api:app --reload

# Mode A
curl -s -X POST http://127.0.0.1:8000/scan/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://github.com/axios/axios"}' | head

# Mode B — lockfile only
curl -s -X POST http://127.0.0.1:8000/scan/upload \
  -F "lockfile=@tests/fixtures/lockfiles/real-world.json" | head
```

Health check: `GET /health` (unchanged).
