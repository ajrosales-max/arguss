# Web service architecture — scan modes and HTTP layer (Week 7)

This document describes how the Arguss **hosted web service** exposes the same remediation engine as the CLI (`arguss propose-fixes`), starting with **Mode A** (`POST /scan/url`). Modes B and C are specified here for context but are not implemented in the Week 7 PR.

**Related docs:** `project-overview-v2.md` (product framing), `fix-confidence-engine.md` (engine and `ProposalReport` shape).

**Code map:**

| Concern | Module |
|---------|--------|
| FastAPI app | `arguss/api.py` |
| Scan routes | `arguss/web/routes.py` |
| GitHub URL parsing | `arguss/web/github_url.py` |
| Shallow clone | `arguss/web/git_clone.py` |
| JSON payloads | `arguss/core/serialization.py` |
| Orchestration (unchanged) | `arguss/engine/propose.py` |

---

## Three input modes (shared engine)

All modes run the same pipeline: parse lockfile → vulnerability lens → fix discovery → trust delta per candidate → pipeline snapshot → fix-confidence engine → `ProposalReport`.

| Mode | Input | Credentials | Mutates repo? | Status |
|------|--------|-------------|---------------|--------|
| **A — Repo URL** | Public `https://github.com/{owner}/{repo}` | None | No (read-only shallow clone) | **Shipped** — `POST /scan/url` |
| **B — File upload** | `package-lock.json` (+ optional workflows / `package.json`) | None | No | Deferred |
| **C — URL + PAT** | Repo URL + GitHub token | User PAT (session-scoped) | Yes (open PRs, merge in-envelope) | Deferred |

Mode A is the primary demo path: paste a URL, receive a structured remediation plan as JSON. Modes B and C differ only in how inputs are collected and whether GitHub write APIs are used; they must not fork the engine.

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
7. Temp directory is removed when the `with` block exits (before the response is fully sent to the client).

Read-only: no branches, commits, or PRs.

---

## Sync/async pattern

`propose_fixes` is **synchronous** and performs blocking I/O (SQLite cache, HTTP to OSV/npm, subprocess for zizmor). The HTTP handler is `async def` but **must not** call `propose_fixes` directly on the event loop.

```python
report = await run_in_threadpool(propose_fixes, lockfile_path, work_tree)
```

An async refactor of `propose_fixes` or the lenses was considered for v1 and **rejected**. The threadpool wrapper keeps the engine unchanged and avoids blocking other requests. Future endpoints that call sync engine code should use the same pattern.

---

## Per-request isolation (`TemporaryDirectory`)

- One temp directory **per HTTP request** — no cross-request reuse or caching of clone results.
- Concurrent scans of the same public repo get independent tempdirs (acceptable duplication).
- Clone target: `{tmpdir}/{parsed.name}` (repo name from the URL, not owner).

---

## Shallow clone pattern

Implemented in `arguss/web/git_clone.py`:

- Verify `git` on `PATH` via `shutil.which`.
- `subprocess.run([...], timeout=60)` — **list form only**, never `shell=True` (URL is user-influenced).
- Args: `git clone --depth 1 --single-branch --no-tags <clone_url> <dest>`.
- Returns the resolved working tree path (`dest`).
- Raises `GitCloneError` on missing git, timeout, or non-zero exit (stderr included in the exception message).

---

## URL parsing and normalization

`parse_github_url` (`arguss/web/github_url.py`) accepts common GitHub HTTPS forms (with or without `https://`, optional `.git`, optional `/tree/branch` suffix ignored).

**User-visible normalization:**

- The parser **silently drops port and userinfo** from the input URL. For example, `https://user:pass@github.com:8443/owner/repo` is treated like a normal `github.com` repo URL.
- The clone URL is **always** the canonical form: `https://github.com/{owner}/{name}.git`.
- Only host `github.com` (case-insensitive). No SSH (`git@…`), no `git://`, no `http://`, no GitHub Enterprise hosts in v1.

Callers should not assume the echoed clone URL preserves arbitrary URL components from user input.

---

## Lockfile requirements (v3 only)

Arguss v1 supports **`lockfileVersion` 3** only (`arguss/core/parser.py`). Lockfiles v1 and v2 raise `ParserError` with an actionable message (e.g. directing the user to run `npm install` with npm 7+).

Supporting older lockfile formats is **out of scope** for v1. On `/scan/url`, that surfaces as **422** (see error table), not 500.

---

## Serialization pattern

HTTP and CLI must emit the **same JSON shape** for `ProposalReport`.

- `proposal_report_payload(report)` in `arguss/core/serialization.py` builds the dict and runs **`_to_json_value()`** recursively so the result contains only JSON primitives (enums → `.value`, datetimes → ISO strings, nested dicts/lists walked).
- **CLI:** `json.dumps(proposal_report_payload(report), indent=2, default=json_default)` — `json_default` remains a backstop for other commands (trust/pipeline debug).
- **HTTP:** `JSONResponse(content=proposal_report_payload(report))` — no per-handler enum unwrapping.

**Convention for future endpoints:** reuse `proposal_report_payload` (or extend `serialization.py` with the same `_to_json_value` pattern). Do not reinvent enum/datetime handling in individual routes.

---

## Error mapping

### Principle: fault attribution, not exception type

Statuses are chosen by **who can fix the problem**, not by which Python exception was raised:

| Category | Meaning | HTTP style | Client `detail` |
|----------|---------|------------|-----------------|
| **User input** | Bad URL, repo unsuitable for scan, lockfile Arguss cannot parse | **4xx** | **Actionable** — parser/validation text or a clear, stable message |
| **Server / environment** | Arguss misconfiguration, clone infrastructure failure, pipeline tool failure, bugs | **5xx** | **Generic** — `"Internal error during analysis"`; full traceback logged server-side only |

`HTTPException` raised inside the handler is **re-raised** by the outer `except HTTPException: raise` so 4xx responses are never turned into 500.

### Full mapping (`POST /scan/url`)

| Condition | HTTP | Client `detail` | Log level |
|-----------|------|-----------------|-----------|
| `InvalidGitHubURLError` (malformed URL, wrong host, SSH, etc.) | **400** | `str(exc)` from parser | — |
| `GitCloneError` (non-timeout: missing repo, private repo, git missing, network error) | **404** | `"Repository not found or not accessible"` | — |
| `GitCloneError` (timeout: `TimeoutExpired` on `__cause__` or `"timed out"` in message) | **504** | `"Clone took too long; repository may be too large"` | — |
| Cloned repo has no root `package-lock.json` | **422** | `"Repository does not contain a package-lock.json"` | — |
| `ParserError` (unsupported lockfile version, corrupt lockfile, etc.) | **422** | `"Could not parse lockfile: {exc}"` (includes parser guidance) | **warning** |
| `ZizmorClientError` during `propose_fixes` | **500** | `"Internal error during analysis"` | **exception** |
| Any other unexpected error in analysis or handler | **500** | `"Internal error during analysis"` | **exception** |

**Notes:**

- **404 for clone failures** treats “this public URL does not yield a cloneable tree” as a client-addressable outcome (wrong URL, private repo, deleted repo), not an Arguss internal bug.
- **422 for `ParserError`** exposes parser messages (e.g. lockfile v1/v2) because the user can regenerate the lockfile; this is intentional, not information leakage.
- **500** responses never include stack traces or exception type names in the JSON body.

---

## Testing

| Suite | Command | Scope |
|-------|---------|--------|
| Unit (default) | `uv run pytest tests/test_scan_url_endpoint.py -v` | URL parser, git clone wrapper (mocked subprocess), endpoint (mocked clone + `propose_fixes`) |
| Integration | `uv run pytest tests/test_scan_url_endpoint.py -v -m integration` | Real git clone + real OSV/npm against **axios/axios** |

**Integration repo choice:** The prompt’s example repo `expressjs/express` no longer ships a root `package-lock.json` on its default branch, so a live clone returns **422** before analysis. The integration test uses **`https://github.com/axios/axios`** (lockfile v3 at repo root). The pinned Express tree used elsewhere is **`tests/fixtures/lockfiles/real-world.json`** — a historical `npm install express@4.17.0` snapshot for unit/integration tests of the engine, not a clone of the Express repository itself.

---

## Deferred (explicitly out of Week 7 PR)

| Item | Notes |
|------|--------|
| **Mode B** — `POST /scan/upload` | Multipart lockfile (+ optional workflow files); separate threat model (upload size, malware scanning). |
| **Mode C** — scan with PAT + GitHub Actions | Opt-in credentialed action; session-scoped token handling. |
| **Claude escalation messages** | Structured copy when tier is `REVIEW_REQUIRED` / `DECLINE`. |
| **Request rate limiting** | Fly.io / reverse-proxy limits; per-IP quotas. |
| **Cache injection into `propose_fixes`** | Shared DB across requests; tracked for Week 7+. |
| **Async refactor** of `propose_fixes` or lenses | Rejected for v1; threadpool only. |
| **Landing page** discoverability for `/scan/url` | Small follow-up on `GET /`. |
| **Lockfile v1/v2 support** | Out of scope; 422 with npm 7+ guidance only. |

---

## Operational entrypoint

Local dev:

```bash
uv run uvicorn arguss.api:app --reload
curl -s -X POST http://127.0.0.1:8000/scan/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://github.com/axios/axios"}' | head
```

Health check: `GET /health` (unchanged).
