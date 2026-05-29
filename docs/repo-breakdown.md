# C295 Repository Breakdown

Team reference for explaining the Arguss codebase — folder roles and main concepts.

---

## Top-level layout

| Folder | What it is |
|--------|------------|
| **`arguss/`** | Main project — autonomous npm supply chain remediation (MICS Capstone, Summer 2026) |
| **`test-as-package/`** | Standalone npm dev tool that packs/installs a package locally to test its CLI as if published. Unrelated to Arguss engine code. |

---

## What Arguss does (one sentence for the team)

Arguss scans an npm project through **three risk lenses**, proposes dependency upgrades for known CVEs, and assigns each fix a **fix-confidence verdict** (`AUTO_MERGE`, `REVIEW_REQUIRED`, or `DECLINE`) so the system knows when it can act autonomously vs. when a human must review.

---

## End-to-end flow

```
Input modes
  Mode A: GitHub URL
  Mode B: Upload lockfile + optional workflows
  Mode C: URL + PAT → open PRs
        │
        ▼
Ingestion
  core/parser.py — parse package-lock.json
  web/github_fetch.py — GitHub Contents API
        │
        ▼
Three lenses (parallel)
  Vulnerability — OSV, EPSS, KEV
  Trust — npm, deps.dev, typosquat
  Pipeline — zizmor + test reality
        │
        ▼
Decision engine
  fix_discovery — propose upgrade targets
  fix_confidence — tier + score + vetoes
        │
        ▼
Outputs
  Web dashboard (HTMX/Jinja)
  JSON API (/scan/*)
  CLI (arguss)
  Mode C → open_fix_pr (GitHub PRs for AUTO_MERGE)
```

---

## `arguss/` folder map

### Application package — `arguss/arguss/`

| File / folder | Role |
|---------------|------|
| **`api.py`** | FastAPI app entry: mounts static assets, wires dashboard + scan routers, `/health` for Fly.io |
| **`cli.py`** | Typer CLI (`arguss scan`, `propose-fixes`, `sbom`, trust helpers, zizmor) |
| **`settings.py`** | Env-based config (DB path, API keys, demo auth, kill switch) |

#### `core/` — shared contracts and plumbing

The **single source of truth** for data shapes. Everything else consumes/produces these Pydantic/dataclass models.

| Module | Purpose |
|--------|---------|
| **`models.py`** | `Dependency`, `Finding`, `LensScore`, `FixCandidate`, `FixConfidence`, `TrustDelta`, `PipelineSnapshot`, etc. |
| **`parser.py`** | Parses `package-lock.json` into a dependency graph |
| **`cache.py`** | SQLite cache (WAL) for OSV/npm responses — 7-day TTL, reduces API calls |
| **`sbom.py`** | CycloneDX 1.7 SBOM export |
| **`serialization.py`** | JSON payloads for API/CLI responses |

#### `lenses/` — the three analyses

Each lens takes dependencies (and sometimes repo files) and returns findings + a subscore.

| Lens | Module | External sources | What it catches |
|------|--------|-------------------|-----------------|
| **Vulnerability** | `vulnerability.py` + `_osv_client.py`, `_cvss.py`, `_epss_client.py`, `_kev_client.py` | OSV.dev, EPSS, CISA KEV | Known CVEs/GHSAs, exploit likelihood, known-exploited flags |
| **Trust** | `trust.py` + `_trust_client.py` | npm registry, deps.dev | Maintainer changes, typosquat (Levenshtein vs top-1000), publish cadence, download collapse |
| **Pipeline** | `pipeline.py` + `_zizmor_client.py` | zizmor (GitHub Actions) | Workflow misconfigurations + **test reality** (does CI actually run meaningful tests?) |

#### `scoring/` — project-level risk score (PRS)

| Module | Purpose |
|--------|---------|
| **`unified.py`** | Combines lens subscores: **40% CVE + 30% trust + 30% pipeline** → single `ProjectScore` for human-readable risk overview |

This is separate from fix-confidence — PRS answers "how risky is this project?" while fix-confidence answers "is this specific upgrade safe to auto-merge?"

#### `engine/` — the intellectual core

| Module | Purpose |
|--------|---------|
| **`propose.py`** | Main orchestrator: lockfile → lenses → candidates → verdicts → `ProposalReport` |
| **`fix_discovery.py`** | For each CVE finding, picks lowest OSV fixed version → `FixCandidate` |
| **`fix_kind.py`** | Classifies upgrade as patch / minor / major (semver) |
| **`fix_confidence.py`** | **Fix-confidence engine** — combines trust delta, pipeline snapshot, fix kind into tier + 0–100 score + veto signals |
| **`kill_switch.py`** | Operator kill switch to halt all auto-merges |
| **`project_scores.py`** | Aggregates lens subscores for the results UI |
| **`explanation.py`** | Deterministic fallback text when AI is unavailable |

#### `explanations/` — AI layer (Claude)

| Module | Purpose |
|--------|---------|
| **`executive_summary.py`** | High-level scan summary prose |
| **`chat.py`** | Q&A panel on results page |
| **`scan_cache.py`** | Caches scan responses for explanation reuse |
| **`_client.py`** | Anthropic API wrapper |

Fails gracefully to templates if no API key.

#### `web/` — HTTP surfaces

| Module | Purpose |
|--------|---------|
| **`routes.py`** | JSON API: `POST /scan/url`, `/scan/upload`, `/scan/with-action` |
| **`dashboard.py`** | HTML UI: home, scan modes, results page, glossary, chat |
| **`results_context.py`** | Builds template context (tier filters, lens explanations, glossary) |
| **`github_fetch.py`** | Fetches lockfile/workflows via GitHub API (Mode A, no clone) |
| **`github_action.py`** | Opens PRs for AUTO_MERGE candidates (Mode C) |
| **`github_url.py`** | Parses/normalizes GitHub URLs |
| **`git_clone.py`** | Shallow clone when needed |
| **`lockfile_fix.py`** | Applies lockfile changes for PRs |
| **`zip_safe.py`** | Safe extraction of uploaded workflow zips |
| **`auth.py`** | Optional demo password gate |
| **`templates/`** | Jinja2 + HTMX pages and partials |
| **`static/css/`** | Tailwind-based styling |

#### `ai/`

Empty placeholder package — AI logic lives in `explanations/`.

---

### Supporting directories

| Folder | Purpose |
|--------|---------|
| **`data/`** | Static `npm-top-1000-*.txt` for typosquat baseline (refreshed via script) |
| **`docs/`** | Architecture, threat model, planning, Q&A |
| **`docs/planning/`** | Product vision, week plans, fix-confidence design, use cases, pivot rationale |
| **`docs/qanda/`** | Team Q&A notes |
| **`tests/`** | Pytest suite (~35 test files); default run excludes `@pytest.mark.integration` |
| **`tests/fixtures/`** | Sample lockfiles, workflows, mock data |
| **`scripts/`** | `refresh-top-1000.py`, GitHub project bootstrap/sync helpers |
| **`.github/workflows/`** | `ci.yml` (lint/test), `deploy.yml` (Fly.io), `secret-scan.yml` |

---

## Main concepts to explain to the team

### 1. Three lenses (orthogonal risk views)

CVE scanners only see published advisories. Arguss adds:

- **Trust** — "Did the package change hands or behave suspiciously between versions?"
- **Pipeline** — "Can we trust CI to catch a bad upgrade?"

### 2. Fix-confidence verdict (per remediation)

For each `(finding → proposed upgrade)` pair:

| Field | Meaning |
|-------|---------|
| **`tier`** | `AUTO_MERGE` / `REVIEW_REQUIRED` / `DECLINE` |
| **`score`** | 0–100 confidence (for UI + tuning) |
| **`reasons`** | Human-readable explanation |
| **`veto_signals`** | Machine-readable IDs (e.g. `fix_kind.major`, `trust.new_maintainer`, `pipeline.test_reality`) |

**Auto-merge envelope (default):** patch/minor bumps where trust is stable, blast radius is bounded, and CI runs real tests.

### 3. Three input modes (same engine, different I/O)

| Mode | Endpoint / UI | Credentials | Action |
|------|---------------|-------------|--------|
| **A** | GitHub URL | None | Read-only analysis |
| **B** | File upload | None | Read-only (good for private repos) |
| **C** | URL + PAT | User-supplied GitHub token (session-only) | Analyze + open PRs for AUTO_MERGE fixes |

### 4. Two scoring systems (don't conflate them)

| System | Question it answers | Where |
|--------|---------------------|-------|
| **PRS (Project Risk Score)** | "How risky is this repo overall?" | `scoring/unified.py` |
| **Fix-confidence** | "Is this specific upgrade safe to auto-merge?" | `engine/fix_confidence.py` |

### 5. Trust veto flags

When comparing `from_version` → `to_version`:

- Ownership transfer
- New maintainer
- Publish cadence anomaly
- Download collapse

Any of these can force `REVIEW_REQUIRED` even for a patch bump.

### 6. Pipeline "test reality"

Four conditions checked before trusting CI post-upgrade. If tests aren't meaningful, the engine vetoes auto-merge — the agent **refuses to merge blind**.

### 7. Caching and purity

- **SQLite cache** — external API responses (OSV, npm, etc.)
- **Fix-confidence engine is pure** — same inputs → same verdict; only I/O is kill-switch check
- **Audit context** — engine version + timestamp on every verdict for replay

---

## How users interact with Arguss

| Surface | Entry point | Typical use |
|---------|-------------|-------------|
| **Web UI** | `uv run uvicorn arguss.api:app` → `localhost:8000` | Demo, capstone presentation |
| **REST API** | Same server, `/scan/*` + OpenAPI at `/docs` | Programmatic integration |
| **CLI** | `arguss scan`, `arguss propose-fixes`, etc. | Local dev, CI scripts |
| **Production** | https://arguss.fly.dev (deploy from `main` via CI) | Hosted demo |

---

## Stack (quick reference)

- **Python 3.11+**, FastAPI, Typer, Pydantic, Jinja2/HTMX
- **SQLite** cache on Fly.io volume
- **zizmor** for GitHub Actions analysis
- **Anthropic Claude** for explanations (optional)
- **uv** for dependency management

---

## Suggested talking points for your team presentation

1. **Problem:** Detection tools find CVEs; Dependabot merges blindly. Arguss sits in the middle — **autonomous action with a defensible risk model**.
2. **Differentiator:** Trust + pipeline vetoes would have escalated xz-utils-style attacks that CVE-only tools miss.
3. **Architecture:** Single deployable app; lenses are pluggable analyzers; engine is pure and auditable.
4. **Demo story:** Hero case (many AUTO_MERGE), major bump (REVIEW_REQUIRED), maintainer change (trust veto).
5. **Docs to point people at:** `README.md`, `docs/planning/project-overview-v2.md`, `docs/architecture.md`, `docs/threat-model.md`.

---

## `test-as-package/` (sibling project)

A TypeScript npm package for testing a repo's CLI **as if it were already published** — packs, installs into `node_modules`, runs tests without modifying `package.json`. Useful for npm package development; **not wired into Arguss**.

---

## Related documentation

- `README.md` — quick start, API endpoints, CLI commands
- `docs/planning/project-overview-v2.md` — product vision and semester plan
- `docs/architecture.md` — C4-style system design
- `docs/threat-model.md` — security and autonomous-action boundaries
