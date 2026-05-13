# Arguss — Project Development Plan

**Secure CI/CD & Software Supply Chain Risk Analyzer**

*MICS Capstone (CYBER 295) — Summer 2026, Section 1*

---

## Overview

Arguss is a web-based supply chain risk analyzer that unifies three lenses — vulnerabilities, package trust signals, and CI/CD pipeline configuration — into a single explainable risk score, augmented with AI-assisted remediation guidance.

**Tagline:** Three lenses. One risk score.

**Strategy:** Vertical-slice delivery. Build a thin version of all three lenses by Week 5, integrate end-to-end by Week 6, demo-ready by Week 8, then deepen features through Week 11. Deploy publicly from Week 7 onward to a stable URL.

---

## Architecture

### Deployment model

Arguss is deployed as a public web application on Fly.io's free tier, accessible at a stable URL throughout the semester for reviewers and demo audiences. The same codebase also ships as a CLI tool and a GitHub Action, so users can self-host scans for sensitive environments where they don't want dependency data leaving their machine.

The architecture is intentionally simple: one containerized FastAPI service, one SQLite database on a persistent volume, one set of external API integrations. No microservices, no managed databases, no orchestration layer. The complexity budget goes into the analysis engine, not the infrastructure.

```
┌─────────────────────────────────────────────────────────────────┐
│                          User                                    │
│   (browser)        (CLI)         (GitHub Action runner)          │
└────────┬───────────────┬─────────────────┬───────────────────────┘
         │               │                 │
         │ HTTPS         │ uvx arguss      │ docker run
         ▼               ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Arguss application (FastAPI)                    │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐    │
│   │ Vuln     │  │ Trust    │  │ Pipeline │  │ AI Explainer │    │
│   │ Lens     │  │ Lens     │  │ Lens     │  │              │    │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘    │
│        │             │             │                │             │
│        └─────────────┴──────┬──────┴────────────────┘             │
│                             ▼                                     │
│                  ┌──────────────────────┐                         │
│                  │  Unified Scoring     │                         │
│                  │  + Remediation       │                         │
│                  │  Ranker              │                         │
│                  └──────────────────────┘                         │
│                             │                                     │
│              ┌──────────────┴──────────────┐                      │
│              ▼                             ▼                      │
│   ┌─────────────────────┐      ┌─────────────────────┐            │
│   │ HTMX Dashboard      │      │ JSON / SBOM Export  │            │
│   └─────────────────────┘      └─────────────────────┘            │
└────────────────┬──────────────────────────────┬─────────────────┘
                 │                              │
                 ▼                              ▼
        ┌──────────────────┐         ┌──────────────────────────┐
        │ SQLite (WAL)     │         │ External APIs            │
        │ /data/arguss.db  │         │ • OSV.dev                │
        │ • API cache      │         │ • npm registry           │
        │ • AI cache       │         │ • deps.dev               │
        │ • scan history   │         │ • OpenSSF Scorecard      │
        └──────────────────┘         │ • EPSS / CISA KEV        │
                                     │ • Anthropic API          │
                                     └──────────────────────────┘
```

### Hosting decisions

| Layer | Choice | Cost |
|---|---|---|
| **Application hosting** | Fly.io free tier (3 shared-CPU VMs, 256MB RAM) | $0/mo |
| **Database** | SQLite on Fly persistent volume (1GB) | $0/mo |
| **Project webpage** | GitHub Pages (static site) | $0/mo |
| **CI/CD** | GitHub Actions (free for public repos) | $0/mo |
| **Source control** | GitHub (public repo) | $0/mo |
| **Secret scanning** | GitHub Actions + gitleaks | $0/mo |
| **Domain (optional)** | Cloudflare Registrar | $10-15/yr |
| **Anthropic API** | Pay-as-you-go with hard spending cap | ~$5-15/mo total |

**Total semester budget: $15-40**, almost entirely Anthropic API costs.

### Database: SQLite on Fly persistent volume

Storage is SQLite running in WAL mode on a Fly persistent volume, with three logical schemas:

- **API response cache** — OSV.dev, npm registry, deps.dev, OpenSSF Scorecard responses with TTL eviction
- **AI explanation cache** — generated explanations keyed by `(package, from_version, to_version, findings_hash, prompt_version)` with 7-day TTL
- **Scan history** — optional, supports shareable scan URLs

Schema migrations are managed by a lightweight in-app migrator (numbered SQL files applied at startup). The same database engine runs identically across local development, CI, the GitHub Action runner, and production — a single environment variable controls the file path.

**Why not Postgres:** at capstone scale, this is a read-heavy single-server workload with regeneratable data. SQLite's microsecond cache lookups outperform a networked database. Operational overhead is zero. Picking Postgres here would be over-engineering.

### Repository structure

```
arguss/
├── README.md
├── pyproject.toml              # uv-managed dependencies
├── Dockerfile                  # Multi-stage build for Fly deployment
├── fly.toml                    # Fly app configuration
├── .env.example                # Committed template; .env is gitignored
├── .pre-commit-config.yaml
├── .github/
│   ├── workflows/              # ci.yml, security.yml, secret-scan.yml, deploy.yml
│   └── ISSUE_TEMPLATE/         # feature.md, bug.md
├── arguss/
│   ├── __init__.py
│   ├── cli.py                  # Entry point: `arguss scan <path>`
│   ├── api.py                  # FastAPI app
│   ├── settings.py             # Env-aware config (DB path, API keys, etc.)
│   ├── core/
│   │   ├── models.py           # Pydantic: Dependency, Finding, Score
│   │   ├── parser.py           # package-lock.json → dependency graph
│   │   ├── cache.py            # SQLite cache + connection management
│   │   └── migrations/
│   │       └── 001_initial.sql # Schema, applied automatically at startup
│   ├── lenses/
│   │   ├── vulnerability.py    # OSV.dev + EPSS + KEV
│   │   ├── trust.py            # npm registry + typosquat + Scorecard
│   │   └── pipeline.py         # zizmor wrapper
│   ├── scoring/
│   │   └── unified.py          # Weighted formula + remediation ranking
│   ├── ai/
│   │   ├── explainer.py        # Anthropic API client + caching
│   │   ├── prompts.py          # Versioned prompt templates
│   │   └── schemas.py          # Pydantic models for AI I/O
│   └── web/
│       ├── templates/          # HTMX + Jinja2
│       └── static/             # Tailwind output, Cytoscape.js
├── tests/
│   ├── fixtures/               # Sample lockfiles, workflow YAMLs
│   └── ...
└── docs/                       # GitHub Pages source for project webpage
    ├── architecture.md
    ├── scoring-model.md
    ├── threat-model.md
    └── ai-design.md
```

### Data model

```python
class Dependency:
    name: str
    version: str
    ecosystem: str = "npm"
    direct: bool
    path: list[str]              # Path from root to this dep
    parents: list[str]           # What pulled this in

class Finding:
    dependency: Dependency
    lens: Literal["cve", "trust", "pipeline"]
    severity: Literal["critical", "high", "medium", "low"]
    score: float                 # 0-100 normalized
    title: str
    description: str
    remediation: str | None
    source_url: str | None

class LensScore:
    lens: str
    score: float                 # 0-100
    findings: list[Finding]

class Remediation:
    change: str                  # e.g., "upgrade foo from 1.2 to 1.4"
    findings_eliminated: list[Finding]
    score_reduction: float
    explanation: Explanation | None  # AI-generated, optional

class Explanation:
    summary: str
    why_it_matters: str
    migration_risk: Literal["low", "medium", "high", "unknown"]
    migration_notes: str
    suggested_steps: list[str]
    confidence: Literal["low", "medium", "high"]
    generated_at: datetime
    model: str
    prompt_version: str

class ProjectScore:
    overall: float               # 0-100
    lens_scores: dict[str, LensScore]
    top_remediations: list[Remediation]
```

### Scoring formula

```
Project Risk Score = 0.4 × CVE_risk + 0.3 × Trust_risk + 0.3 × Pipeline_risk
```

Weights are configurable. Defaults prioritize known vulnerabilities (the most actionable signal) while giving meaningful weight to the two lenses existing free tools ignore.

### Toolchain

| Layer | Tool |
|---|---|
| Language | Python 3.11+ |
| Package management | uv |
| Web framework | FastAPI |
| Data validation | Pydantic v2 |
| Storage | SQLite (stdlib, WAL mode, no ORM) |
| Frontend | HTMX + Jinja2 + Tailwind |
| Graph viz | Cytoscape.js (CDN) |
| Lint/format | ruff |
| Type checking | mypy |
| Testing | pytest |
| AI | Anthropic API (claude-sonnet-4-5) |
| Pipeline analysis | zizmor (subprocess) |
| Containerization | Docker (multi-stage) |
| Hosting | Fly.io |
| CI | GitHub Actions |
| Pre-commit | pre-commit framework + gitleaks |

---

## Cost controls

The project budget is bounded by four explicit mechanisms, all in place from Day 1:

1. **Fly.io free tier limits** — 3 VMs × 256MB RAM, 3GB total storage, 160GB outbound/month. Capstone traffic stays well under these.
2. **Anthropic spending cap** — hard limit set in the Anthropic console ($20/month). When hit, AI explanations gracefully degrade to "temporarily unavailable" rather than burning money.
3. **Aggressive caching** — every external API response (OSV, npm, deps.dev, Scorecard) cached in SQLite with TTL. AI explanations cached 7 days. Repeated scans of popular packages are free.
4. **Per-IP rate limiting** — public dashboard limits scans-per-hour-per-IP to prevent abuse. The `--no-ai` flag and a UI toggle let users opt out of AI calls.

If any control fails, the next one catches it. The spending cap is the last line of defense.

---

## Project board (GitHub Projects v2)

### Views

1. **Board by status** — Columns: Backlog, This Week, In Progress, In Review, Done
2. **Roadmap by week** — Timeline grouped by Week field; screenshot for Milestone Report and 5-Point Presentation

### Custom fields

- **Week** (single-select: Week 1–14) — when planned
- **Owner** (single-select: team members) — accountable person
- **Lens** (single-select: Vulnerability, Trust, Pipeline, Scoring, AI, Frontend, Infra, Eval) — component
- **Size** (single-select: S=1 day, M=2-3 days, L=1 week) — effort

### Issue templates

- `feature.md` — context, acceptance criteria, **out of scope** (scope creep prevention)
- `bug.md` — reproduction, expected vs actual

### Working rhythm

- Weekly Monday sync: move cards from Backlog → This Week
- Daily async Slack updates: did / next / blocked
- Create issues 1–2 weeks ahead, not 14 weeks ahead

---

## CI/CD setup

### `.github/workflows/ci.yml`

Runs on every push and PR. Lint, format check, type check, test with coverage. **Required status check** for merging to main.

### `.github/workflows/security.yml`

Runs weekly + on dependency changes. `pip-audit` for our own deps, `zizmor` against our own workflows. Eating our own dog food matters — we're a supply chain tool.

### `.github/workflows/secret-scan.yml`

Runs on every push and PR. Gitleaks scans for leaked secrets. Defense against an Anthropic key ending up in the repo.

### `.github/workflows/deploy.yml`

Runs on push to `main` after CI passes. Deploys to Fly.io using `flyctl deploy`. Continuous deployment from Week 7 onward.

### Pre-commit hooks (`.pre-commit-config.yaml`)

- `ruff` (lint + format)
- `gitleaks` (secret scan locally before commit)
- `check-added-large-files`, `check-merge-conflict`, `check-yaml`, `end-of-file-fixer`, `trailing-whitespace`

Every team member runs `pre-commit install` once after cloning.

### Branch protection on `main`

- Require pull request before merging
- Require 1 approval
- Require status checks: `test`, `gitleaks`
- Require conversation resolution
- Do not allow bypassing (protects against tired self-merges)

### `.env` and key handling

```
# .gitignore
.env
.env.*
!.env.example
```

`.env.example` committed with placeholders:

```
ANTHROPIC_API_KEY=sk-ant-...your-key-here
ANTHROPIC_MODEL=claude-sonnet-4-5
OSV_API_BASE=https://api.osv.dev
ARGUSS_DB_PATH=./arguss.db
CACHE_TTL_HOURS=24
AI_EXPLANATION_TTL_DAYS=7
LOG_LEVEL=INFO
```

Each team member copies to `.env` and fills in their own key. Startup validation fails fast with a helpful message if the key is missing or malformed.

Production secrets (Anthropic key, etc.) are set via `flyctl secrets set` and injected as env vars at runtime — never committed.

**The `--no-ai` flag exists from Day 1**, even before AI is built. It's a threat-model mitigation (data leakage to external API) and future-proofs the tool for sensitive environments.

---

## Fake-data skeleton

**Goal:** Every component exists and connects to the next, but each returns hardcoded data. `arguss scan ./anywhere` runs end-to-end on Day 2 of Week 1. Each week replaces one fake with a real implementation.

### Three files form the spine

**`arguss/core/models.py`** — All Pydantic models. Pure data, no logic. Build first; everything depends on it.

**`arguss/lenses/*.py`** — Each lens has the same shape:

```python
class VulnerabilityLens:
    def scan(self, deps: list[Dependency]) -> LensScore:
        # WEEK 3: replace with real OSV.dev integration
        return LensScore(
            lens="cve",
            score=75.0,
            findings=[_fake_finding()],
        )
```

The signature is the contract. When the real implementation lands in Week 3, nothing else changes.

**`arguss/cli.py`** — wires everything:

```python
@app.command()
def scan(path: str):
    deps = parse_lockfile(path)
    cve = VulnerabilityLens().scan(deps)
    trust = TrustLens().scan(deps)
    pipeline = PipelineLens().scan(path)
    score = compute_project_score(cve, trust, pipeline)
    print(score.model_dump_json(indent=2))
```

### Canary integration test

One pytest test that runs the entire CLI end-to-end. Stays green for the whole semester. Catches contract violations immediately.

### Two skeleton principles

1. **Make unified scoring real, not fake.** The math is simple and reusable; verify it works while the lenses are still stubbed.
2. **Fake the slow stuff aggressively.** Anything that would hit a network returns a hardcoded fixture. Full test suite under 2 seconds.

---

## Week-by-week build plan

### Week 1 (May 6) — Ideation, architecture, deployment proof

- Finalize team, confirm Arguss as project name
- Set up repo, CI, project board, fake-data skeleton
- Lock in API key handling: individual `.env` files per team member
- Architecture diagram drafted
- **Sign up for Fly.io, install `flyctl`, deploy a "hello world" FastAPI app** to confirm the deployment toolchain works end-to-end before Week 7

**Deliverable:** Team formed, project topic locked, hello-world deployment live

---

### Week 2 (May 13) — 5W1H submission, scope refinement

- Submit polished 5W1H with Arguss name, syllabus-aligned phasing, AI remediation as step 8 of "How"
- Define three demo scenarios in detail (specific packages, CVEs, workflow misconfigs)
- Write `architecture.md` with three-lens diagram + AI explainer block + deployment topology

**Deliverable:** 5W1H submitted

---

### Week 3 (May 20) — Vulnerability lens v1 + Project Overview

- **Mon–Tue:** package-lock.json v3 parser → `Dependency` objects with transitive graph
- **Wed–Thu:** OSV.dev integration via `/v1/querybatch`; SQLite cache with 24h TTL
- **Fri:** Map vulns to Findings; compute CVE sub-score (max CVSS across critical-path deps, normalized 0–100)

**Risk:** Lockfile v1/v2/v3 schema differences. Pin to v3 only; document constraint.

**Deliverable:** 1–2 page Project Overview

---

### Week 4 (May 27) — Trust signal lens v1 + Milestone Report

- **Mon–Tue:** npm registry API — pull `maintainers`, `time.modified`, `time.created`; cache aggressively
- **Wed:** Typosquatting check — static top-1000 npm list, Levenshtein distance ≤ 2
- **Thu:** Trust sub-score formula:

  ```
  trust_score = clamp(0, 100,
    50
    + (10 if maintainer_count >= 3 else -20 if maintainer_count == 1 else 0)
    + (-30 if days_since_publish < 30 else 0)
    + (-40 if typosquat_distance <= 2 else 0)
    + (-20 if package_age_days < 90 else 0)
  )
  ```
  Document weights in `scoring-model.md`.
- **Fri:** Write Milestone Report covering progress, plan, risks, AI feature planned for Week 10

**Deliverable:** Milestone Report

---

### Week 5 (Jun 3) — Pipeline lens v1 + Solution Design Presentation

- **Mon:** Install zizmor, run against test workflows, study JSON output
- **Tue–Wed:** Wrap zizmor as subprocess, parse output, map findings to normalized severity scale
- **Thu–Fri:** Prep architecture presentation. Show all three lenses + unified scoring + AI explainer as clearly-labeled v2 component + deployment topology.

**Risk:** zizmor severity may not map cleanly. Build explicit mapping table in `scoring-model.md`.

**Deliverable:** Solution Design & Architecture Presentation

---

### Week 6 (Jun 10) — Unified scoring + threat modeling + AI design ⭐

The week AI work shifts from "later" to "designed."

- **Mon–Tue:** Weighted scoring formula, remediation ranker. **Design `Remediation` data model with AI explainer needs baked in** (findings list, version delta, changelog URL slot).
- **Wed:** Threat-model the tool, including AI surface and public deployment surface (class exercise). Cover:
  - Prompt injection via package metadata
  - Data leakage to Anthropic API
  - Hallucinated remediation advice
  - Public web app abuse vectors (scan spam, AI cost exhaustion, malicious lockfile inputs)
  Document in `threat-model.md`.
- **Thu:** Write `ai-design.md` (planning, not code):
  - Why AI for explanations (and why not for analysis)
  - Grounding strategy (structured inputs, not free-form context)
  - Output schema
  - Failure modes and mitigations
  - Cost/latency budget
- **Fri:** Draft prompt template in `prompts.py`. Test manually via Anthropic console with 1–2 example remediations.

**Deliverable:** Working CLI with all three lenses + unified score + AI design doc

---

### Week 7 (Jun 17) — Minimal dashboard + first production deploy + 5-Point Presentation ⭐

- **Mon–Tue:** FastAPI routes + HTMX templates. Three-panel layout: vulnerability findings, trust findings, pipeline findings. Header shows unified score. No graph viz yet — just lists.
- **Wed:** **Write Dockerfile and fly.toml. Deploy dashboard to Fly.io.** Set up `deploy.yml` workflow for continuous deployment on merge to main. Production URL stable from this week onward.
- **Thu:** Polish for mid-point presentation. Bar: reviewer visits the live URL, sees real findings on a real package-lock.json.
- **Fri:** 5-Point Presentation. Lead with architecture, show progress, **demo the live URL**. Mention AI feature briefly — design done, build scheduled for Week 10.

**Note:** In remediation panel mockup, include a disabled "Explain this fix" placeholder button with "coming soon" tooltip. Sets up Week 10 to land cleanly.

**Deliverable:** 5-Point Presentation + live production URL

---

### Week 8 (Jun 24) — Demo polish + PoC delivery

Whole week dedicated to making Week 8's demo not embarrassing.

- Fix UI papercuts; prep demo script; run dry runs with teammates against the live URL
- Build **demo scenario 1**: project with Log4Shell-style transitive CVE. Tool catches it; dashboard shows blast radius (as list — graph comes Week 9)
- Record backup demo video
- Verify cost controls active: rate limiting in place, AI feature gracefully degrades when capped

**Deliverable:** Demo / Proof of Concept

---

### Week 9 (Jul 1) — Blast radius graph + GitHub Action

- **Mon–Wed:** Cytoscape.js dependency graph. Nodes = packages, edges = "depends on." Highlight path from root → vulnerable dep in red. Click node → show findings. Cap at 100 nodes by default with "show all" toggle.
- **Thu–Fri:** GitHub Action wrapper. Workflow runs Arguss on PR, posts comment with unified score and top findings, exits non-zero if score below threshold.

**Class focus: bias and privacy.** Add a paragraph to `scoring-model.md` on potential bias in weights and how users can override them. Update `threat-model.md` with privacy considerations for the public web deployment (what data is logged, retention, etc.).

**Note:** PR comment should include AI explanation placeholder ("Run with `--ai` to get a contextual explanation") to set up Week 10.

---

### Week 10 (Jul 8) — v2 enrichments + AI explainer build ⭐

The week everything comes together.

- **Mon:** EPSS API integration — exploit-prediction weighted into CVE scoring
- **Tue:** CISA KEV catalog — flag findings in known-exploited list
- **Wed (heavy AI day):** Build `RemediationExplainer` class:
  - Anthropic API client with retries and error handling
  - SQLite cache keyed on `(package, from_version, to_version, findings_hash, prompt_version)`, 7-day TTL
  - JSON-mode prompt with schema from Week 6
  - Graceful degradation: if API fails or spending cap reached, remediation still renders without explanation
- **Thu:** Wire explainer into dashboard. "Explain this fix" button → HTMX request → FastAPI endpoint → explainer → explanation HTML. Loading spinner (1–3 second latency).
- **Fri:** OpenSSF Scorecard + CycloneDX SBOM export

**Risk:** If Wednesday hits a snag (prompt won't return clean JSON, caching bugs, rate limits), defer polish to Friday and skip Scorecard. Scorecard is the easier feature to drop.

---

### Week 11 (Jul 15) — Evaluation + 2-minute pitch ⭐

- **Mon–Tue:** Build remaining demo scenarios:
  - **Scenario 2:** xz-style maintainer takeover (single-maintainer + recent ownership + suspicious activity signals)
  - **Scenario 3:** Unpinned-actions workflow with overly broad token scopes
- **Wed:** Run Arguss against 2–3 real npm repos (mid-sized Express app, CLI tool, something with known historical CVEs). Run Snyk and OSV-Scanner against the same repos. Tabulate side-by-side findings, false positive rates, what each tool catches that others miss. Be honest.
- **Thu (AI evaluation):** Evaluate AI explanations:
  - Generate explanations for 15–20 representative remediations
  - Rate each on: factual accuracy (matches changelog/CVE data?), helpfulness (would a developer act on this?), failure mode handling (correctly says "unknown" when data missing?)
  - At least two team members rate independently and compare
  - Document 1–2 failure cases honestly
  - Calculate average latency and cost per explanation
- **Fri:** 2-minute pitch. Lead with three-lens story; close with AI feature (~10 seconds max)

**Deliverable:** 2-minute pitch

---

### Week 12 (Jul 22) — Final deliverable webpage

- Project webpage on GitHub Pages (docs/ folder)
- Sections: problem, solution, architecture, demo scenarios, evaluation results, **AI design and evaluation** (why AI for remediation, grounding strategy, prompt with version, eval results, threat-model considerations), team
- Link prominently to the live Fly URL
- Embed demo video
- Screenshot gallery
- UI polish pass
- Optional: custom domain via Cloudflare Registrar

**Deliverable:** Final Project Deliverables Webpage + live URL stable

---

### Week 13 (Jul 29) — Dry run + iterate

- Present to instructors, gather feedback, fix anything broken
- Practice final presentation until each person can do their section cleanly
- **AI-specific:** Rehearse demo with AI feature visible. Pre-generate explanations for demo scenarios so the demo never blocks on a live API call. Have cached fallback ready.
- **Infrastructure-specific:** Run a small load test against the live URL (`hey` or `siege`, 10-20 concurrent users) to confirm the free-tier VM holds up during the showcase. Have a fallback ready: if Fly is down during your slot, Cloudflare Tunnel from a teammate's laptop hosts the same app in 15 minutes.

---

### Week 14 (Aug 5) — Final showcase

Joint section presentation, 4:00–6:30 PM Pacific.

---

## Risk register

| Risk | Mitigation |
|---|---|
| OSV.dev rate limits or downtime during demo | Aggressive SQLite caching with long TTLs; "demo mode" flag runs entirely offline from cached responses |
| zizmor output format changes | Pin version in `pyproject.toml`; don't auto-upgrade |
| Cytoscape.js performance on large dep graphs | Cap visualization at 100 nodes by default; full graph behind toggle |
| Trust signal false positives (new legitimate packages look like typosquats) | Don't fail builds on trust signals alone in v1; surface as warnings; document in threat model |
| Team member drops or goes silent | Every lens has a backup owner; PR reviews mean ≥2 people understand each piece |
| Scope creep | Maintain "out of scope" list on project board; v3/future work goes there, not in current sprint |
| Anthropic API outage during demo | Pre-generate explanations for all demo scenarios; demo never depends on live API |
| Hallucinated or unhelpful AI explanations | Structured grounding; explicit confidence field; Week 11 evaluation; per-package template fallback if needed |
| API cost overrun | Anthropic spending cap ($20/mo); aggressive caching; per-IP rate limiting; `--no-ai` flag and UI toggle |
| Fly.io outage during showcase | Cloudflare Tunnel from a teammate's laptop as 15-minute fallback; same code, same URL pattern |
| Fly free tier exhausted | 3 VMs × 256MB / 3GB / 160GB bandwidth — all unrealistic at capstone traffic. Monitor dashboard weekly. |
| Public web app abuse (scan spam) | Per-IP rate limiting from Day 1; spending caps catch what rate limits miss |

---

## Division of labor

For a 3–5 person team:

| Role | Owns |
|---|---|
| **Engine lead** | Parser, scoring engine, unified model, AI explainer (grounded in their data model) |
| **Lens leads (1–2 people)** | Vulnerability lens + trust lens + pipeline lens (pipeline often combined with another since zizmor does heavy lifting) |
| **Frontend lead** | Dashboard, blast radius graph, GitHub Action, AI UI affordances |
| **Infra lead** (can be combined with another role) | Dockerfile, Fly deployment, GitHub Actions workflows, cost monitoring |
| **Eval & presentation lead** | Demo scenarios, evaluation methodology, AI eval, final webpage, presentation deck (busiest weeks 11–14) |

Everyone codes. "Lead" = accountable, not solo-builder. Every PR gets a review from someone outside the component owner.

---

## Day 1 setup checklist

1. `pyproject.toml` with FastAPI, Pydantic, Typer, python-dotenv, anthropic, pytest, ruff, mypy, httpx
2. `arguss/core/models.py` with all Pydantic models stubbed
3. `arguss/core/cache.py` with SQLite connection + WAL mode + migration runner
4. `arguss/core/migrations/001_initial.sql` with the three-table schema
5. `arguss/settings.py` with env-aware DB path (local file vs `/data/arguss.db` on Fly)
6. `arguss/lenses/{vulnerability,trust,pipeline}.py` each returning fake data
7. `arguss/scoring/unified.py` with the real 40/30/30 math
8. `arguss/cli.py` wired end-to-end (includes `--no-ai` flag stub)
9. `tests/test_skeleton.py` with the canary integration test
10. `.github/workflows/ci.yml` and `secret-scan.yml`
11. `.pre-commit-config.yaml` and run `pre-commit install`
12. `.env.example` committed, `.env` in `.gitignore`
13. GitHub Project set up with views and custom fields
14. Branch protection on `main` (require PR, 1 approval, status checks)
15. One team member gets a "hello world" Anthropic API call working
16. **Sign up for Fly.io, install `flyctl`, deploy a minimal FastAPI hello-world** to confirm the deployment toolchain end-to-end

When `arguss scan ./test-dir` prints a JSON ProjectScore on your laptop, the same runs green in CI on a PR, *and* a hello-world FastAPI deploy is live on `arguss.fly.dev`, the foundation is complete. Every subsequent week replaces one fake with a real implementation; Week 7 promotes the real app to that same URL.

---

## Success criteria

By Week 14, Arguss demonstrates:

1. **Working tool** — CLI, web dashboard (live at a public URL), GitHub Action all functional on real npm projects
2. **Three lenses unified** — single explainable risk score combining CVE + trust + pipeline analysis
3. **AI-augmented remediation** — grounded LLM explanations with structured output, caching, evaluation
4. **Demonstrated wedge** — three demo scenarios show Arguss catching what Snyk and OSV-Scanner miss
5. **Eats own dog food** — own CI passes Arguss's own checks
6. **Defensible decisions** — scoring weights, threat model, AI design, infrastructure choices all documented and justifiable under questioning
7. **Cost-disciplined** — total semester spend under $40, all controls documented
