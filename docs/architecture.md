# Arguss — Architecture

**Document status:** Draft v1 — to be updated in Week 5 ahead of the Solution Design & Architecture Presentation and again in Week 12 for the final deliverable.

**Audience:** Reviewers, capstone instructors, future maintainers, and the team itself.

---

## 1. System overview

Arguss is a software supply chain risk analyzer that produces a single explainable risk score for a project by combining three independent analyses (called *lenses*) and an AI-assisted remediation layer. It is deployed as a public web application with optional CLI and GitHub Action surfaces.

### Core thesis

Existing free scanners (Snyk Free, Dependabot, OSV-Scanner, Trivy, Grype) match dependencies against a CVE database and stop there. They miss the classes of supply chain attack that have caused the most damage in the last five years — xz-utils (2024), event-stream (2018), ua-parser-js (2021), recurring npm credential theft — because those attacks succeeded *before* any CVE existed.

Arguss closes that gap by analyzing three orthogonal risk dimensions in a single pass, and explaining the highest-leverage remediation in plain language:

| Lens | What it sees | What it catches that CVE-only scanners miss |
|---|---|---|
| **Vulnerability** | OSV.dev CVEs, GHSAs, enriched with EPSS exploit prediction and CISA KEV known-exploited status | Nothing new — this is the table-stakes layer |
| **Trust signals** | Maintainer count, package age, last-publish recency, typosquatting proximity, OpenSSF Scorecard | xz-utils-class maintainer takeovers, slopsquatting, suspicious new packages |
| **Pipeline** | GitHub Actions workflow configuration via zizmor | Unpinned actions, overly broad token scopes, secret leakage, malicious third-party actions |

The unified score weights these as 40% vulnerability, 30% trust, 30% pipeline, with every flag traceable to its source and weights configurable. Remediations are ranked by *risk reduction per change*, and the AI explainer translates each top remediation into a developer-readable explanation grounded in the structured finding data.

---

## 2. System context (C4 Level 1)

```
                                                              ┌──────────────────┐
                                                              │   OSV.dev        │
                                                              │   (vulns)        │
                                                              └────────▲─────────┘
                                                                       │
                              ┌────────────┐                  ┌────────┴─────────┐
                              │            │                  │   npm registry   │
                              │  Developer │                  │   (maintainers)  │
                              │            │                  └────────▲─────────┘
                              └─────┬──────┘                           │
                                    │                          ┌───────┴──────────┐
                                    │ scans                    │   deps.dev       │
                                    │ projects                 │   (package meta) │
                                    ▼                          └──────▲───────────┘
                            ┌───────────────┐                         │
                            │               │                ┌────────┴─────────┐
                            │    ARGUSS     │◄───────────────┤  OpenSSF         │
                            │               │   trust data   │  Scorecard       │
                            │               ├───────────────►│                  │
                            └───────┬───────┘                └──────────────────┘
                                    │
                                    │ generates                 ┌──────────────────┐
                                    │ explanations              │  EPSS API        │
                                    ├──────────────────────────►│  (exploit pred.) │
                                    │                           └──────────────────┘
                                    │
                                    │                           ┌──────────────────┐
                                    │ exploit-prediction        │  CISA KEV        │
                                    │ + known-exploited         │  (catalog)       │
                                    │                           └──────────────────┘
                                    │
                                    │ remediation reasoning     ┌──────────────────┐
                                    └──────────────────────────►│  Anthropic API   │
                                                                │  (Claude)        │
                                                                └──────────────────┘
```

### External actors and systems

| Actor / System | Role | Direction |
|---|---|---|
| **Developer** | Primary user. Scans projects via CLI, web dashboard, or PR-time GitHub Action. | Inbound |
| **OSV.dev** | Open Source Vulnerabilities database. Aggregates CVEs and GHSAs across ecosystems. | Outbound API call |
| **npm registry** | Source of maintainer counts, publish dates, package age. | Outbound API call |
| **deps.dev** | Google's package metadata API. Cross-ecosystem dependency and security data. | Outbound API call |
| **OpenSSF Scorecard** | Automated security health metrics for open-source projects. | Outbound API call |
| **EPSS API** | FIRST.org's Exploit Prediction Scoring System. | Outbound API call |
| **CISA KEV** | Known Exploited Vulnerabilities catalog. | Outbound bulk fetch |
| **Anthropic API** | LLM provider for grounded remediation explanations. | Outbound API call |

All external dependencies are free at the project's usage levels. Anthropic is the only paid service, bounded by a $20/month spending cap.

---

## 3. Container view (C4 Level 2)

Arguss is deliberately a single deployable unit, not a microservice architecture. The "containers" below are processes and storage, not separate services.

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                         Arguss application (single container)                 │
│                                                                               │
│   ┌────────────────┐    ┌────────────────┐    ┌────────────────┐              │
│   │  CLI           │    │  FastAPI       │    │  GitHub Action │              │
│   │  (Typer)       │    │  Web service   │    │  (Docker)      │              │
│   └────────┬───────┘    └────────┬───────┘    └────────┬───────┘              │
│            │                     │                     │                      │
│            └─────────────────────┴─────────────────────┘                      │
│                                  │                                            │
│                                  ▼                                            │
│   ┌─────────────────────────────────────────────────────────────────────┐     │
│   │                       Core analysis engine                          │     │
│   │                                                                     │     │
│   │   ┌─────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐      │     │
│   │   │ Parser  │───▶│ Vuln Lens │    │Trust Lens│    │ Pipeline │      │     │
│   │   │         │    │           │    │          │    │ Lens     │      │     │
│   │   └─────────┘    └─────┬─────┘    └─────┬────┘    └─────┬────┘      │     │
│   │                        │                │                │           │     │
│   │                        └────────────────┼────────────────┘           │     │
│   │                                         ▼                            │     │
│   │                          ┌──────────────────────────┐                │     │
│   │                          │ Unified Scoring          │                │     │
│   │                          │ Remediation Ranker       │                │     │
│   │                          └─────────────┬────────────┘                │     │
│   │                                        │                             │     │
│   │                                        ▼                             │     │
│   │                          ┌──────────────────────────┐                │     │
│   │                          │ AI Explainer (Week 10)   │                │     │
│   │                          │ Anthropic + grounding    │                │     │
│   │                          └──────────────────────────┘                │     │
│   └─────────────────────────────────────────────────────────────────────┘     │
│                                                                               │
│   ┌─────────────────────────────────────────────────────────────────────┐     │
│   │                       Cache (SQLite, WAL mode)                      │     │
│   │   • api_cache          • ai_explanations       • scan_history       │     │
│   └─────────────────────────────────────────────────────────────────────┘     │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Container responsibilities

| Container | Technology | Responsibility |
|---|---|---|
| **CLI** | Typer | Developer-local scanning (`arguss scan`) and **CycloneDX 1.7** SBOM export (`arguss sbom`). Entry point for self-hosted scans and CI/CD integrations. |
| **FastAPI Web** | FastAPI + HTMX + Jinja2 | Public web dashboard. Renders scan results, blast radius graphs, remediation explanations. |
| **GitHub Action** | Docker image wrapping the CLI | PR-time scanning in customer repos. Posts findings as PR comments. |
| **Core analysis engine** | Python | The actual scanning logic — parser, three lenses, scoring, remediation ranker, AI explainer. Shared by all three surfaces. |
| **SQLite cache** | SQLite (WAL mode) | API response cache, AI explanation cache, optional scan history. Single file on a persistent volume. |

The same engine code runs in all three surfaces. There is no separate "API server" or "worker" — Arguss is a library plus three thin entry points.

---

## 4. Component view (C4 Level 3)

This is where the lenses get specified. Each lens has the same shape: take a dependency graph (or workflow files), produce a `LensScore` with a sub-score 0–100 and a list of `Finding` objects.

### 4.1 Vulnerability lens

**Inputs:** `list[Dependency]` from the parser

**Outputs:** `LensScore(lens="cve", ...)`

**Pipeline:**

```
deps → OSV.dev query (batched)
     → enrich each finding with EPSS exploit prediction
     → enrich with CISA KEV (known-exploited flag)
     → trace each finding back through transitive graph (blast radius data)
     → normalize severity to 0-100
     → return LensScore
```

**External calls:**
- `POST https://api.osv.dev/v1/querybatch` — vulnerability lookup (batched for efficiency)
- `POST https://api.first.org/data/v1/epss` — exploit prediction scores
- `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` — KEV catalog (fetched and cached for 24h)

**Sub-score calculation:** Maximum normalized CVSS score across all findings on critical paths, with multipliers for findings in KEV (×1.5, capped at 100) and high-EPSS findings (×1.2, capped at 100). Documented in `scoring-model.md`.

**Caching:** OSV responses cached 24h per package@version. EPSS cached 24h per CVE. KEV catalog cached 24h globally.

### 4.2 Trust signal lens

**Inputs:** `list[Dependency]` from the parser

**Outputs:** `LensScore(lens="trust", ...)`

**Pipeline:**

```
for each dep:
  → npm registry lookup (maintainers, publish dates)
  → deps.dev lookup (cross-ecosystem metadata)
  → OpenSSF Scorecard lookup (security health score)
  → Levenshtein distance against top-1000 npm package list (typosquat check)
  → compute per-package trust sub-score
aggregate → return LensScore
```

**External calls:**
- `GET https://registry.npmjs.org/{package}` — maintainer count, publish dates
- `GET https://api.deps.dev/v3/systems/npm/packages/{name}/versions/{v}` — metadata
- `GET https://api.scorecard.dev/projects/github.com/{owner}/{repo}` — OpenSSF Scorecard (best-effort; not all packages have one)

**Static data:** A top-1000 npm packages list, refreshed quarterly, committed to the repo as JSON.

**Sub-score calculation:** Per-package scoring with weighted signals:

```
trust_score = clamp(0, 100,
  50
  + (10 if maintainer_count >= 3 else -20 if maintainer_count == 1 else 0)
  + (-30 if days_since_publish < 30 else 0)
  + (-40 if typosquat_distance <= 2 else 0)
  + (-20 if package_age_days < 90 else 0)
  + (scorecard_score - 5) * 4  if scorecard_score available
)
```

Aggregated to lens score as the highest individual package score (i.e., worst-trust package dominates), reflecting the "weakest link" nature of supply chain trust.

**Caching:** All external API responses cached 24h. Scorecard responses cached longer (7 days) since they change slowly.

### 4.3 Pipeline lens

**Inputs:** Path to project root

**Outputs:** `LensScore(lens="pipeline", ...)`

**Pipeline:**

```
walk .github/workflows/*.yml
  → invoke zizmor as subprocess
  → parse zizmor JSON output
  → map zizmor severity levels → Arguss severity scale
  → return LensScore
```

**External calls:** None. zizmor is a local binary.

**Sub-score calculation:** Highest severity finding across all workflow files, normalized 0-100. zizmor's `error/warning/note` levels map to `high/medium/low` in Arguss. Mapping table documented in `scoring-model.md`.

**Caching:** Not cached — zizmor is fast and the inputs (workflow files) change frequently.

### 4.4 Unified scoring and remediation ranker

**Inputs:** Three `LensScore` objects

**Outputs:** `ProjectScore` with overall risk and ranked remediations

**Scoring formula:**

```
overall = 0.4 × cve.score + 0.3 × trust.score + 0.3 × pipeline.score
```

Weights are configurable via CLI flag or environment variable. Justified and discussed in `scoring-model.md`.

**Remediation ranking algorithm:**

```
candidates = []
for each direct dependency d in project:
  proposed = find_safe_upgrade_version(d)
  if proposed is None: continue

  with d upgraded to proposed:
    simulated_score = recompute_project_score()

  reduction = current_score - simulated_score
  candidates.append(Remediation(
    change=f"upgrade {d.name} from {d.version} to {proposed}",
    findings_eliminated=findings_no_longer_present,
    score_reduction=reduction,
  ))

return candidates.sort_by(score_reduction, descending=True)[:5]
```

This is the "which one upgrade helps most" answer. The simulation is approximate (it doesn't re-fetch trust signals for the proposed version) but good enough for ranking.

### 4.5 AI explainer

**Inputs:** A `Remediation` object and optional changelog/release-notes text

**Outputs:** An `Explanation` attached to the Remediation

**Pipeline:**

```
remediation → check cache (key: package, from_v, to_v, findings_hash, prompt_v)
  ├─ hit:  return cached explanation
  └─ miss: → build structured prompt with grounding data
           → call Anthropic API (JSON mode)
           → parse and validate response
           → cache for 7 days
           → return
```

**Prompt design:** Structured grounding only — the LLM receives the findings, version delta, and changelog as data, NOT as instructions. The model's job is to translate, not analyze. Output schema is fixed (summary, why_it_matters, migration_risk, migration_notes, suggested_steps, confidence). Detailed in `ai-design.md`.

**Failure modes and mitigations:**

| Failure | Mitigation |
|---|---|
| Anthropic API down | Graceful degradation: remediation renders without explanation |
| Spending cap hit | Same — UI shows "AI explanations temporarily unavailable" |
| Model returns invalid JSON | Retry once, then fall back to template-based summary |
| Hallucinated content | Confidence field surfaces uncertainty; structured grounding limits drift |
| Prompt injection via package metadata | Treat all package metadata as untrusted data, never as instructions |

**Caching:** 7-day TTL keyed on the inputs that affect the explanation. Popular packages get explained once, served from cache to all subsequent users.

---

## 5. Data flow — a complete scan

Walking through what happens when a developer hits the public dashboard and pastes a `package-lock.json`:

```
1. Browser POSTs lockfile content to FastAPI endpoint
2. FastAPI passes content to parser
3. Parser walks package-lock.json v3 schema
   → produces list[Dependency] with transitive graph
4. Engine kicks off three lens scans in parallel (asyncio):
   a. Vulnerability lens
      → batch OSV.dev query (cached responses returned instantly)
      → enrich with EPSS and KEV
   b. Trust lens
      → npm registry calls (parallel, cached)
      → deps.dev calls (parallel, cached)
      → typosquat check against static top-1000 list
   c. Pipeline lens
      → zizmor subprocess against .github/workflows/
5. Three LensScore objects returned to scoring engine
6. Unified scoring engine:
   → computes overall = 0.4×cve + 0.3×trust + 0.3×pipeline
   → runs remediation ranker (simulates upgrades, ranks by reduction)
   → produces ProjectScore
7. FastAPI renders dashboard via Jinja2 + HTMX:
   → three lens panels with findings
   → blast radius Cytoscape.js graph (highlights worst CVE path)
   → remediation panel with disabled "Explain this fix" buttons
8. User clicks "Explain this fix" on top remediation
9. HTMX request → /api/explain endpoint
   → AI explainer checks cache
   → cache miss → Anthropic API call (1-3 seconds)
   → returns Explanation
   → endpoint renders HTML fragment
   → HTMX swaps it into the page
10. Scan result optionally persisted to scan_history table for shareable URL
```

End-to-end latency for a fresh scan of a real npm project: 5-15 seconds for the analysis, plus 1-3 seconds per AI explanation generated. For a cached scan (popular project), under 2 seconds total.

---

## 6. Deployment topology

### Production: Fly.io

```
┌─────────────────────────────────────────────────────────────────┐
│                        Fly.io (iad region)                       │
│                                                                  │
│   ┌────────────────────────────────────────────────────────┐    │
│   │  Machine 1 (shared-cpu-1x, 256MB RAM)                  │    │
│   │  ┌──────────────────────────────────────────────────┐  │    │
│   │  │ Docker container                                 │  │    │
│   │  │  - uvicorn arguss.api:app --port 8080            │  │    │
│   │  │  - FastAPI app                                   │  │    │
│   │  │  - Mount: /data ──┐                              │  │    │
│   │  └────────────────────┼─────────────────────────────┘  │    │
│   │                       │                                │    │
│   └───────────────────────┼────────────────────────────────┘    │
│                           │                                     │
│                           ▼                                     │
│                  ┌────────────────────┐                         │
│                  │ Volume: arguss_data │                         │
│                  │  /data/arguss.db   │                         │
│                  │  (SQLite + WAL)    │                         │
│                  └────────────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
                            ▲
                            │ HTTPS via Fly proxy
                            │
                  https://arguss.fly.dev/
```

### Development: local

```
$ uv run arguss scan .             # CLI mode
$ uv run uvicorn arguss.api:app    # Web mode, port 8000
$ pytest                           # Test mode

SQLite at ./arguss.db (gitignored)
Anthropic key from .env (gitignored)
```

### CI: GitHub Actions

```
On push:
  ci.yml         → lint, format, type-check, test
  secret-scan.yml → gitleaks
On merge to main (after CI passes):
  deploy.yml     → flyctl deploy
Weekly + on dep changes:
  security.yml   → pip-audit, zizmor against own workflows
```

### Customer integration: GitHub Action

```
Customer repo's workflow:
  on: pull_request
  jobs:
    arguss:
      uses: arguss/arguss-action@v1
      with:
        score-threshold: 70
```

The action wraps the Arguss Docker image, runs a scan, posts a comment on the PR with findings, and exits non-zero if the unified score is below the threshold.

---

## 7. Architectural decisions

This section is the lightweight ADR log. Each decision records what was chosen, what was considered, and why.

### ADR-001: Single deployable unit, not microservices

**Decision:** Arguss runs as one FastAPI process with one SQLite database.

**Alternatives considered:** Separate API server + scanner worker + database; serverless functions per lens.

**Rationale:** At capstone scale, microservices add deployment complexity without performance benefit. A single container is easier to reason about, deploy, and debug. The three lenses run in-process as async tasks. If Arguss ever needed horizontal scale (which it won't at this scale), each lens could be extracted; the data model contracts make that possible.

**Tradeoff:** A bug in one lens can affect the whole process. Mitigated by per-lens error handling — a failed lens degrades to "no findings" rather than crashing the scan.

### ADR-002: SQLite over Postgres

**Decision:** SQLite in WAL mode on a Fly persistent volume.

**Alternatives considered:** Fly Postgres, Supabase, DynamoDB, Redis.

**Rationale:** Workload is read-heavy single-server with regeneratable data. SQLite's microsecond cache lookups outperform networked databases at this scale. Zero operational overhead — no separate service to deploy, monitor, or upgrade. Same engine in dev, CI, and production. Picking Postgres would be over-engineering.

**Tradeoff:** Concurrent writes are serialized (one writer at a time). At capstone traffic levels, this is fine. If Arguss ever needed multi-region deployment or higher write concurrency, Litestream could replicate SQLite to S3, or a migration to Postgres would be straightforward (no ORM coupling).

### ADR-003: Fly.io over AWS

**Decision:** Deploy on Fly.io free tier.

**Alternatives considered:** AWS (Lambda, ECS, App Runner, Lightsail), Cloudflare Workers, Render, Railway, Vercel.

**Rationale:** Fly's free tier covers the application's needs entirely ($0/month). No cold starts. Long-running scans fit naturally (no Lambda timeout headaches). Subprocesses (zizmor) and SQLite both work without contortion. Single deploy command. Capstone team has AWS credits but using them for this workload is wasteful — credits are better saved for projects that actually need AWS-specific services.

**Tradeoff:** Vendor lock-in is real but limited — the Dockerfile is platform-agnostic and Fly's config is one file. Migration to any container host (Render, Railway, ECS, Cloud Run) is straightforward.

### ADR-004: Wrap zizmor instead of building our own GHA analyzer

**Decision:** Run zizmor as a subprocess, parse its JSON output.

**Alternatives considered:** Build our own YAML analyzer for GitHub Actions workflows.

**Rationale:** zizmor is a mature, well-maintained Rust tool that does exactly what we need. Building an equivalent would consume weeks of capstone time with worse results. Our value-add is in the *integration* — combining pipeline findings with the other two lenses in a unified score and explainable dashboard.

**Tradeoff:** We're dependent on zizmor's output format. Mitigated by pinning the version in `pyproject.toml` and treating their JSON schema as a contract.

### ADR-005: AI for explanations, not analysis

**Decision:** Use Anthropic's API to *explain* deterministic findings, not to detect them.

**Alternatives considered:** LLM-based risk classification (let the model judge whether a package is suspicious); template-based explanations.

**Rationale:** AI is good at translating structured data into prose; it's bad at producing consistent, evaluable risk scores. Our deterministic scoring engine produces the findings; the AI explains them. This split means hallucinations affect prose quality, not security decisions. Failure modes are bounded — bad explanation, not bad analysis.

**Tradeoff:** Templates would be cheaper and more predictable but produce robotic, less useful explanations. The grounding strategy (structured inputs, JSON output, confidence field) makes the AI useful without trusting it more than warranted.

### ADR-006: Pydantic v2 + stdlib SQLite, no ORM

**Decision:** Pydantic v2 for data validation; raw SQLite via stdlib `sqlite3` module; no ORM.

**Alternatives considered:** SQLAlchemy, SQLModel, Tortoise ORM.

**Rationale:** ORM features (relationships, lazy loading, query builders, migrations) don't help here. Our queries are simple (cache get/set, history insert), our schema is flat, and SQL is the right level of abstraction. Pydantic handles the type safety at the model layer; SQLite handles the storage layer; nothing in between. Less code, less magic, less surface area for bugs.

**Tradeoff:** If the schema grew complex with many tables and relationships, an ORM would start paying off. At capstone scope it doesn't.

### ADR-007: HTMX over React/Vue

**Decision:** HTMX + Jinja2 server-rendered HTML for the dashboard.

**Alternatives considered:** React SPA, Vue, vanilla JS.

**Rationale:** The dashboard is mostly read-heavy with light interactivity (toggle filters, "explain this fix" buttons, graph navigation). HTMX is server-side state, no build pipeline, no JavaScript framework to wrestle with. The team is mostly security-focused and HTMX has the shallowest learning curve. Cytoscape.js handles the one heavy JS component (dependency graph) as an isolated widget.

**Tradeoff:** HTMX is less mainstream than React. Mitigated by HTMX's simplicity — most patterns are obvious from one example.

### ADR-008: One ecosystem (npm) in v1

**Decision:** npm only for the capstone. pip, Maven, Go, etc. are future work.

**Alternatives considered:** Multi-ecosystem from day one.

**Rationale:** Going deep on one ecosystem produces a better tool in 14 weeks than going shallow on four. npm is the right pick — most attacked, richest public API surface, most dramatic demo stories (event-stream, ua-parser-js, slopsquatting). The data model is ecosystem-agnostic (`Dependency.ecosystem` is already a field), so adding pip later doesn't require rearchitecting.

**Tradeoff:** Reviewers might ask "what about pip?" The answer is "future roadmap" — and the architecture supports it without changes.

---

## 8. Security and threat model summary

A full threat model lives in `threat-model.md`. The high points:

### Attack surfaces

| Surface | Threats | Key mitigations |
|---|---|---|
| **Public dashboard** | Scan spam, AI cost exhaustion, malicious lockfile inputs | Per-IP rate limiting; Anthropic spending cap; lockfile parser validates structure; max dep count limit |
| **AI explainer** | Prompt injection via package metadata, data leakage to external API | Structured grounding (data not instructions); `--no-ai` flag for sensitive environments; documented in privacy notice |
| **External APIs** | Compromised OSV response, npm registry MITM | TLS required; response schema validation; defense-in-depth (we don't trust any single source) |
| **Database** | SQL injection (we don't use raw user input in SQL); volume corruption | Parameterized queries only; SQLite's atomic write semantics; regeneratable cache (data loss is recoverable) |
| **Our own CI/CD** | Compromised GitHub Action, leaked Fly token, malicious dependency | We eat our own dog food: zizmor runs against our workflows; gitleaks on every commit; pre-commit hooks; pip-audit weekly |

### Trust boundaries

```
              UNTRUSTED                            TRUSTED
                  │                                  │
   User input ────┼──► Schema validation ───────────►│ Pydantic model
                  │                                  │
   Package    ────┼──► Treated as data,             ►│ Never injected
   metadata       │    never as instructions         │ into prompts
                  │                                  │
   External   ────┼──► Response validation,         ►│ Cached results
   APIs           │    timeout, retry limits         │
```

---

## 9. Glossary

| Term | Definition |
|---|---|
| **Blast radius** | The set of dependencies transitively affected by a single vulnerable package. Shown visually as the path from a project's direct dependency to the vulnerable transitive package. |
| **CISA KEV** | CISA's Known Exploited Vulnerabilities catalog. A curated list of CVEs known to be exploited in the wild. |
| **CVE** | Common Vulnerabilities and Exposures — a public identifier for a known security flaw. |
| **CVSS** | Common Vulnerability Scoring System. A standardized severity score 0-10 for a CVE. |
| **CycloneDX** | OWASP standard for machine-readable SBOMs. Arguss emits **CycloneDX 1.7** JSON (ECMA-424 2nd Edition) from the lockfile parser via `arguss sbom`. |
| **EPSS** | Exploit Prediction Scoring System. FIRST.org's probabilistic prediction of which CVEs will be exploited in the next 30 days. |
| **Lens** | An independent analysis dimension in Arguss. Three lenses: vulnerability, trust, pipeline. |
| **OSV** | Open Source Vulnerabilities. A vulnerability database covering many ecosystems, run by Google's OSS-Fuzz team. |
| **SBOM** | Software Bill of Materials — a structured inventory of components (here: npm packages from `package-lock.json`). |
| **Scorecard** | OpenSSF Scorecard. Automated checks producing a 0-10 security health score for an open-source project. |
| **Slopsquatting** | A 2024+ supply chain attack pattern: attackers register packages with names AI coding assistants are known to hallucinate. |
| **Trust signal** | Any non-CVE indicator that a package may be risky — maintainer changes, age, typosquat similarity, etc. |
| **Typosquatting** | Registering a package with a name similar to a popular one (`reqests` vs `requests`) to catch typos. |
| **zizmor** | An open-source static analyzer for GitHub Actions workflows. Arguss wraps it for the pipeline lens. |

---

## 10. Document history

| Version | Date | Author | Changes |
|---|---|---|---|
| Draft v1 | Week 2 (May 13, 2026) | Capstone team | Initial architecture document |
| v2 (planned) | Week 5 (Jun 3, 2026) | Capstone team | Update for Solution Design Presentation |
| v3 (planned) | Week 12 (Jul 22, 2026) | Capstone team | Final version for project deliverable webpage |
