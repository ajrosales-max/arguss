# Arguss — Use Cases & Delivery Plan

**Status:** Living document (May 2026). Supersedes scattered use-case mentions in course submissions.

**Related:** [`project-overview-v2.md`](project-overview-v2.md) (product framing), [`web-service-architecture.md`](web-service-architecture.md) (Modes A/B/C), [`fix-confidence-engine.md`](fix-confidence-engine.md) (verdict model), [`github-project-setup.md`](github-project-setup.md) (GitHub Project + issues).

**Note:** `arguss-project-plan.md` is the original 14-week scanner-era plan. This document is the **use-case-driven plan** after the Week 2 (remediation) and Week 6 (web UI) pivots.

---

## MoSCoW summary

| Priority | ID | Use case | Primary mode(s) | Delivery window |
|----------|-----|----------|-----------------|-----------------|
| **Must** | UC1 | Read-only dependency audit | A, B | ✅ Shipped; polish Weeks 8–9 |
| **Must** | UC2 | Auto-remediate low-impact upgrades | C (partial) | ✅ Verdicts shipped; PR open shipped; CI merge **out of scope v1** |
| **Must** | UC3 | Generate SBOM for compliance | CLI; web TBD | ✅ CLI shipped; web export Week 10 / sprint |
| **Must** | UC4 | Evaluate before granting GitHub credentials | A, B → C | ✅ Shipped; demo script Week 8 |
| **Should** | UC5 | Fix-confidence check on contested fix | A, B, C | ✅ Shipped; reasoning UI polish Week 8–9 |
| **Should** | UC6 | AI-generated explanations | All (escalations) | ✅ Shipped; pre-cache for demo Week 8 |
| **Could** | UC7 | Triage active supply chain incident | A, B | Week 10+ (no dedicated UI) |
| **Won't** | UC8 | Org-wide operational rollout | — | Out of semester scope |

---

## Input modes (shared by all use cases)

| Mode | Endpoint / UI | Credentials | Mutates target repo? |
|------|---------------|-------------|----------------------|
| **A** | `POST /scan/url`, `/dashboard/scan` | Optional `ARGUSS_GITHUB_TOKEN` (server) for rate limits | No |
| **B** | `POST /scan/upload`, `/dashboard/upload` | None | No |
| **C** | `POST /scan/with-action`, `/dashboard/scan-with-action` | User PAT (session only) | Yes — opens PRs for `AUTO_MERGE` only; **does not merge** |

All modes run the same engine: `propose_fixes` → `ProposalReport` (findings, candidates, fix-confidence verdicts).

---

## UC1 — Run a read-only dependency audit

**Priority:** Must
**Actors:** Developer, DevSecOps engineer
**Goal:** Understand CVE exposure and remediation tiers without granting write access.

### User story

As a maintainer, I submit a public repo URL or upload a `package-lock.json` so Arguss lists vulnerabilities, proposed version bumps, and fix-confidence tiers (AUTO_MERGE / REVIEW_REQUIRED / DECLINE) with reasons and veto signals.

### Acceptance criteria

- [x] Mode A: public GitHub URL + optional `ref` fetches lockfile/workflows via Contents API.
- [x] Mode B: multipart upload with size limits; optional workflows zip and `package.json`.
- [x] Response includes per-finding transitive path, CVSS where available, and per-candidate verdict.
- [x] Project-level lens subscores and PRS available in UI (secondary to per-fix verdicts).
- [ ] Frozen demo target documented (`expressjs/express` fork pin) with expected finding counts.
- [ ] Public Fly URL stable with demo auth for class reviewers.

### Implementation

| Layer | Location |
|-------|----------|
| API | `arguss/web/routes.py` — `/scan/url`, `/scan/upload` |
| UI | `arguss/web/dashboard.py`, `templates/index.html`, `results.html` |
| Engine | `arguss/engine/propose.py` |
| CLI equivalent | `arguss propose-fixes` |

### Schedule

| Phase | Weeks | Work |
|-------|-------|------|
| Core | 3–7 | ✅ Lenses + engine + HTTP + dashboard |
| Polish | 8–9 | Express fork, demo button, error UX, cold-start note on Fly |
| Eval | 11 | Compare detection overlap vs Snyk on same lockfile |

---

## UC2 — Auto-remediate low-impact dependency upgrades

**Priority:** Must (reframed for v1 — see scope note)
**Actors:** Developer opting in with PAT
**Goal:** Act on fixes the engine trusts, without blind Dependabot-style bumps.

### Scope note (honest v1)

Course copy sometimes says “wait on CI and merge.” **Shipped behavior:** Arguss assigns `AUTO_MERGE` tier and, in Mode C, **opens one PR per candidate** on a deterministic branch (`arguss/fix-{id}`). It does **not** poll CI or merge. Full merge automation is **Could / post-v1**.

### User story

As a maintainer who trusts Arguss’s envelope, I provide a PAT so Arguss opens PRs only for `AUTO_MERGE` candidates, with structured description and veto-free reasoning. I merge after my CI passes.

### Acceptance criteria

- [x] Fix-confidence engine: patch/minor in envelope → `AUTO_MERGE`; major / trust / pipeline vetoes → `REVIEW_REQUIRED`.
- [x] Mode C opens PRs only for `AUTO_MERGE`; idempotent branch names.
- [x] PR body states agent has **not** merged.
- [x] Kill switch and project veto halt auto-action paths.
- [ ] Documented demo on **owned test repo** (not upstream Express).
- [ ] Optional stretch: CI status poll + merge when green (feature-flagged).

### Implementation

| Layer | Location |
|-------|----------|
| Engine | `arguss/engine/fix_confidence.py` |
| Action | `arguss/web/github_action.py`, `lockfile_fix.py` |
| API | `POST /scan/with-action` |
| UI | Mode C form on `index.html`, `results_with_actions.html` |

### Schedule

| Phase | Weeks | Work |
|-------|-------|------|
| Engine | 6 | ✅ Fix-confidence + `propose-fixes` |
| Action | 7–9 | ✅ PR open path |
| Polish | 8 | Dry-run Mode C on test repo; consent copy |
| Stretch | 10+ | CI wait/merge if team capacity |

---

## UC3 — Generate an SBOM for a compliance audit

**Priority:** Must
**Actors:** Security/compliance reviewer
**Goal:** CycloneDX 1.7 export for EO 14028 / CISA SBOM alignment narrative.

### User story

As a compliance reviewer, I export a CycloneDX SBOM for the same dependency graph Arguss analyzed.

### Acceptance criteria

- [x] CLI: `arguss sbom <path>` emits CycloneDX 1.7 JSON.
- [x] SBOM components dedupe by `(name, version)` with merged parent paths.
- [ ] Web: download SBOM from last scan — **not shipped**.
- [ ] Sample SBOM artifact for reviewers (docs or demo repo).

### Implementation

| Layer | Location |
|-------|----------|
| Generator | `arguss/core/sbom.py` |
| CLI | `arguss/cli.py` — `sbom` command |

### Schedule

| Phase | Weeks | Work |
|-------|-------|------|
| Core | 3 | ✅ SBOM generator |
| Web | 10 or sprint W2 | Export after scan |
| Final | 12 | SBOM on project webpage |

---

## UC4 — Evaluate Arguss before granting GitHub credentials

**Priority:** Must
**Actors:** Security-conscious developer
**Goal:** See full remediation plan without PAT.

### User story

As a user evaluating Arguss, I run Mode A or B first, review AUTO_MERGE vs REVIEW_REQUIRED counts and veto signals, and only then opt into Mode C on a repo I control.

### Acceptance criteria

- [x] Modes A and B require no user GitHub token.
- [x] Mode C form separated with consent notice.
- [x] Threat model documents session-only PAT handling.
- [ ] Demo script always shows A → optional C.
- [ ] Threat model signed off by team.

### Implementation

| Layer | Location |
|-------|----------|
| UI flow | `index.html` — three sections in order |
| Threat model | `docs/threat-model.md` |

### Schedule

| Phase | Weeks | Work |
|-------|-------|------|
| Product | 6 pivot | ✅ Three-mode design |
| Demo | 8 | Scripted “trust ladder” for presentation |
| Sign-off | 8 | Threat model review |

---

## UC5 — Get a fix-confidence check on a contested fix

**Priority:** Should
**Actors:** Developer reviewing a risky upgrade
**Goal:** Understand why Arguss escalated (or approved) a specific bump.

### User story

As a developer, I inspect one remediation and see tier, score, human reasons, and machine-readable `veto_signals` (e.g. `fix_kind.major`, `trust.new_maintainer`).

### Acceptance criteria

- [x] Every `ProposalEntry` includes `verdict.tier`, `score`, `reasons`, `veto_signals`.
- [x] UI finding card shows tier badge, score, veto chips, reasons, transitive path.
- [ ] Demo Scenario B (major bump) and C (trust save) scripted with expected signals.
- [ ] Optional: per-entry “Explain” for REVIEW_REQUIRED via Claude.

### Implementation

| Layer | Location |
|-------|----------|
| Engine | `arguss/engine/fix_confidence.py` |
| UI | `partials/_finding_card.html` |

### Schedule

| Phase | Weeks | Work |
|-------|-------|------|
| Core | 6 | ✅ Engine + card partial |
| Demo | 8–11 | Scenarios B & C on frozen fork |
| Polish | 9 | Collapsible “why this tier” panel |

---

## UC6 — Receive AI-generated explanations of findings

**Priority:** Should
**Actors:** Developer receiving escalations
**Goal:** Natural-language summary without AI affecting AUTO_MERGE decisions.

### User story

As a user, I see an executive summary and escalation prose that names veto signals and what to review — from Claude with template fallback if the API fails.

### Acceptance criteria

- [x] Claude not on auto-merge decision path.
- [x] Graceful degradation when `ANTHROPIC_API_KEY` missing.
- [x] SQLite cache for explanations.
- [ ] Pre-generated explanations for demo scenarios (Week 8).
- [ ] Spending cap documented in ops runbook.

### Implementation

| Layer | Location |
|-------|----------|
| Client | `arguss/explanations/_client.py` |
| Executive summary | `arguss/explanations/executive_summary.py` |
| Verdict prose | `arguss/engine/explanation.py` |

### Schedule

| Phase | Weeks | Work |
|-------|-------|------|
| Build | 7 | ✅ Shipped |
| Demo | 8 | Pre-cache; never block live demo on API |
| Eval | 11 | Sample rating for accuracy/helpfulness |

---

## UC7 — Triage an active supply chain incident

**Priority:** Could
**Actors:** Security responder
**Goal:** Fast prioritization during an active incident.

### User story

As a responder, I point Arguss at a repo or lockfile and use severity + trust vetoes + EPSS/KEV (when available) to rank what to patch first.

### Acceptance criteria

- [ ] EPSS and/or CISA KEV enrichment on findings (Week 10).
- [ ] Sort/filter UI by severity and exploitability.
- [x] Read-only scan (UC1) sufficient for minimal triage today.

### Schedule

| Phase | Weeks | Work |
|-------|-------|------|
| Minimal | 8 | UC1 + manual sort by tier/severity |
| Enrichment | 10 | EPSS/KEV flags (display-only first) |
| Full UC7 | 11+ | Dedicated incident view only if time |

---

## UC8 — Operationalize Arguss across an engineering organization

**Priority:** Won't (semester)
**Rationale:** No multi-tenant auth, org dashboards, webhooks, or GitHub App install. Document as future work on the final webpage.

---

## Traceability matrix

| UC | Mode A | Mode B | Mode C | CLI | Primary output |
|----|--------|--------|--------|-----|----------------|
| UC1 | ✅ | ✅ | — | `propose-fixes` | `ProposalReport` |
| UC2 | — | — | ✅ (PR open) | — | PR URLs in `actions[]` |
| UC3 | — | — | — | `sbom` | CycloneDX JSON |
| UC4 | ✅ | ✅ | optional | `propose-fixes` | Same as UC1 |
| UC5 | ✅ | ✅ | ✅ | `propose-fixes` | `verdict` per entry |
| UC6 | ✅ | ✅ | ✅ | — | `executive_summary` + templates |
| UC7 | ✅ | ✅ | — | `scan` | Lens findings (partial) |
| UC8 | — | — | — | — | N/A |

---

## 14-week delivery map (by use case)

| Week | Syllabus focus | Use cases advanced |
|------|----------------|-------------------|
| 1–2 | Ideation, 5W1H, pivot | UC8 excluded; scope UC1–UC4 |
| 3 | Vulnerability lens, SBOM | UC1 (partial), UC3 (CLI) |
| 4 | Trust lens | UC1, UC5 (trust vetoes) |
| 5 | Pipeline lens | UC1, UC5 (pipeline vetoes) |
| 6 | Fix-confidence, threat model | UC2 (verdicts), UC5 |
| 7 | Request handler, explanations | UC1–UC6 (API + AI) |
| 8 | **Demo / PoC** | UC1, UC4, UC6 — dry runs; UC2 on test repo |
| 9 | Web UI polish | UC1, UC4, UC5 — reasoning panel |
| 10 | v2 enrichments | UC3 (web SBOM), UC7 (EPSS/KEV) |
| 11 | **Evaluation** | Must/Should — Snyk/Dependabot comparison |
| 12 | Final webpage | UC1–UC6 screenshots; honest UC2 scope |
| 13–14 | Dry run, showcase | UC1–UC6 demo script |

---

## Three-week sprint overlay (go-live: ~May 27 – Jun 16, 2026)

| Sprint week | UC1 | UC2 | UC3 | UC4 | UC5 | UC6 | UC7 |
|-------------|-----|-----|-----|-----|-----|-----|-----|
| **W1** Truth & demo target | Express fork, Fly verify | — | CLI docs | Consent copy | — | — | — |
| **W2** PoC | Pre-cache scan | Mode C dry-run | Web SBOM? | A→C script | Scenarios B/C | Pre-cache AI, video | — |
| **W3** Eval & ship | Snyk table | Document no-merge v1 | Web export? | Threat sign-off | Eval scenarios | — | EPSS display? |

---

## Open gaps (use case vs code)

| Gap | Affects | Plan |
|-----|---------|------|
| CI wait + merge | UC2 | Won't v1; document as future |
| Blast radius veto in engine | UC2, UC5 | Document or implement threshold |
| OpenSSF Scorecard / deps.dev | UC1, UC7 | Week 10 or Won't v1 |
| Web SBOM export | UC3 | Sprint W2–W3 or Week 10 |
| Per-IP rate limiting | UC1, UC4 | Week 10 / infra |
| Frozen Express fork documented | UC1, eval | Sprint W1 |

---

## Owners (fill in names)

| UC | Suggested owner role |
|----|----------------------|
| UC1, UC4 | Engine / backend lead |
| UC2 | GitHub integration + demo repo |
| UC3 | Compliance narrative + SBOM export |
| UC5, UC6 | Frontend + AI explanations |
| UC7 | Vulnerability lens lead (optional) |
| Eval (Week 11) | Presentation / eval lead |
