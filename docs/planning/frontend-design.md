# Frontend Design — Arguss Dashboard

**Status:** Design, pre-implementation
**Owner:** Sherbano Khan (frontend), Adrian Rosales (API)
**Date:** May 2026, Week 8

## Purpose

This document captures the design plan for the Arguss web dashboard — the surface users see when they visit the hosted service. It is the consumer of the three scan endpoints documented in [`web-service-architecture.md`](web-service-architecture.md) and the realization of the pivot away from a GitHub App described in [`web-ui-pivot-rationale.md`](web-ui-pivot-rationale.md).

The frontend is being pulled forward from the original Week 9 plan into Week 8, alongside the demo polish work. This is feasible because the four Mode A PRs shipped in this cycle (crawl, blob fallback, v2 parser, OSV chunking) gave us a complete demo dataset served from a single HTTP endpoint.

## Scope

In scope: a dashboard UI that lets a user submit a scan via one of the three input modes, displays results in a way that supports a live 10-minute demo, and renders both auto-merge and review-required outcomes with clear visual hierarchy.

Out of scope (filed as Week 10+ or later):

- User accounts, authentication, or saved scan history
- Multi-tenancy / per-user isolation beyond per-session
- Webhook flows or continuous monitoring
- Mobile-responsive design (Zoom demo only)
- Internationalization
- An admin/configuration interface

## Tech stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Templates | Jinja2 | Already in deps; server-rendered HTML is sufficient |
| Interactivity | HTMX | Scan submission + results swap; no SPA needed |
| Styling | Tailwind CSS via CDN | No build step; keeps engineering effort on the engine |
| Scripts | Vanilla JS | Only where HTMX isn't enough (file upload UX, package search) |
| Backend | Existing FastAPI app | New HTML routes added to `arguss/api.py` or `arguss/web/routes.py`; reuses the three scan endpoints |

No frontend framework dependencies (no React, Vue, Alpine, build step, bundler). The 5W1H's discipline: engineering effort concentrated on the engine and lenses, not a custom SPA.

## Information architecture

The challenge: scans return up to ~200 findings. The naive "render every entry" approach overwhelms the viewer.

Layered disclosure, from broadest to most specific:

### 1. Summary banner

Pinned to the top of the results view. The first thing a viewer sees.

`177 findings · 90 auto-merge · 83 review · 4 skipped`

Big numbers, distinct visual treatment, immediate status read. Sourced from the response's `summary` object.

### 2. Tier filter tabs

Below the summary:

`[All]` `[Auto-merge 90]` `[Review 83]` `[Skipped 4]`

Filters the visible set of grouped rows. Helps the viewer focus on the verdict tier they care about.

### 3. Grouped by package

Collapses 173 individual entries to ~30 package rows. Each row shows:

- Package name (e.g. `semver`, `tar`, `minimatch`)
- Finding count for that package
- Severity range (low → critical)
- Summary tier — `auto_merge`, `review_required`, or `mixed` if entries differ within the package

Sort options: by finding count (default), by severity, by package name.

### 4. Expanded per-finding cards

Click a package row → expand to show individual findings. Each card displays:

- Version delta (`5.7.1 → 7.5.2`)
- Score (0–100, lower = riskier)
- Tier badge (green AUTO_MERGE / amber REVIEW_REQUIRED / red DECLINE)
- Veto signals as colored chips (`pipeline.test_reality`, `trust.new_maintainer`, etc.)
- Reasons as bullets (the human-readable `verdict.reasons`)
- Claude-generated explanation, when present
- OSV advisory link (`finding.source_url`)
- Transitive path: `root → express → semver` (from `finding.dependency.path`)

### 5. Search by package name (optional)

Useful during a live demo when expanding a specific package quickly matters.

## Input modes

All four input surfaces feed the same results view:

| Mode | Form | Action |
|------|------|--------|
| A | URL field + optional `ref` field | Hit `POST /scan/url`, render results |
| B | File picker / drag-drop for lockfile + optional workflows zip + optional package.json | Hit `POST /scan/upload`, render results |
| C | URL + `ref` + PAT field with explicit consent UX | Hit `POST /scan/with-action`, render results including the actions section |

Mode C requires extra care: the user is granting credentials and authorizing changes. The consent UX should clearly state what Arguss will do (open PRs only for AUTO_MERGE candidates, never merge, never act outside the envelope) and explicitly call out that the PAT is session-only.

## Demo-driven design

The dashboard's information architecture is shaped by the 10-minute live demo flow:

1. **Open** — scan axios v1.0.0 live. ~3 seconds. Summary banner shows 177 findings.
2. **Auto-merge story** — expand `minimatch` (15 findings, all auto-merge, score 75) or `qs` (8 findings, clean trust). Show what the agent green-lights.
3. **Trust-signal save (climax)** — expand `semver` (18 findings, scores 45–60, ownership transferred + new maintainer). Drop the line: *"Dependabot would have merged this. Arguss didn't, and here's why."*
4. **Major-version escalation** — expand `tar` (multi-veto including `fix_kind.major`). Show what the agent escalates for compound reasons.
5. **Mode C** — pre-recorded 60-second clip embedded in the dashboard or shown beside it.
6. **Close** — SBOM artifact, scope discipline.

The package grouping in particular makes the "expand this one" demo gesture natural. The veto signal chips make the "see why" moment visual without requiring narration.

## Loading states

Mode A scans take roughly 2–4 seconds end-to-end (mostly OSV calls). Mode B is faster (no network for the lockfile). Mode C is slowest because of the PR creation and CI wait.

Without a loading state, viewers see a frozen UI for several seconds and assume something is broken. Required:

- Submit button enters a disabled state with a spinner
- A progress message rotates through lens stages: "Fetching repository... Analyzing dependencies... Checking trust signals... Evaluating fixes..." (cosmetic; the real work is one synchronous request)
- After ~10 seconds with no response, surface a friendly "this is taking longer than usual" message — but do not auto-cancel

If the request fails (4xx/5xx from the server), surface the error message from the response body, not a generic "something went wrong." The endpoints return informative detail strings.

## Response shape contract

The endpoints return JSON with this top-level shape:

```json
{
  "summary": {
    "total_findings": <int>,
    "total_candidates": <int>,
    "auto_merge_count": <int>,
    "review_required_count": <int>,
    "decline_count": <int>
  },
  "entries": [
    {
      "finding": { ... },
      "candidate": { ... },
      "verdict": { ... }
    }
  ],
  "skipped_findings": [
    "GHSA-...",
    { "reason": "osv_unavailable", "detail": "...", "lens": "vulnerability" }
  ]
}
```

`skipped_findings` is heterogeneous on purpose:

- **Strings** are advisory IDs for findings where OSV has no fix version available
- **Objects** are structured `ScanSkip` entries for lens-level failures (e.g., OSV unavailable)

The UI should handle both types. Strings render as small reference badges; objects render as warning banners since they indicate the scan was incomplete.

Full schema available at `/docs` and `/redoc` when the server is running.

## Open questions

Decisions Sherbano will need to make during the build:

1. **Single page or multi-page?** Likely single page with input form at top, results below, both visible. But a two-screen flow (input → results) is also defensible.
2. **How to surface the demo target.** A "Try the axios v1.0.0 example" button on the input form would make the demo flow smoother. Or a small "Example URLs" link with a few options.
3. **Mode C consent UX.** Where does the explicit consent live? Inline form text, modal before submission, separate confirmation step?
4. **Empty states.** What does the dashboard show before the first scan? What does a successful scan with zero findings look like? What does a scan with a populated `skipped_findings` warning look like?
5. **Color system.** Tailwind defaults work, but the verdict tiers need consistent visual treatment. Probably green/amber/red, but the specific palette is open.

## References

- [`web-service-architecture.md`](web-service-architecture.md) — backend architecture
- [`web-ui-pivot-rationale.md`](web-ui-pivot-rationale.md) — why we moved to a web UI from a GitHub App
- [`fix-confidence-engine.md`](fix-confidence-engine.md) — how verdicts are computed (informs what the UI displays)
- [`explanation-design.md`](explanation-design.md) — Claude-generated explanation flow
- Project overview: [`project-overview-v2.md`](project-overview-v2.md)
