# Arguss Backlog

Central tracking document for items deferred from the redesign series, the capstone work, and post-showcase scope. Each entry includes a status, rough effort estimate, description, and trigger for when to pick it up.

**Last updated:** July 2, 2026 (moved Scorecard hygiene section and per-finding Claude explanation to Resolved; previously June 17, 2026 — 6 items from full project review)

---

## Categories

- **Pre-showcase capstone deliverables** — overdue or pending syllabus work that gates the August 5 showcase grade
- **Engineering backlog** — features that could ship pre-showcase if time allows
- **Post-showcase / v2** — explicitly out of capstone scope; for production / v2
- **Tech debt** — small fixes, deprecation warnings, code quality
- **Blocked** — waiting on external dependencies or decisions

---

## Pre-showcase capstone deliverables (overdue / pending)

These are graded deliverables on the syllabus. **Engineering is ahead of schedule, but writing is behind.** These are higher priority than any engineering backlog item.

### Evaluation harness (Week 11)
**Filed: June 17, 2026 — project review; replaces the sparse original entry**

- **Status**: Not started
- **Effort**: ~6-8 hours
- **Why this is the most important missing piece**: The fix-confidence engine is sound in theory, but without the evaluation every claim is unsubstantiated. When the showcase panel asks "how do you know AUTO_MERGE is safe?" or "how do you compare against Dependabot?" — the answer right now is theoretical. The evaluation turns theory into evidence.

**Sub-task 1 — Trust-delta on real known attacks (works today, zero new code)**

Run the existing engine against packages from confirmed supply chain attacks. The npm packument still records historical maintainer structure:

- `arguss trust-delta event-stream 3.3.4 3.3.6` — event-stream@3.3.6 was published by `right9operator` who took ownership from `dominictarr` (November 2018 attack). Engine should return: `ownership_transferred: True`, `new_maintainer: right9operator`, `safe_to_auto_merge: False`.
- `arguss trust-delta ua-parser-js 0.7.28 0.7.29` — account hijacking attack (October 2021). Should show new maintainer signal.

Screenshot these outputs. They are the proof-of-thesis. Dependabot would have merged both; Arguss blocks both. This is the killer demo moment and it takes 10 minutes to produce with existing code.

**Sub-task 2 — Three demo scenarios on frozen Express fork**

Reproduce all three scenarios with actual engine output:
1. **Scenario A (hero case)**: Express fork with real patch-level CVEs → show AUTO_MERGE with high score and reasoning.
2. **Scenario B (major-version block)**: An upgrade that requires a major version bump → show REVIEW_REQUIRED with `fix_kind.major` veto signal and explanation.
3. **Scenario C (trust-signal save)**: A patch-level fix where the package had a maintainer change in the upgrade window → show REVIEW_REQUIRED with `trust.new_maintainer` or `trust.ownership_transferred` even though the semver delta is small.

Record tier counts and scores. These become the numbers cited in the presentation.

**Sub-task 3 — Comparison table**

For each candidate the engine evaluated, build a table showing:
| Package | Dependabot would | Snyk would | Arguss verdict | Why Arguss differs |
|---------|------------------|------------|----------------|-------------------|

For the trust-signal scenarios, the table is the entire argument: Dependabot AUTO_MERGE, Snyk silent (no CVE yet), Arguss REVIEW_REQUIRED. Include this table in the evaluation section of the project webpage and in the final presentation.

**Sub-task 4 — Confidence weight tuning**

After running scenarios, check whether the `_SCORE_REDUCTION` weights in `fix_confidence.py` produce calibrated scores (when score=90, are those fixes empirically safe?). Adjust if needed before the showcase.

- **Trigger**: Week 11. This is the academic spine of the capstone — ship everything else first so Week 11 can focus entirely on this.

### Final Project Webpage (Week 12)
- **Status**: Not started
- **Effort**: ~4-6 hours
- **Description**: Public-facing site with architecture diagram, threat model summary, screenshots, and demo video. Requires unscoping the current HTTP Basic auth so the public can access it for the showcase. Threat model summary asset now unblocked (revision submitted).
- **Trigger**: Week 12.

### Demo backup video
- **Status**: Not started
- **Effort**: ~2-3 hours (recording + editing)
- **Description**: Pre-recorded 10-minute demo as fallback if live demo fails. Should also be embedded on the Project Webpage.
- **Trigger**: Week 12-13.

### 2-minute pitch
- **Status**: Not started
- **Effort**: ~1-2 hours
- **Trigger**: Week 11.

### Joint final presentation (Week 14)
- **Status**: Aug 5, 2026
- **Trigger**: Week 14. Dry run in Week 13.

---

## Engineering backlog

Features that could ship pre-showcase if time allows, but aren't required for the demo.

### Transitive remediation v1
**Filed: May 28, 2026 — design doc: `transitive-remediation-design.md`**

- **Status**: Design captured, no code
- **Effort**: ~6-9 hours (multi-path awareness with one primary execution path)
- **Description**: How Arguss handles transitive vulnerabilities where the fix isn't a simple direct-dep upgrade. Three paths: parent upgrade, npm overrides, skip.
- **Trigger to pick up**: After PR 6 lands. v1 could ship pre-showcase for a strong demo moment.

### Transitive remediation v2
- **Status**: Design captured (in same doc)
- **Effort**: ~2-3 days
- **Description**: Full multi-path decision-making — user explicitly selects which path to execute per finding.
- **Trigger to pick up**: Post-showcase.

---

### Mode B lockfile v1 full parser support
**Filed: May 28, 2026 — design doc: `mode-b-lockfile-version-limitation.md`**

- **Status**: Better UX (Option 2+3 from the triage doc) addressed in PR 6. Full parser extension remains backlog.
- **Effort**: ~4-6 hours
- **Description**: Arguss currently only supports lockfileVersion 2 and 3. v1 lockfiles (npm 5-6 era) get a verbose error (now styled in PR 6, but still rejected). Full support would require a v1-specific parser code path.
- **Trigger to pick up**: Post-showcase if real users hit this. Lower priority than other items.

---

### Chat history persistence on reload
- **Status**: Not implemented (intentionally deferred per PR 5 review)
- **Effort**: Server-side session storage ~2h; client-side sessionStorage ~30min
- **Description**: Currently chat history clears on page refresh. Matches Claude.ai and ChatGPT-anonymous patterns.
- **Trigger to pick up**: If showcase demo flow benefits from persistence. Otherwise leave as-is.
---

### CLI verbose scan-stage messages
- **Status**: Implemented in PR 5 dashboard. CLI may benefit from similar UX during long scans.
- **Effort**: ~1 hour
- **Trigger to pick up**: Low priority. Pick up if working on CLI ergonomics.

---

### CLI URL-to-clone auto-handling
**Filed: May 28, 2026 — from PR 6.1 manual QA**

- **Status**: Not implemented; CLI `arguss scan` expects a local path only
- **Effort**: ~1-2 hours
- **Description**: Dashboard Mode A accepts a GitHub URL and clones it server-side. CLI requires the user to clone manually first. Adding URL detection + auto-clone to the CLI would close the parity gap. Detect URLs by `://` or `git@` prefix, clone to a tmp dir, scan that path, clean up after.
- **Why filed**: Surfaced during PR 6.1 verification — passing a URL to `arguss scan` produces the misleading "Path does not exist" error. Dev-only workflow but bad first impression.
- **Trigger to pick up**: Low priority. Pick up when working on CLI ergonomics or before any external developer demo.

---

### Dual trust subscores (actionable + overall) — needs architectural rethink
**Filed: May 28, 2026 — first attempt reverted due to perf**

- **Status**: First attempt reverted. Requires different architecture.
- **Effort**: Original estimate ~2-2.5h was too low — actual scope includes API cost / latency design work
- **Description**: Display two trust subscores side-by-side: actionable (direct deps only, drives PRS) and overall (all lockfile deps including transitives, contextual). Strong differentiator for the showcase narrative.

**Architecture problem from first attempt:**

The naïve implementation fetched per-package trust snapshots for **every transitive dependency** in the lockfile. For axios (~178 deps), that's ~178 npm registry calls per scan. Mode A URL scans took 1-3+ minutes and appeared hung. Caching helps on subsequent scans but cold cache (first scan, showcase demo) is unusable.

**Cheaper alternatives to consider:**

1. **Sample transitives** — fetch trust snapshots for direct deps + the top-N transitives (e.g. by package count weight or by being in the dependency path of multiple direct deps). Lose some accuracy on "overall" but feasible at scan time.

2. **Background pre-computation** — first scan shows actionable only with a "computing overall trust..." indicator; overall populates asynchronously. Requires async/background job infrastructure.

3. **Cheap proxy metric instead of full snapshot** — instead of full TrustSnapshot (which requires maintainer/cadence/typosquat/downloads), use a simpler indicator like "X transitives have signals in our top-1000 typosquat list" or just count of deps. Context, not a true score.

4. **Two-tier UX** — show "Actionable trust: 32" prominently, plus "+178 transitives not deeply analyzed" as context text. Doesn't require new computation. Honest about what we can and can't tell cheaply.

**Recommended approach (if/when picked up):**

Option 4 — the two-tier UX — is the cheapest honest solution. Shows context without claiming we've evaluated trust for transitives. The framing becomes: *"We've deeply analyzed the 56 direct deps you can act on. Your project also pulls in 122 transitives we haven't trust-scored — those are out of your direct control anyway."*

- **Trigger to pick up**: Post-showcase. The architecture problem makes pre-showcase shipping risky. Showcase demo can use the existing single-trust-score approach with verbal framing around "this is the actionable risk."

---

### Trust aggregation deduplication
**Filed: May 28, 2026 — surfaced during Scorecard PR verification (axios v1.0.0 scan)**

- **Status**: Open
- **Effort**: ~30-60 minutes
- **Description**: The top-10 list in the Trust breakdown panel can contain duplicate (package, version) entries. Surfaced on the axios v1.0.0 scan where `get-stream@5.2.0` appeared twice with identical subscore and Scorecard data. The duplication also affects the "Mean of top 10 snapshot subscores" calculation, making the project subscore slightly inaccurate. Likely root cause is in the aggregation that builds `direct_trust_packages` — either the dependency graph yields the same direct dep twice (transitive that's also direct), or the iteration is keyed by something other than (name, version) and the sort+truncate happens on a list with dupes.
- **Fix**: Dedupe by (name, version) before truncating to top 10, keeping the highest-risk occurrence. Add a regression test scanning a fixture with a known-duplicating dependency graph.
- **Where to look**: `arguss/lenses/trust.py` (likely `aggregate_trust_subscores` or whoever builds the sorted list); `arguss/web/results_context.py` for the `lens_explain.trust.packages` path; possibly `arguss/engine/propose.py` for `direct_trust_packages` assembly.
- **Trigger to pick up**: Any pass through `trust.py` or trust-aggregation code. Cosmetic/visual, not blocking the demo — the duplicate is honest data (the package really is at that risk), just rendered twice.
---


### npm Provenance Attestation in trust lens — fourth trust signal
**Filed: June 17, 2026 — project review**

- **Status**: Not started
- **Effort**: ~4 hours
- **Description**: npm provenance (introduced 2023) is SLSA Level 2 — the build environment is verifiably linked to a public source repository. Most security tools don't surface this at the per-upgrade decision level yet. Adding it to `fetch_snapshot` is a single API call:
  ```
  GET https://registry.npmjs.org/-/npm/v1/attestations/{package}@{version}
  → 200 with attestation bundle if provenance exists
  → 404 if not
  ```
  A package WITH provenance gets a trust bonus in `_compute_subscore` (suggested: −15 from the subscore — provenance means a verifiable build chain). A package that HAD provenance in `from_version` but LOST it in `to_version` is a meaningful red flag and should be a veto signal.

  Add `provenance_verified: bool | None` to `TrustSnapshot` and surface it as a chip in the trust breakdown tile. Include it in `TrustDelta` so the fix-confidence engine can see if provenance was dropped across the upgrade window.

- **Why this is above and beyond**: Provenance is a genuine 2023+ supply chain hardening signal that neither Snyk nor Dependabot expose at the per-upgrade decision level. It directly extends the trust model with a new veto axis, and you can cite the npm + SLSA specs as academic grounding.
- **Honesty constraint**: Provenance absence is NOT a veto on its own — the majority of npm packages predate provenance and don't have it. Only provenance loss (had it, then doesn't) is a red flag.
- **Where to add**: `arguss/lenses/_trust_client.py` (new `fetch_provenance` function), `arguss/lenses/trust.py` (`fetch_snapshot` and `fetch_delta`), `arguss/core/models.py` (`TrustSnapshot`, `TrustDelta`).
- **Trigger to pick up**: Any engineering sprint with 4 available hours. High showcase impact relative to effort.

---

### Policy-as-code — `.arguss/policy.yml`
**Filed: June 17, 2026 — project review**

- **Status**: Not started
- **Effort**: ~6 hours
- **Description**: Right now the auto-merge envelope is hardcoded in `fix_confidence.py`. Teams with different risk tolerances can't customize it. A simple YAML policy file transforms Arguss from a tool with hardcoded rules into a framework with a configurable, auditable policy:
  ```yaml
  # .arguss/policy.yml
  auto_merge:
    allow_minor: true
    allow_major: false
  trust:
    block_on_new_maintainer: true
    block_on_ownership_transfer: true
    cadence_anomaly_threshold_ratio: 0.3
    block_on_provenance_loss: true
  pipeline:
    require_ci: true
    require_test_files: true
  ```
  `compute_fix_confidence` reads this file (from the repo root or from a path flag), merges with defaults, and applies the policy. The policy file itself becomes part of the audit trail — any verdict can be reconstructed by replaying the policy in effect at evaluation time.

- **Why this is above and beyond**: Renovate has config, but it's version-availability only. Policy-as-code for a risk-model-backed autonomous agent is a genuinely different framing. It also directly enables the evaluation: pin the policy file so all scenarios use identical thresholds, making results reproducible and citable.
- **Where to add**: New `arguss/engine/policy.py` that loads and validates the YAML; `compute_fix_confidence` accepts an optional `Policy` object; CLI flags `--policy-file` and `--no-policy`.
- **Trigger to pick up**: After evaluation sub-tasks are complete — you want the policy file to be part of the evaluation methodology. Pre-showcase is ideal.

---

### Complete the remediation ranker stub
**Filed: June 17, 2026 — project review**

- **Status**: Stub returns empty list
- **Effort**: ~3 hours
- **Location**: `arguss/scoring/unified.py`, `_rank_remediations()` (line ~135); the Week 6 comment reads "Real ranker lands Week 6."
- **Description**: `_rank_remediations` currently returns `[]`. The function is called in `compute_project_score` but its output (`top_remediations` on `ProjectScore`) is never populated. The ranker should order candidates by `score_reduction × fix_confidence_score` — fixes that eliminate the most risk AND the engine is most confident about go first. This produces the "do these 5 things first" to-do list that is the main value proposition of an autonomous remediation agent.

  Inputs already available at call time: the three `LensScore` objects (with all findings and scores). The ranker needs to: find all findings with a fixed version available, compute the per-finding score contribution to PRS, rank by contribution × confidence, return as `list[Remediation]`.

- **Why this matters**: Right now results show findings flat. A ranked remediation plan is the difference between "here is your scan" and "here is your action plan." The top-5 remediations section in the results UI is wired to receive this output — it's just never populated.
- **Where to add**: `arguss/scoring/unified.py` (`_rank_remediations`); `arguss/web/results_context.py` may need a new section builder for the ranked plan panel.
- **Trigger to pick up**: Pair with the evaluation — you want the ranker live so you can show the full end-to-end flow in the showcase demo.

---

### "What would Dependabot have done?" comparison panel in results UI
**Filed: June 17, 2026 — project review**

- **Status**: Not started
- **Effort**: ~4 hours
- **Description**: For each fix candidate in the results page, add a comparison row or badge showing what a version-only auto-merge tool (Dependabot) would have done:
  - **Dependabot verdict**: AUTO_MERGE — newer version with a fix exists
  - **Arguss verdict**: REVIEW_REQUIRED — trust.ownership_transferred

  The inference is simple: if a fixed version exists, Dependabot would have auto-merged it. No integration with the actual Dependabot API needed — this is a deterministic inference. The comparison makes the value proposition visible without requiring the user to know anything about Dependabot.

  For the trust-signal-save scenario (Scenario C in the evaluation), this comparison is the entire argument. Surface it prominently: a callout at the top of the results page reading "Dependabot would have auto-merged N of these candidates. Arguss flagged M for human review due to trust or pipeline signals." The M number is the thesis made concrete.

- **Where to add**: `arguss/web/results_context.py` (add `dependabot_would_merge: bool` to the per-candidate context); `results.html` / `partials/_finding_card.html` to render the comparison badge.
- **Trigger to pick up**: After evaluation sub-tasks complete, so the comparison uses real numbers. High demo impact.

---

### Dependency graph visualization with risk coloring
**Filed: June 17, 2026 — project review**

- **Status**: Partially built — `arguss/web/graph_data.py` already generates Cytoscape.js node/edge data; the visualization is not wired to the results page
- **Effort**: ~4 hours (connect existing data to template + add risk-color logic)
- **Description**: Wire the existing `graph_data.py` output to a Cytoscape.js panel in `results.html`, with node color encoding risk:
  - **Red**: packages with active CVEs
  - **Orange**: packages with trust flags (ownership transfer, new maintainer, etc.)
  - **Yellow**: packages with pipeline/zizmor findings
  - **Green**: clean packages
  - **Node size** or **edge thickness**: how many other packages depend on this one (blast radius proxy — already computable from the lockfile graph)

  The graph turns the dependency tree into a visual argument for why the scan found what it found. For the Express fork demo, the colored nodes make the risk surface immediately obvious.

- **Where to add**: `arguss/web/results_context.py` (pass graph data with risk annotations to template context); `results.html` (add Cytoscape.js panel, probably collapsible); `arguss/web/static/js/` (small Cytoscape.js initializer).
- **Honesty constraint**: Show only what the engine actually evaluated. Don't color-code nodes for risks the engine didn't assess.
- **Trigger to pick up**: After the evaluation, so the graph can be demoed against the frozen Express fork with real scan data. Visually the strongest single addition for a showcase.

---

### "Dependabot would have merged X" narrative callout in results UI
**Filed: June 17, 2026 — project review**

- **Status**: Not started
- **Effort**: ~2 hours
- **Description**: Add a prominent callout at the top of the results page (above the lens tiles) that converts the scan result into a direct value-proposition statement:

  > "Dependabot would have auto-merged **5** of these candidates. Arguss flagged **2** for human review — one due to a new maintainer added during the upgrade window, one due to a major version bump."

  The numbers come from data already computed: total candidates with a fixed version (= what Dependabot would auto-merge), minus Arguss AUTO_MERGE count = how many Arguss caught that Dependabot would have missed. The reason text comes from the top veto signals on the REVIEW_REQUIRED candidates.

  This single sentence is the entire thesis of the project made concrete for a non-technical evaluator. It should appear on every scan result, not just in evaluation materials.

- **Where to add**: `arguss/web/results_context.py` (compute the callout data from `ProposalReport`); `results.html` (prominent callout card above the lens tiles, maybe with a subtle warning color).
- **Trigger to pick up**: Low effort, very high showcase narrative value. Pick up in any UI sprint.

---

### Degraded-scan banner for significant OSV skips
**Filed: May 28, 2026 — from PR 6 review**

- **Status**: Not implemented; OSV failures currently surface only as per-finding `ScanSkip` warning badges in the skipped_findings section
- **Effort**: ~1-2 hours
- **Description**: When OSV.dev is fully down or significantly degraded (e.g. >50% of batch queries failed, or zero findings returned for a scan that should have hundreds), show a banner at the top of the results page noting the scan completed with partial data. Different from per-finding skip badges — communicates that the OVERALL scan is degraded.
- **Why filed**: The web layer currently doesn't render a network error card for OSV failures because the scan still completes (just with incomplete data). That's correct behavior, but if a showcase audience hits a moment where OSV is down, the scan might look thin without any acknowledgment of why.
- **Trigger to pick up**: Pre-showcase if OSV reliability becomes a concern. Otherwise post-showcase. Low priority since current behavior is honest (no fake findings) just non-attention-grabbing.

---

## Post-showcase / v2

Items explicitly out of capstone scope. Production / v2 considerations.

### Split `results_context.py` into a service layer and thin context builders
**Filed: June 17, 2026 — code review pass on main**

- **Status**: Open
- **Effort**: 1–2 days
- **Location**: `arguss/web/results_context.py` (1,970 lines)
- **Description**: `results_context.py` is the largest file in the codebase and violates the web layer's separation from domain logic. It directly imports private-prefixed symbols from lens and scoring modules:
  ```python
  from arguss.lenses.pipeline import _PIPELINE_SUBSCORE_WEIGHTS, _SUBSCORE_CAP, _TEST_REALITY_PENALTY
  from arguss.lenses.vulnerability import _cvss_to_severity, _normalize_cvss_to_100
  from arguss.scoring.unified import DEFAULT_WEIGHTS
  ```
  The web layer should not reach into underscore-prefixed domain internals. The symptom is that any change to lens internals requires coordinated changes in the web layer, and the template context logic is entangled with scoring math.
- **Fix approach**:
  1. Make the private lens helpers public (remove leading underscore, export them from the lens module's public API).
  2. Extract a `ResultsViewModel` dataclass that the scan engine produces — the web layer only receives this ViewModel, not raw scan dicts.
  3. Split the 1,970-line file into: `results_service.py` (builds ViewModel from cached scan payload), and per-section context builders (`vulnerability_context.py`, `trust_context.py`, `pipeline_context.py`).
- **Why post-showcase**: Large refactor, high test surface, risk of regressions. Not blocking any feature.
- **Trigger**: Post-showcase when doing a planned architecture pass.

---

### Split `dashboard.py` by handler surface
**Filed: June 17, 2026 — code review pass on main**

- **Status**: Open
- **Effort**: Half day
- **Location**: `arguss/web/dashboard.py` (1,118 lines)
- **Description**: The dashboard router contains HTMX handlers for scan, upload, action, chat, streaming, and candidate selection — all unrelated surfaces crammed into one file. The file exceeds the project's own 800-line ceiling for module size.
- **Fix**: Split into focused router modules registered on the same FastAPI app:
  - `arguss/web/handlers/scan_handlers.py` — Mode A scan form handler
  - `arguss/web/handlers/upload_handlers.py` — Mode B upload form handler
  - `arguss/web/handlers/action_handlers.py` — Mode C action + streaming handlers
  - `arguss/web/handlers/chat_handlers.py` — chat panel HTMX endpoint
- **Why post-showcase**: Mechanical refactor, no logic changes, but high test surface. All existing tests should pass unchanged.
- **Trigger**: Post-showcase during any planned cleanup pass.

---

### PDF report export
- **Status**: Placeholder button exists from PR 4.1 ("Coming soon")
- **Effort**: ~2-3 hours
- **Description**: Frequently-requested for compliance contexts.

### Auto-merge user-selection checkboxes
- **Status**: Not implemented
- **Effort**: Significant — changes Mode C flow
- **Description**: Currently Mode C either acts on all AUTO_MERGE candidates or none. User checkbox selection would let user choose specific candidates to action.

### Persistent storage of scan decisions for replay
- **Status**: Planned Week 10 enrichment
- **Effort**: ~3-4 hours
- **Description**: Per-scan history so users can see decisions over time.

### Reliability hardening
- **Status**: Planned Week 10
- **Effort**: ~2-3 hours
- **Description**: Single-flight per repo (deduplicate concurrent scans of the same project), retry safety on Mode C action layer.

### Multi-ecosystem support
- **Status**: Out of scope per 5W1H
- **Effort**: Significant per ecosystem
- **Description**: PyPI, Maven, Cargo, etc. npm is the v1 target.

### Multi-CI/CD platform support
- **Status**: Out of scope per 5W1H
- **Effort**: Significant per platform
- **Description**: GitLab CI, CircleCI, Jenkins, etc. GitHub Actions is the v1 target.

---

## Tech debt

Small cleanup items that don't block anything but accumulate.

### Remove Tailwind Play CDN from base.html
**Filed: June 17, 2026 — code review pass on main**

- **Status**: Open
- **Effort**: 30 seconds (delete one line)
- **Location**: `arguss/web/templates/base.html` line 12
- **Description**: `<script src="https://cdn.tailwindcss.com"></script>` is loaded on every page but zero Tailwind utility classes are used anywhere in the template tree. This is the Tailwind **Play CDN** — Tailwind's own docs explicitly say "do not use the Play CDN in production." It injects a ~3MB JS runtime that generates CSS on demand, and its bundled Preflight CSS reset conflicts with `base.css`'s own resets. Confirmed by grepping all templates: no `.flex`, `.grid`, `.text-*`, `.bg-*`, or any Tailwind class anywhere outside `base.html` itself.
- **Fix**: Delete line 12 of `base.html`. Run the app and verify no visual regressions — there won't be any because the CDN contributes nothing.
- **Trigger**: Smallest possible PR. Do this before any public demo.

---

### Fix font scale from `px` to `rem` in tokens.css
**Filed: June 17, 2026 — code review pass on main**

- **Status**: Open
- **Effort**: 15 minutes
- **Location**: `arguss/web/static/css/tokens.css` lines 37–46
- **Description**: All typography tokens are defined in `px` (e.g. `--text-xs: 12px`, `--text-sm: 14px`). `px` values are absolute — they ignore the user's browser font size preference. Users who increase their browser's default font size (a common accessibility accommodation) will still see 12px text. Converting to `rem` makes all sizes relative to the browser root so user preferences are respected.
- **Conversion table** (at 16px base):
  ```
  --text-xs: 12px   → 0.75rem
  --text-sm: 14px   → 0.875rem
  --text-base: 16px → 1rem
  --text-lg: 18px   → 1.125rem
  --text-xl: 20px   → 1.25rem
  --text-2xl: 24px  → 1.5rem
  --text-3xl: 32px  → 2rem
  --text-4xl: 40px  → 2.5rem
  --text-5xl: 56px  → 3.5rem
  --text-hero: 72px → 4.5rem
  ```
- **Note**: Space tokens (`--space-*`) and fixed small sizes used for decorative dots/borders can stay as `px`. `rem` matters for text.
- **Trigger**: Fold into any small-PR touching `tokens.css` or alongside the Tailwind CDN removal.

---

### Fix "vs section" 3-column grid — missing mobile breakpoint
**Filed: June 17, 2026 — code review pass on main**

- **Status**: Open
- **Effort**: 5 minutes
- **Location**: `arguss/web/templates/index.html` ~line 864 ("What makes Arguss different" section)
- **Description**: The three contrast cards (vs. Snyk / vs. Dependabot / vs. Manual review) use an inline `style="display:grid;grid-template-columns:repeat(3,1fr);gap:var(--space-5);"` with no responsive override. At 375px, three equal columns gives ~110px per card — too cramped for the two-paragraph content in each card. The redesign (PR #154) added responsive breakpoints for the Observatory panel, stats grid, and feature panels but missed this section.
- **Fix**: Add a class to the wrapper div (e.g. `contrast-card-grid`) and add to the index page `<style>` block alongside the existing `@media (max-width: 840px)` rules:
  ```css
  @media (max-width: 640px) {
    .contrast-card-grid { grid-template-columns: 1fr; }
  }
  ```
- **Trigger**: Fold into any index page touch. Very low risk.

---

### Fix CTA URL input — missing form semantics
**Filed: June 17, 2026 — code review pass on main**

- **Status**: Open
- **Effort**: 30 minutes
- **Location**: `arguss/web/templates/index.html`, bottom CTA section (`home-cta__input-row`)
- **Description**: The "Scan your first repo" CTA has a `<input type="text">` and an `<a>` tag button that are not wrapped in a `<form>`. Three problems:
  1. **Screen readers cannot associate the input with the button** — the submit relationship is invisible to assistive tech.
  2. **`type="text"` instead of `type="url"`** — mobile browsers will not show the URL keyboard (with `.com` shortcut).
  3. **No-JS fallback is broken** — if JS fails, clicking "Scan →" navigates to `/scan` with no URL prefilled; the typed input is silently discarded.
- **Fix**: Wrap in a `<form>` and progressively enhance the URL normalization in JS:
  ```html
  <form class="home-cta__input-row" action="/scan" method="GET" id="cta-form">
    <input class="home-cta__input" type="url" name="url"
           id="cta-repo-input"
           placeholder="github.com/your-org/your-repo"
           autocomplete="url" />
    <button type="submit" class="btn btn-on-dark"
            style="padding:var(--space-3) var(--space-5);white-space:nowrap;">
      Scan →
    </button>
  </form>
  ```
  In JS, intercept `form.addEventListener('submit', e => { e.preventDefault(); ... })` and run the existing `normalizeGithubUrl()` logic before redirecting. No-JS path: the GET form submits `?url=...` which the `/scan` route already handles via `prefill_url`.
- **Trigger**: Fold into any landing page polish PR.

---

### Replace fake social proof trust bar with honest attribution
**Filed: June 17, 2026 — code review pass on main**

- **Status**: Open
- **Effort**: 30 minutes
- **Location**: `arguss/web/templates/index.html`, `home-trust` section (~line 646)
- **Description**: The scrolling trust bar reads "Securing repos across teams at" followed by a JS-generated marquee of company names: Vercel, Stripe, Supabase, PlanetScale, Hashicorp, Netlify, Render, Fly.io, Railway, Turso, Neon, Resend, Upstash, Clerk, Convex. These companies have not consented to being listed, and Arguss is not deployed at any of them. This is a fabricated social proof pattern — precisely the kind called out as banned in this project's own design-quality standards. For a tool whose pitch is about trust and safety, listing fake partner logos is self-defeating.
- **Options**:
  1. **Remove it entirely.** The Observatory panel directly above already provides real social proof via live scan data.
  2. **Replace with honest attribution**: change to "Scanning the Alpha-Omega ecosystem" with a stat strip showing total projects scanned, critical findings found, and auto-fix candidates — data already available from the Observatory query that backs the hero panel.
- **Trigger**: Before any public or showcase demo. Credibility issue, not just a style issue.

---

### Deduplicate scan/upload page CSS
**Filed: June 17, 2026 — code review pass on main**

- **Status**: Open
- **Effort**: 1 hour
- **Location**: `<style>` blocks in `arguss/web/templates/scan.html` and `arguss/web/templates/upload.html`
- **Description**: The scan and upload page redesigns used near-identical CSS copy-pasted into per-template `<style>` blocks rather than extracted to `base.css`. Structurally identical class groups:
  - `.scan-guidance` / `.upload-guidance` — background, border, left accent, padding, radius
  - `.scan-guidance__title` / `.upload-guidance__title` — uppercase label
  - `.scan-guidance__body` / `.upload-guidance__body` — font-size, line-height
  - `.scan-header__eyebrow` / `.upload-header__eyebrow` — pill badge with dot
  - `.scan-card` / `.upload-card` — surface card with shadow
- **Fix**: Extract to shared classes in `base.css` (e.g. `.form-guidance`, `.form-guidance__title`, `.form-card`, `.form-eyebrow-badge`). Keep per-template `<style>` blocks only for truly page-specific layout (e.g. `.scan-page` centering flex). This prevents the pages from drifting when one is updated but the other isn't.
- **Trigger**: Any pass through scan or upload templates.

---

### Remove dead `data-target="0"` on the "$0" stat card
**Filed: June 17, 2026 — code review pass on main**

- **Status**: Open
- **Effort**: 2 minutes
- **Location**: `arguss/web/templates/index.html`, stats section — the "Cost to scan" card
- **Description**: `scroll-reveal.js` explicitly skips counter animation when `target === 0`. The `$0 — Cost to scan your first repo` card has `data-target="0"` on its `<span>` which means the attribute does nothing — no animation runs, the `0` is just static text. Dead markup.
- **Fix**: Remove the `data-target="0"` attribute from that `<span>`. The `0` text stays static.
- **Trigger**: Fold into any index page touch.

---

### Tokenize marketing-page hardcoded hex
- **Status**: Open
- **Description**: Tokenize marketing-page hardcoded hex once the redesign is fully landed and the palette is consolidated.
- **Trigger**: After redesign series fully on main and palette consolidated.

### `format_zizmor_breakdown_formula` omits finding counts — formula is misleading
**Filed: June 17, 2026 — lens/scoring review**

- **Status**: Open
- **Effort**: 5 minutes
- **Location**: `arguss/web/score_formulas.py`, `format_zizmor_breakdown_formula()`
- **Description**: The per-scan breakdown formula currently shows `severity×weight` (e.g., `medium×15 + high×30`) but the actual subscore computation is `count × weight` per severity. With 3 medium + 1 high findings, the formula renders as if it evaluates to 45 when the real score is 75. The breakdown table rows in `results_context.py` already show counts correctly (`f"{count} → {count * weight}"`); only the formula string is wrong.
- **Fix**: Change `f"{severity}×{_PIPELINE_SUBSCORE_WEIGHTS[severity]}"` to `f"{z_counts[severity]}×{_PIPELINE_SUBSCORE_WEIGHTS[severity]}"` in the list comprehension. The reference formula (`format_zizmor_reference_formula`) correctly stays as unit-cost-per-severity — that one is intentional.
- **Trigger**: Any touch to `score_formulas.py` or the pipeline breakdown tile.

---

### `_TRUST_LENS_TOP_N` is private-named but imported across three modules
**Filed: June 17, 2026 — lens/scoring review**

- **Status**: Open
- **Effort**: 5 minutes
- **Location**: `arguss/lenses/trust.py` line 35; also imported in `arguss/web/score_formulas.py` and `arguss/web/results_context.py`
- **Description**: The constant `_TRUST_LENS_TOP_N = 10` has a leading underscore (conventionally "private") but is directly imported by two other modules as part of their logic. Leading underscore signals to readers that the symbol is internal and safe to change without considering callers — but it isn't. Rename to `TRUST_LENS_TOP_N` (public) to match the existing `TRUST_SUBSCORE_WEIGHTS` pattern.
- **Fix**: Rename the constant in `trust.py` and update the two import sites.
- **Trigger**: Fold into any pass through `trust.py`.

---

### Duplicate `raw_summary` validity check in `_vuln_to_finding`
**Filed: June 17, 2026 — lens/scoring review**

- **Status**: Open
- **Effort**: 2 minutes
- **Location**: `arguss/lenses/vulnerability.py`, `_vuln_to_finding()` lines ~181–183 and ~195–198
- **Description**: The function computes `summary` from `raw_summary` (lines 181–183), then re-checks `isinstance(raw_summary, str) and raw_summary.strip()` a second time (lines 195–198) to build `title`. The second check re-does what `summary != "No summary provided"` already encodes. Minor but noisy.
- **Fix**: Replace the second `raw_summary` re-check with `if summary != "No summary provided": title = f"{vuln_id}: {summary}"`.
- **Trigger**: Any touch to `vulnerability.py`.

---

### HTTP_413 deprecation warning
- **Location**: `arguss/web/routes.py:356`
- **Fix**: Replace `HTTP_413_REQUEST_ENTITY_TOO_LARGE` with `HTTP_413_CONTENT_TOO_LARGE`
- **Effort**: 5 minutes
- **Trigger**: Fold into any small-PR opportunity.

### Three missing milestone tags
- **Items**: `milestone/redesign-pr1`, `milestone/redesign-pr3`, `milestone/redesign-pr4`
- **Description**: Backfill these on the appropriate merge commits for rollback parity with the other redesign milestones.
- **Effort**: 5 minutes
- **Trigger**: When checking out merge commits anyway.

---

## Blocked

Waiting on external dependencies or decisions.

### Mark-only logo SVG
- **Status**: Blocked on team supplying asset
- **Owner**: Sherbano
- **Description**: Current `arguss/web/static/arguss-logo.png` has the wordmark baked in (duplicates with nav text). Mark-only SVG enables:
  - Cleaner nav rendering
  - Spinning logo as a loading indicator (currently a generic spinner)
  - Crisper retina/print rendering
- **Trigger**: When asset arrives.

---

## Resolved (moved out of backlog)

For reference only. Items that were in this backlog and have since shipped.

### Milestone Report
- **Resolved**: June 17, 2026 — written and submitted
- **Description**: Capstone Milestone Report. Was originally due May 27, 2026.

### Threat model revision (Modes B + C)
- **Resolved**: June 17, 2026 — written and submitted
- **Description**: Revision of the original Week 6 threat model to cover the web-service pivot (Mode B file upload, Mode C URL + PAT). Unblocks the threat model summary asset for the Final Project Webpage.

### Solution Design Presentation
- **Resolved**: June 17, 2026 — written and submitted
- **Description**: Solution Design & Architecture presentation, deferred from Week 6. Slides + speaker notes.

### OpenSSF Scorecard enrichment (Week 10)
- **Resolved in**: Scorecard PR (490 tests passing, milestone tag pending)
- **Description**: Per-package engineering hygiene signals from `api.securityscorecards.dev`. Trust lens fetches Scorecard score, date, and top 3 lowest-scoring checks for each direct dependency (transitives skipped to control API cost). Trust breakdown panel renders score and concern chips per package; renders "not available" when no Scorecard exists (404) or repo is non-GitHub. Display-only — does not affect trust subscore, PRS, or fix-confidence. Helpers added: `extract_github_owner_repo` in `arguss/web/github_url.py` handles git+https, plain https, git+ssh, git://, and `github:` shorthand forms. Scorecard caching: 7-day TTL for hits, 24h TTL for 404s. Verified live on axios v1.0.0 — 9 of top-10 direct deps showed real Scorecards with score range 2.0-8.1.

### Scorecard hygiene section — decouple from top-10-by-trust display
**Filed: June 17, 2026 — surfaced during Scorecard render debugging**

- **Resolved in**: Scorecard hygiene PR (`7ac853b`)
- **Description**: Fixed heterogeneous `ScoreBreakdown.lines` rendering (dict-shaped Scorecard lines with `label`/`value`/`indent`/`muted` and chip values were blank in the template). Added a separate Scorecard hygiene section in `build_trust_breakdown` via `_scorecard_hygiene_lines`: iterates all direct deps with `scorecard_score is not None`, sorted worst-score-first, decoupled from the top-10-by-trust-subscore list. Zero new API calls — display-only over already-fetched direct-dep data. Captioned as engineering hygiene context, not a gating signal. Does not extend Scorecard fetching to transitives.

### Per-finding Claude explanation
**Filed: May 28, 2026 — deferred from PR 6**

- **Resolved in**: Finding explain PRs (`4b0afaf`, `f9f355e`)
- **Description**: On-demand Claude prose per finding via an Explain button on finding cards and the select-candidates page. HTMX endpoint at `POST /dashboard/finding-explain` returns an HTML chunk; results cached in `scan_cache` keyed by `(scan_hash, finding_id)`. Loading state shows three-dot typing indicator; falls back gracefully if Claude API fails (shows "No explanation available" — finding card retains all other info). Display-only — does not affect PRS, fix-confidence, or verdicts. Select-candidates page adds optional version-change-risks section via separate cache key.

### Workflow Security `not_applicable` state
- **Resolved in**: PR 4.2 score-transparency fixes
- **Description**: Workflow Security tile shows `not_applicable` (not `0`) when no workflows scanned

### Workflow Security decoupled from test_reality penalty
- **Resolved in**: PR 4.2 score-transparency fixes
- **Description**: The Workflow Security tile shows zizmor-only score; test_reality penalty stays in PRS calculation but not in the Workflow Security tile display

### Inverted lens tile color direction
- **Resolved in**: PR 4.2 score-transparency fixes
- **Description**: All lens tiles now honor engine direction (higher = more risk)

### Chat panel slide-in UX
- **Resolved in**: PR 5 + PR 5.1 fixes
- **Description**: Slide-in from right desktop, bottom-sheet mobile, page content shifts, etc.

### Stub banner removal
- **Resolved in**: PR 5
- **Description**: All stub routes replaced with real content

### Loading rotating scan-stage messages
- **Resolved in**: Implemented (pre-PR 6 scoping confirmed)
- **Description**: Stage message rotation during loading indicator

### Generic styled error card system
- **Resolved in**: PR 6
- **Description**: `partials/_error_card.html` with title/message/suggestions/actions, used by all major error paths (Mode B lockfile, Mode A/C GitHub fetch, clone failures, zip uploads, generic 500s)

### Mode B lockfile error UX
- **Resolved in**: PR 6
- **Description**: Friendly error card with "Try Mode A instead" CTA, plus pre-flight JS validation on the upload form. Replaces the previous verbose Python traceback rendering.

### Mode-aware pipeline.test_reality veto message
- **Resolved in**: PR 6
- **Description**: Mode B variant suggests trying Mode A URL scan for live workflow analysis, since Mode B uploads can't include workflows

### Chat system prompt — zizmor terminology fix
- **Resolved in**: PR 6
- **Description**: Added Arguss architecture overview and lens glossary to chat system prompt. Resolves the bug where Claude said "the scan doesn't contain zizmor results" — zizmor IS the workflow security analysis tool in Arguss, and the prompt now explicitly maps user terminology ("zizmor", "workflow security", "CI security") to the Pipeline lens.

### Finding card score badge
- **Resolved in**: PR 6
- **Description**: Color-coded badge styling (green/amber/red) replacing plain "Score X" text. Direction is "lower = riskier" (opposite of lens subscores).

### Trust subscore — CLI direct-deps alignment
- **Resolved in**: PR 6
- **Description**: CLI filters to direct deps when computing the trust subscore, matching the dashboard. Simple fix — passes direct-only list to existing `aggregate_trust_subscores`.

---

## How to update this file

When a new backlog item surfaces:
1. Add it under the appropriate category
2. Include status, effort estimate, description, and trigger
3. Date the entry if it's substantial

When a backlog item ships:
1. Move it to the **Resolved** section at the bottom
2. Note which PR resolved it
3. Keep the description for reference

This file is the central place to track "things we know about but aren't doing right now."
