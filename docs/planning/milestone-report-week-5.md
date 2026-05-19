# Arguss — Milestone Report (Week 5 Closure)

**MICS Capstone CYBER 295.001 — Summer 2026**

*Sherbano Khan, Huiping Qiu (Sophia), Adrian Rosales*

**Report date:** May 18, 2026

---

## Where we are

We are tracking three weeks ahead of the syllabus calendar. By Week 5 of the syllabus (June 3, 2026), we have shipped Weeks 3, 4, and 5's planned deliverables and have just merged Week 6 PR 1. The acceleration is deliberate: we're banking schedule buffer for the conceptually harder weeks ahead (Week 7 request handler, Week 9 web UI build, Week 11 evaluation).

## What's shipped

### Week 3: Vulnerability lens (complete)
- npm `package-lock.json` v3 parser with transitive dependency graph and logical-edge resolution
- OSV.dev client with 7-day caching, batch query support, and graceful error handling
- Vulnerability lens with CVSS v3 vector parsing (including `path-to-regexp` and other real-world cases)
- CycloneDX 1.7 SBOM generator (validates against the spec)
- CLI: `arguss scan`, `arguss sbom`
- Tagged `milestone/week-3-complete`. 70+ tests at this point.

### Week 4: Trust signal lens (complete)
Built in two PRs.

**PR 1 (`feature/trust-snapshot`):** TrustSnapshot model, npm registry client mirroring the OSV client pattern (24h cache, typed errors), Levenshtein typosquat detector, a top-1000 npm popularity snapshot derived from search-API results, a `scripts/refresh-top-1000.py` for regeneration, the `arguss trust-snapshot` CLI command.

**PR 2 (`feature/trust-delta`):** TrustDelta model with four veto flags (OWNERSHIP_TRANSFER, NEW_MAINTAINER, CADENCE_ANOMALY, DOWNLOAD_COLLAPSE), the cadence anomaly logic with a three-condition rule (ratio + version count + 7-day floor), top-10 mean aggregation across the project's most-impacted packages, graceful degradation when registry fetches fail, the `arguss trust-delta` CLI command.

A real-world scan on the Express fork at this point produced PRS=55.2 with the CVE lens at 75.0 (12 real findings) and Trust lens at 34.0. Several legitimate false positives are now documented (e.g., sole-maintainer packages flagged conservatively; `ms`, `qs`, `send`, `raw-body`, `depd` missing from the search-derived top-1000 list). These are tracked as Week 10 enhancements.

Tagged `milestone/week-4-complete`. 100 tests.

### Week 5: Pipeline lens (complete)
Built in two PRs.

**PR 1 (`feature/zizmor-wrapper`):** ZizmorClient subprocess wrapper around the zizmor 1.25.2 CLI, with the real JSON output schema captured by inspection (top-level array, `ident`/`desc`/`url`, `determinations.severity` nested, Primary location preference, 0→1 indexed line conversion). Severity values lowercased from zizmor's title-case (`Informational`, `Low`, `Medium`, `High`). Uses zizmor's `--no-exit-codes` flag so successful runs always return 0. CLI: `arguss zizmor-scan`.

**PR 2 (`feature/pipeline-lens`):** TestReality and PipelineSnapshot models. Four-condition test reality rule (has_test_script, not_no_op, has_test_files, workflow_runs_tests). Recognizes yarn/pnpm/bun aliases for the test invocation via regex. Severity-weighted-sum subscore (informational=2, low=5, medium=15, high=30) plus a 40-point test-reality penalty, capped at 100. Cascading-reasons short-circuit (no `package.json` emits only one reason, not the downstream cascade). Six fixtures under `tests/fixtures/repos/` covering each veto path. CLI: `arguss pipeline-snapshot`.

Tagged `milestone/week-5-complete`. 153 tests.

### Week 6 PR 1 (just merged): Fix-confidence engine
The conceptual core. FixCandidate and FixConfidence models (frozen dataclasses with derived idempotency keys). Three new modules in `arguss/engine/`: the FixKind classifier (minimal semver parser), the kill switch (operator-level disable via env var or sentinel file), and the fix-confidence engine itself (pure decision function combining the three lens outputs into a tier + score + reasons + veto signals + audit context). 27 new tests, full suite now at 180 passed.

The engine's evaluation order is: kill switch → project veto → fix_kind.MAJOR → trust → pipeline. Vetoes are independent; multiple can fire simultaneously and all appear in the output. Score reductions per veto signal land in a documented table that's empirically tunable in Week 11 evaluation.

Engine version `fix-confidence-v1.0.0` is stamped on every verdict for audit trail traceability.

## Two pivots, briefly

The project has pivoted twice during the planning and early-build phases.

**Week 2 pivot:** from "three-lens scanner with explanations" to "autonomous remediation agent with three-lens confidence envelope." Driven by instructor feedback. The change reframed the product around remediation (not detection) and around a defensible risk model (not a unified score). Documented in `docs/planning/pivot-rationale.md`.

**Week 6 pivot:** from "installable GitHub App" to "web service with opt-in GitHub action." Driven by the realization that autonomous decision-making and autonomous action are separable, and that the demo lands harder with a web UI showing the agent's reasoning than with a list of bot-authored PRs in GitHub. Documented in `docs/planning/web-ui-pivot-rationale.md`.

Both pivots preserved all shipped code. The three lenses, the fix-confidence engine, the CLI, the parsers, the clients all live below the deployment-model boundary — they don't change shape when the deployment changes. The Week 9 work shifts from GitHub App registration to web UI build, but the build budget is comparable.

## The current product

Arguss is an autonomous decision-making system for npm supply chain remediation, delivered as a web service. Users point Arguss at a GitHub repository (by URL, by file upload, or by URL + token), and Arguss produces a remediation plan: which dependency upgrades address the project's CVEs, which the agent would auto-merge given its confidence model, and which need human review. With a token (Mode C), Arguss can enact the plan by opening PRs.

The contribution is the decision-making layer: autonomous evaluation of remediations against a defensible risk model, in a category that's mostly served by either dumb auto-PR tools (Dependabot, Renovate) or smart-but-passive detection tools (Snyk, Socket.dev).

## What's next

**Week 6 PR 2 (in progress):** the `arguss propose-fixes` CLI command and the fix-discovery layer that produces FixCandidate(s) from CVE findings. This ties the lenses to the engine end-to-end and produces the first user-visible artifact that says "here's what the agent would do."

**Threat model (in progress):** parallel deliverable for Week 6. Eight threats identified, each with mitigations and residual risk. Several mitigations land as design constraints in the engine (kill switch, idempotency key, audit trail, DECLINE as first-class).

**Solution Design & Architecture Presentation:** scheduled for Week 6 per the syllabus. Will present the three-lens architecture, the fix-confidence engine, the web UI deployment shape, and the threat model.

**Week 7:** request handler that ties everything together for on-demand analysis. The first piece of the web service's real functionality. Escalation message generation via Anthropic's API as a separate small PR.

**Week 9:** the web UI build. HTMX + Tailwind dashboard with the three input modes. The first user-visible product.

**Week 11:** evaluation. The three demo scenarios reproduced on a frozen Express fork; comparison with Snyk and Dependabot; empirical tuning of the fix-confidence score weights based on results.

## Real numbers

Where we have them:

| Metric | Value |
|---|---|
| Tests passing | 180 (1 skipped) |
| Lines of production Python | ~3,500 (rough estimate; will refine) |
| Modules in `arguss/` | 12 |
| CLI commands | 6 (`scan`, `sbom`, `trust-snapshot`, `trust-delta`, `zizmor-scan`, `pipeline-snapshot`) |
| Real-world Express scan PRS | 55.2 (CVE: 75.0, Trust: 34.0, Pipeline: 40 baseline) |
| Real CVEs found in Express fork | 12 |
| Documented limitations | 7 (tracked as GitHub issues) |
| Pivots taken | 2 |

## Risks and concerns

**Pivot fatigue.** Two pivots in five weeks is a real pattern. We have committed in writing that further direction changes require a rationale document at the same level of rigor as the existing two. We believe the current direction is stable.

**Web UI build cost.** Week 9's HTMX + Tailwind build is concentrated in one week. We're banking schedule buffer (currently three weeks ahead) specifically to absorb Week 9 if it runs long.

**Anthropic API integration risk.** The Claude-backed escalation message generator is a Week 7 add. The architecture explicitly keeps Claude in the presentation layer (it never affects the agent's decision-making), so a Claude failure degrades the UX but doesn't compromise correctness.

**Evaluation honesty.** Week 11 evaluation will report what we find, including false positives and false negatives. The fix-confidence score weights are empirically tunable; we expect to revise them based on evaluation data.

## Team contributions (Week 3–6)

- **Sherbano Khan:** [team can fill in]
- **Huiping Qiu (Sophia):** [team can fill in]
- **Adrian Rosales:** primary implementer of Weeks 3–6 PRs; design and architecture work; pivot rationale documents; threat model draft; coordination with Cursor for code generation discipline.

---

**Submission target:** May 27, 2026 per syllabus.
