# Arguss — Week 4 Milestone Report

**MICS Capstone (CYBER 295) — Summer 2026**

*Team:* Sherbano Khan, Huiping Qiu (Sophia), Adrian Rosales

*Submitted by:* Adrian Rosales

*Date:* May 27, 2026

---

## Executive summary

Through Week 4 we have shipped all planned Weeks 1–4 deliverables on schedule, completed a strategic pivot of the project's core thesis in response to instructor feedback at the boundary of Weeks 2 and 3, and now have a working three-lens scanner producing real risk scores on real npm projects. The pivot — from a three-lens supply chain scanner with AI-explained remediations to an autonomous remediation agent with a three-lens confidence envelope — preserved all prior engineering work unchanged while sharpening the project's competitive positioning and demo story. Team sign-off on the pivot was recorded via the `docs/pivot-marker` pull request merged on May 15.

The Week 4 trust signal lens shipped in two pull requests (`feature/trust-snapshot` and `feature/trust-delta`), completing one week of project plan progress in a single working week of focused engineering. End-to-end, `arguss scan` on a real-world Express fixture now produces a Project Risk Score of 55.2, combining 12 real CVE findings, real trust signals across 50 dependencies, and a placeholder pipeline lens (which will land in Week 5).

## Where we are vs. the project plan

The original 14-week plan called for a vertical-slice delivery strategy: a thin version of all three lenses by Week 5, end-to-end integration by Week 6, demo-ready by Week 8. We are on that schedule, with the following deliverables shipped to `main`, all tagged:

### Weeks 1–2 (May 6–13)

Repository and CI/CD infrastructure stood up. FastAPI skeleton deployed to Fly.io with a live URL. SQLite caching layer in place. Architecture documentation and Day 1 setup guide committed to `docs/`. Project board configured with custom fields. The 5W1H deliverable was submitted on schedule.

### Week 3 (May 20)

The vulnerability lens shipped end-to-end:

- npm `package-lock.json` parser (v3) handling scoped packages, nested transitives, workspaces, and lockfile v1 detection-with-error
- OSV.dev client with 7-day cache TTL, batched querying, and deduplication
- Vulnerability lens producing real `LensScore` output with CVSS vector parsing
- Integration tests against real OSV data (gated by pytest marker)
- CycloneDX 1.7 SBOM generator with a hand-rolled emitter (no external CycloneDX library)
- New `arguss sbom <path>` CLI subcommand
- 70+ tests in the suite, all green; CI green on every push to `main`

Tagged in git as `milestone/week-3-complete`.

### Week 4 (current)

The trust signal lens shipped end-to-end across two PRs under the new agent-veto framing:

**Branch 1 (`feature/trust-snapshot`):**
- `TrustSnapshot` data model and snapshot fetcher
- npm registry client (mirrors OSV client patterns)
- Typosquat distance calculator (iterative Levenshtein DP)
- Top-1000 npm list committed as `data/npm-top-1000-2026-05.txt` (1000 sorted entries) plus refresh script
- `arguss trust-snapshot <package> <version>` CLI subcommand
- 10 unit tests via `MockTransport` plus 1 integration test against real npm

**Branch 2 (`feature/trust-delta`):**
- `TrustDelta` and `TrustFlag` enum
- Four-flag veto logic: ownership transfer, new maintainer, cadence anomaly, download collapse
- Cadence anomaly with three-condition rule (ratio + version count + absolute floor)
- `TrustLens.scan()` replaced with real implementation: per-dep snapshot fetching, top-10-mean aggregation, graceful degradation on per-dep failures
- `arguss trust-delta <package> <from> <to>` CLI subcommand
- 12 new delta unit tests + 5 lens integration tests + 1 integration test against real npm (lodash 4.17.20 → 4.17.21)

Tagged in git as `milestone/week-4-complete`.

## What we learned and how we responded

Around the boundary of Weeks 2 and 3 we received feedback that significantly shaped the rest of the project. The feedback, in summary:

> In a world where agentic AI systems are increasingly writing, deploying, and updating production code, detection-with-human-review is becoming commodity. The unsolved problem is not finding the vulnerability — it is acting on the vulnerability autonomously, in a way the operator can defend. The differentiation lives in autonomous remediation, not better detection. Can we narrow scope to differentiate by going deep on autonomous action?

Our team's response, after structured discussion, was to absorb this feedback as a strategic pivot rather than a tactical adjustment. The full rationale is documented in `docs/planning/pivot-rationale.md`. The revised product framing is in `docs/planning/project-overview.md`. Both files were committed to `main` before the Week 3 Project Overview was submitted to the instructor, ensuring we presented a single coherent direction.

The decision to pivot at Week 2 rather than later was deliberate: all Week 1–3 implementation work (parser, OSV client, vulnerability lens, SBOM generator) was preserved unchanged in the new plan, and Week 4's trust lens was implemented under the new framing from the start.

## What changed

The pivot's substance is documented in `docs/planning/pivot-rationale.md`. For this report's purposes, the high-level changes are:

**Product framing.** Arguss is now an autonomous remediation agent for npm supply chain vulnerabilities, delivered as an installable GitHub App. It detects vulnerable dependencies, generates the fix, opens a pull request, waits for the repository's existing CI to verify it, and merges — but only when the fix falls inside a defensible confidence envelope.

**The three lenses are reframed.** Rather than composing a single risk score for human review, the three lenses now compose a per-remediation fix-confidence function that gates the agent's authority to act. The trust lens, shipped this week, produces both a snapshot-level subscore for the existing Project Risk Score path and a delta-level `safe_to_auto_merge` veto bit that the Week 6 fix-confidence engine will consume.

**Auto-merge envelope.** We will defend the following default: patch and minor version bumps to known vulnerable packages, where trust signals are unchanged, blast radius is bounded under a configurable threshold, the repository's CI runs real tests, and those tests pass. The envelope is configurable; the default is conservative on purpose.

**Deployment.** A GitHub App on Fly.io, replacing the originally-planned web upload tool. The App will hold scoped credentials, receive webhooks, and take action with a named bot identity. Implementation lands Week 9.

**Evaluation comparison.** We replace the planned detection-coverage comparison versus Snyk with a remediation-throughput comparison versus Dependabot. The intellectual wedge is that Dependabot and Renovate auto-PR based on version availability with no risk model; Arguss auto-acts only when a defensible risk model says it is safe to do so.

## End-to-end evidence: real-world scan results

The Week 4 trust signal lens means that, for the first time, `arguss scan` produces real numbers on real npm projects across all three lenses (though pipeline remains stubbed until Week 5).

Running `arguss scan` on `tests/fixtures/lockfiles/real-world.json` — a frozen Express 4.17.0 dependency tree — produces:

| Metric | Value | Notes |
|---|---|---|
| Project Risk Score | **55.2** | Weighted: 0.4 × 75 + 0.3 × 34 + 0.3 × 50 |
| CVE lens score | **75.0** | 12 real findings from OSV.dev |
| Trust lens score | **34.0** | Top-10 mean of per-dep subscores |
| Pipeline lens score | 50.0 | Still the fake stub (Week 5 replaces) |

The CVE lens identified real, patchable vulnerabilities with known fix versions on the Express fixture — the exact case the autonomous agent is designed to handle. Examples:

- **body-parser 1.19.0 → 1.20.3** — DoS via URL encoding (high severity, patch-level bump available)
- **cookie 0.4.0 → 0.7.0** — out-of-bounds character handling (low severity, minor bump available)
- **path-to-regexp 0.1.7 → 0.1.13** — three separate ReDoS advisories (high severity, patch-level bump available)
- **express 4.17.0 → 4.20.0** — XSS and open-redirect findings (medium severity, minor bump available)
- **qs 6.7.0 → 6.10.3** — prototype pollution (high severity, minor bump available)

Several of these are exactly the auto-merge cases the agent will handle: clean patch-level bumps to known-good versions, with the responsible package's maintainer set unchanged (verified via the trust lens). These specific CVEs may seed our Week 8 demo scenarios.

The trust lens identified false-positive patterns that we now have concrete evidence for and have documented in backlog issues:

- **Sole-maintainer false positive:** Approximately 8 dependencies in the Express fixture trigger the +30 sole-maintainer subscore. These are legitimate Doug Wilson (`dougwilson`) packages — `etag`, `fresh`, `parseurl`, etc. The trust lens flags them correctly per its v1 rules, but a more mature system would discount the penalty for known high-reputation maintainers. Documented in `docs/planning/trust-signal-lens.md` as a known characteristic; namespace/maintainer allowlisting is deferred to Week 10 v2 enrichment.

- **Top-1000 coverage gap:** High-download packages `ms` (449M weekly downloads), `qs` (165M), `send` (107M), `raw-body` (111M), and `depd` (114M) are absent from our search-derived top-1000 list. They each trigger typosquat distance penalties of +15 or +25 because the list contains lexically-similar but less-popular names. Total false-positive contribution on this fixture: approximately 120 subscore points across the findings, raising the trust lens score from a theoretical ~25 to the observed 34. Documented in a backlog issue; switching to a download-statistics-derived source is planned for Week 10.

Both patterns are bounded by the conservative envelope design: in the agent flow, they escalate to human review rather than blocking auto-merge incorrectly. The conservative posture is working as designed.

## What's preserved

For honest accounting, the following from the original plan is unchanged:

- All Week 1–3 implementation code (parser, OSV client, vulnerability lens, SBOM generator, scaffolding, CI)
- The project name (Arguss)
- The scope discipline (npm, GitHub Actions, OSV.dev, Fly.io)
- The three-lens architecture
- The team structure and role assignments
- The vertical-slice delivery strategy
- The Week 6 unified scoring engine — gaining one additive output, not being replaced

## What's next — Week 5 and the path to Week 8

**Week 5 (Jun 3).** Pipeline lens v1 — a wrapper around `zizmor` for GitHub Actions workflow analysis, plus heuristics for "does the repository's CI run meaningful tests." Under the new framing, the pipeline lens answers "is this repository safe for the agent to act on at all?" Solution Design & Architecture Presentation delivered.

**Week 6 (Jun 10).** The unified scoring engine gains its second output: the per-remediation fix-confidence score. Threat model written specifically for an autonomous agent acting with delegated credentials, including credential scoping, idempotency, and rollback semantics.

**Week 7 (Jun 17).** Minimal agent loop end-to-end against a single mock repository. Branch creation, commit, PR opening, CI polling, merge or escalation. No GitHub App yet — a personal access token validates the loop logic. 5-Point Mid-Point Presentation delivered.

**Week 8 (Jun 24).** Demo polish, Proof of Concept delivery, real demo repository staged. Current candidate: a frozen-in-time fork of a recognizable mid-size npm project — the Week 4 Express 4.17.0 fixture is a strong candidate given the rich set of real CVEs it carries.

**Weeks 9–14.** GitHub App migration, reliability hardening, evaluation against three reconstructed scenarios, final webpage, dry run, showcase.

## Risk register

The pivot introduces new risks we are explicitly watching:

| Risk | Severity | Mitigation |
|---|---|---|
| Agent unreliability at demo | High | Conservative envelope by default; cached demo mode for all live API calls; escalation paths are themselves demoable; GitHub Actions handles test orchestration so we don't build our own test harness |
| GitHub App operational reliability | Medium | Existing Fly.io deployment extends naturally to the App host; monitoring via Fly.io built-ins; failure mode is "agent declines to act" not "agent breaks main" |
| Scope creep into multi-repo / fleet operation | Medium | Out-of-scope list maintained on project board; multi-repo deferred to "future work" in the pitch |
| Week 9 GitHub App migration slipping | Medium | One owner assigned; Week 7 agent loop validates the logic before the App refactor, so a slip affects polish not core functionality |
| Auto-merge of a malicious package | High (impact) / Low (likelihood) | Conservative trust veto; trust signal stability is the primary guard; default thresholds tuned to false-positive over false-negative; threat model documents the residual risk |
| False positives in trust lens producing demo noise | Medium | Documented patterns (sole-maintainer on dougwilson packages, typosquat on absent-from-top-1000 high-download names); demo repo selection will avoid pathological cases; backlog issues track v2 enrichment to reduce noise |
| Anthropic API outage during demo | Low | Escalation messages pre-generated for all demo scenarios; demo never depends on a live API call |

The risks from the original plan (OSV.dev rate limits, zizmor format changes, team member availability, API cost overrun) carry over unchanged.

## Project management evidence

The team's planning artifacts are all in version control under `docs/planning/`:

- `project-plan.md` — original 14-week plan (preserved for diff-against-pivot)
- `pivot-rationale.md` — why we pivoted, what changed, with team sign-off
- `project-overview.md` — current product framing (Week 3 deliverable)
- `week-3-plan.md` — Week 3 implementation breakdown
- `trust-signal-lens.md` — Week 4 design doc (Branch 1 + Branch 2 sections, false-positive observations)
- `parser-notes.md` — parser design notes
- `qanda/sbom-generator.md` — SBOM generator design walkthrough

Git tags mark milestones: `milestone/day1-complete`, `milestone/week-3-complete`, `milestone/week-4-complete`. Each future milestone will get its own tag.

GitHub issues track known limitations and deferred work: cache self-heal on corrupt rows, top-1000 list source improvement, namespace allowlist for trust signal false positives.

## Conclusion

We are on schedule with a sharper product thesis than we started with and a working two-and-a-half-lens scanner producing real Project Risk Scores on real npm dependency trees. The remaining 10 weeks are concentrated on the pipeline lens (Week 5), the unified fix-confidence engine and threat model (Week 6), the agent loop (Week 7), demo staging (Week 8), and the GitHub App migration with reliability hardening (Weeks 9–10). Evaluation and final delivery follow in Weeks 11–14.

The Week 4 deliverable demonstrates that the project is not only on track but is genuinely producing the kind of analysis that the autonomous remediation thesis requires: real CVE detection, real trust signal analysis, and explicit per-remediation veto logic ready to feed the Week 6 fix-confidence engine.

Adrian Rosales, on behalf of the team
