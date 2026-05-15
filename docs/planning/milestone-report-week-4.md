# Arguss — Week 4 Milestone Report

**MICS Capstone (CYBER 295) — Summer 2026**

*Team:* Sherbano Khan, Huiping Qiu (Sophia), Adrian Rosales

*Submitted by:* Adrian Rosales

*Date:* May 27, 2026

---

## Executive summary

Through Week 4 we have shipped all planned Week 1–3 deliverables on schedule, completed a strategic pivot of the project's core thesis in response to instructor feedback, and begun Week 4 implementation under the new framing. The pivot — from a three-lens supply chain scanner with AI-explained remediations to an autonomous remediation agent with a three-lens confidence envelope — preserves all Week 1–3 engineering work unchanged while sharpening the project's competitive positioning and demo story. Team sign-off on the pivot is recorded in `docs/planning/pivot-rationale.md` and via the `docs/pivot-marker` pull request merged on [date].

## Where we are vs. the project plan

The original 14-week plan called for a vertical-slice delivery strategy: a thin version of all three lenses by Week 5, end-to-end integration by Week 6, demo-ready by Week 8. We are on that schedule, with the following deliverables shipped to `main` and tagged:

**Weeks 1–2 (May 6–13).** Repository and CI/CD infrastructure stood up. FastAPI skeleton deployed to Fly.io with a live URL. SQLite caching layer in place. Architecture documentation and Day 1 setup guide committed to `docs/`. Project board configured with custom fields. The 5W1H deliverable was submitted on schedule.

**Week 3 (May 20).** The vulnerability lens shipped end-to-end:

- npm `package-lock.json` parser (v3) handling scoped packages, nested transitives, workspaces, and lockfile v1 detection-with-error
- OSV.dev client with 7-day cache TTL, batched querying, and deduplication
- Vulnerability lens producing real `LensScore` output with CVSS vector parsing
- Integration tests against real OSV data (gated by pytest marker)
- CycloneDX 1.7 SBOM generator with a hand-rolled emitter (no external CycloneDX library)
- New `arguss sbom <path>` CLI subcommand
- 70+ tests in the suite, all green; CI green on every push to `main`

Tagged in git as `milestone/week-3-complete`.

**Week 4 (May 27 — this submission).** Strategic pivot landed via `docs/pivot-marker` PR. Week 4 implementation work has begun on the trust signal lens under the new framing (see "What's next").

## What we learned

Around the boundary of Weeks 2 and 3 we received feedback that significantly shaped the rest of the project. The feedback, in summary:

> In a world where agentic AI systems are increasingly writing, deploying, and updating production code, detection-with-human-review is becoming commodity. The unsolved problem is not finding the vulnerability — it is acting on the vulnerability autonomously, in a way the operator can defend. The differentiation lives in autonomous remediation, not better detection. Can we narrow scope to differentiate by going deep on autonomous action?

Our team's response, after structured discussion, was to absorb this feedback as a strategic pivot rather than a tactical adjustment. The full rationale, including what we are changing and what we are preserving, is documented in `docs/planning/pivot-rationale.md`. The revised product framing is in `docs/planning/project-overview.md`. Both files were committed before the Week 3 Project Overview was submitted to the instructor, ensuring we present a single coherent direction rather than a shifting target.

The decision to pivot at Week 2 rather than later was deliberate: all Week 1–3 implementation work (parser, OSV client, vulnerability lens, SBOM generator) is preserved unchanged in the new plan. The pivot affects the project's narrative and the Week 7+ agent loop build, not the foundational lens infrastructure being shipped now.

## What changed

The pivot's substance is documented in `docs/planning/pivot-rationale.md`. For this report's purposes, the high-level changes are:

**Product framing.** Arguss is now an autonomous remediation agent for npm supply chain vulnerabilities, delivered as an installable GitHub App. It detects vulnerable dependencies, generates the fix, opens a pull request, waits for the repository's existing CI to verify it, and merges — but only when the fix falls inside a defensible confidence envelope.

**The three lenses are reframed.** Rather than composing a single risk score for human review, the three lenses now compose a per-remediation fix-confidence function that gates the agent's authority to act. The vulnerability lens identifies what needs fixing. The trust lens vetoes auto-merge if maintainer signals shifted in the upgrade window. The pipeline lens vetoes auto-merge if the repository's CI does not run meaningful tests.

**Auto-merge envelope.** We will defend the following default: patch and minor version bumps to known vulnerable packages, where trust signals are unchanged, blast radius is bounded under a configurable threshold, the repository's CI runs real tests, and those tests pass. Anything outside the envelope escalates to a human with a structured explanation. The envelope is configurable; the default is conservative on purpose, and we will tune it empirically in Week 11 evaluation.

**Deployment.** A GitHub App on Fly.io, replacing the originally-planned web upload tool. The App holds scoped credentials, receives webhooks, and takes action with a named bot identity. The HTMX dashboard survives as an observability view of the agent's reasoning rather than the primary product UI.

**Evaluation comparison.** We replace the planned detection-coverage comparison versus Snyk with a remediation-throughput comparison versus Dependabot. The intellectual wedge is that Dependabot and Renovate auto-PR based on version availability with no risk model; Arguss auto-acts only when a defensible risk model says it is safe to do so.

## What's preserved

For honest accounting, the following from the original plan is unchanged:

- All Week 1–3 implementation code (parser, OSV client, vulnerability lens, SBOM generator, scaffolding, CI)
- The project name (Arguss)
- The scope discipline (npm, GitHub Actions, OSV.dev, Fly.io)
- The three-lens architecture
- The team structure and role assignments
- The vertical-slice delivery strategy
- The Week 6 unified scoring engine — gaining one additive output, not being replaced

## What's next — Week 4 and the path to Week 8

**Week 4 (current).** Trust signal lens v1, under the new framing. The lens emits two outputs:

- A `TrustSnapshot` per `package@version` capturing maintainer data, publish cadence, typosquat distance to top-1000 packages, and weekly download counts. The snapshot's subscore feeds the existing PRS unchanged.
- A `TrustDelta` computed from two snapshots, capturing what changed across the upgrade window. The delta carries an explicit `safe_to_auto_merge` veto bit and an enumerated flag list (ownership transfer, new maintainer, cadence anomaly, download collapse).

The delta is the agent's veto signal. The Week 6 fix-confidence engine will consume it. The Week 4 build itself is split across two pull requests (`feature/trust-snapshot` then `feature/trust-delta`) so the snapshot infrastructure is reviewable independently of the delta computation.

**Week 5.** Pipeline lens v1 — a wrapper around `zizmor` for GitHub Actions workflow analysis, plus heuristics for "does the repository's CI run meaningful tests." Under the new framing, the pipeline lens answers "is this repository safe for the agent to act on at all?"

**Week 6.** The unified scoring engine gains its second output: the per-remediation fix-confidence score. Threat model written specifically for an autonomous agent acting with delegated credentials, including credential scoping, idempotency, and rollback semantics.

**Week 7.** Minimal agent loop end-to-end against a single mock repository. Branch creation, commit, PR opening, CI polling, merge or escalation. No GitHub App yet — a personal access token validates the loop logic. 5-Point Mid-Point Presentation delivered.

**Week 8.** Demo polish, Proof of Concept delivery, real demo repository staged (current candidate: a frozen-in-time fork of a recognizable mid-size npm project carrying real historical CVEs).

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
| Anthropic API outage during demo | Low | Escalation messages pre-generated for all demo scenarios; demo never depends on a live API call |

The risks from the original plan (OSV.dev rate limits, zizmor format changes, team member availability, API cost overrun) carry over unchanged.

## Project management evidence

The team's planning artifacts are all in version control under `docs/planning/`:

- `project-plan.md` — original 14-week plan (preserved for diff-against-pivot)
- `pivot-rationale.md` — why we pivoted, what changed, with team sign-off
- `project-overview.md` — current product framing (Week 3 deliverable)
- `week-3-plan.md` — Week 3 implementation breakdown
- `parser-notes.md` — parser design notes
- `qanda/sbom-generator.md` — SBOM generator design walkthrough

Git tags mark milestones: `milestone/day1-complete`, `milestone/week-3-complete`. The forthcoming `milestone/week-4-complete` tag will mark the trust signal lens shipping.

## Conclusion

We are on schedule, with a sharper product thesis than we started with and the foundational engineering already in place to deliver against it. The remaining 10 weeks are concentrated on the agent loop, the fix-confidence engine, and evaluation — the work that distinguishes Arguss from existing free tools and that justifies the project's contribution.

Adrian Rosales, on behalf of the team
