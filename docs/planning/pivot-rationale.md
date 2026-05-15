# Arguss — Pivot Rationale

**Date:** May 13, 2026 (Week 2 of 14)

**Status:** Proposed — pending team sign-off

**Authors:** Sherbano Khan, Huiping Qiu (Sophia), Adrian Rosales

---

## Why this document exists

We received instructor feedback that the original project framing — a three-lens supply chain scanner with explanations — is well-built but increasingly commodity in a world where agentic AI systems are writing, deploying, and updating production code. The feedback was to consider whether we can narrow scope and differentiate by going deep on **autonomous remediation**: agents that detect, fix, verify, and merge without human intervention, while knowing when not to act.

This document records what we're changing, what we're keeping, and why we believe the new direction is stronger — so the team can sign off on the pivot before it commits in writing via the Week 3 Project Overview.

## The feedback in one paragraph

> *How does our project manifest in an agentic AI world? Detection becomes better and better; the unsolved problem is remediation without a human in the loop. Can we narrow scope to differentiate? Can we take the CVE and the report and take action — auto-correct as much as possible, address vulnerabilities en masse, make the agent part of the entire CI/CD pipeline? What we have is a real problem. The differentiation lives in autonomous action, not better detection.*

## What we're keeping

- **Project name:** Arguss
- **The three lenses:** vulnerability, trust signals, pipeline
- **The scope discipline:** npm, GitHub, OSV.dev, Fly.io
- **All Week 1–3 implementation work:** lockfile parser, OSV client, CycloneDX SBOM generation, scaffolding, CI, planning docs
- **The team structure and role assignments**
- **The vertical-slice delivery strategy**

## What's changing

| Aspect | Before | After |
|---|---|---|
| **Product framing** | Three-lens scanner with explained remediations | Autonomous remediation agent with three-lens confidence envelope |
| **Primary UI** | HTMX dashboard with three panels | Pull request feed + escalation queue; dashboard becomes observability view |
| **Role of three lenses** | Composing a unified risk score for human review | Composing a fix-confidence function that gates the agent's authority to act |
| **Deployment** | Web upload tool | Installable GitHub App with webhooks and scoped credentials |
| **Decision boundary** | Show all findings, let humans decide | Auto-act inside a defensible envelope; escalate outside it |
| **AI feature** | Explain remediations to humans on demand | Generate the escalation message when the agent hands off to humans |
| **Evaluation comparison** | vs. Snyk on detection coverage | vs. Dependabot on remediation throughput and risk-bounded merge correctness |

## The auto-merge envelope we will defend

> Patch and minor version bumps to known vulnerable packages, where trust signals are unchanged over the upgrade window, blast radius is bounded under a configurable threshold, the repository's CI runs real tests, and those tests pass.

Major version bumps, trust anomalies, unbounded blast radius, missing tests, or failing tests all escalate. Conservative on purpose; the threshold is a dial we will defend empirically in Week 11 evaluation.

## Why now is the right time

- **We are at Week 2 of 14** — early enough that most planning artifacts can be revised without throwing away built code.
- **Week 1–3 implementation work is preserved unchanged** in the new plan. The parser, OSV client, and SBOM generation are still needed in exactly the form they're being built.
- **Locking in the pivot before Project Overview submission (Week 3)** means we present one coherent direction to the instructor, not a shifting target.
- **The pivot rationale is itself a deliverable.** Capstones are judged in part on how the team responds to feedback. Documenting this decision in writing demonstrates project management maturity.

## Why this is a stronger project, not just a different one

**Sharper demo.** "We auto-fix 60% of npm CVEs end-to-end on a real fork of Express in 3 minutes" lands harder than "we scan three lenses and show a dashboard."

**Sharper competitive positioning.** The comparison to Dependabot is more interesting than the comparison to Snyk was. Snyk competes on detection coverage and CVE database freshness — both areas where a capstone cannot reasonably compete. Dependabot competes on auto-PR throughput with zero risk model. We have a real wedge there: a defensible risk model gating autonomous action.

**Richer threat model.** Autonomous agents acting with delegated credentials is contemporary research territory, not solved ground. We get to write a threat model about agent identity, credential scoping, confidence-bounded autonomy, and rollback — much more interesting than a threat model about a scanner.

**Demoable failure modes.** When the agent declines to act, that is a feature ("the agent knows what it doesn't know"), not a bug. The escalation cases in the demo are as compelling as the auto-merge cases. This is a meaningful advantage: most demos hide their failure cases, and ours showcases them.

**Real-world demo on a real repo.** A forked-and-frozen `expressjs/express` (or a comparable mid-size npm project) lets us show the agent acting on a repository every JavaScript developer recognizes. The fork is pinned to a commit ~12–18 months old so the CVEs are real, with known good fixes.

## What we're worried about and how we'll mitigate it

**Agent unreliability at demo.** Mitigated by:
- Conservative envelope by default — the agent only auto-merges in a regime where it basically can't be wrong
- Cached demo mode — all live API calls (OSV, Anthropic, GitHub) pre-cached for the demo repo
- Escalation paths as demoable moments — the agent declining to act is a slide, not a failure
- GitHub Actions for test orchestration — we don't build our own test harness, we use the repo's existing CI

**Throwing away done work.** Almost none thrown away. Week 1–3 build survives; Week 4–6 lens work survives with reframing; Week 9–10 is where the new build cost lives.

**Defending it to instructors.** This pivot rationale is the defense. The confidence-envelope reasoning is the intellectual core. The Dependabot comparison is the practical anchor. Project Overview reflects the new direction officially.

**Operational reliability of the GitHub App.** A real persistent service that runs for the project duration. Mitigated by: existing Fly.io deployment grows into the App host (not a new system), straightforward monitoring (Fly.io built-ins are sufficient), and the App's failure mode is degraded — the agent doesn't act — rather than catastrophic.

## What we are giving up

For honest accounting:

- **The Cytoscape.js interactive blast radius graph** as a centerpiece. Replaced by a static blast radius diagram in the escalation message. The interactive version becomes future work.
- **The HTMX dashboard as the primary product.** It survives as an observability view of the agent's reasoning, not the deliverable.
- **EPSS, CISA KEV, OpenSSF Scorecard as separate v2 features.** They fold into the fix-confidence engine as inputs, but don't get standalone UI features.
- **The detection-coverage comparison vs. Snyk.** Replaced by the remediation-throughput comparison vs. Dependabot.

These cuts are net positive: they free engineering budget for the agent loop, which is now the project's core contribution.

## Team commitments needed

- **One owner for the GitHub App infrastructure.** Week 9 is the heavy week — App registration, OAuth, webhooks, credential storage, scoped permissions. This person should be comfortable with operational concerns.
- **One owner for the fix-confidence engine.** Week 6 is conceptually critical — the engine is the project's intellectual core. Defining inputs, weights, and thresholds in a way we can defend.
- **One owner for evaluation and the demo repo.** From Week 7 onward — staging the fork, reproducing the three scenarios, building the metrics tables.
- **Agreement that the dashboard is no longer the primary UI.** The primary UI is the PR feed.
- **Agreement on the auto-merge envelope.** Default: patch + minor + trust unchanged + bounded blast radius + tests pass. Configurable, but this is what we defend.

## Decision

By signing off on this document, the team agrees to:

1. The new product framing (autonomous remediation agent, not three-lens scanner)
2. The auto-merge envelope as stated
3. The deployment model (GitHub App on Fly.io)
4. The revised 14-week plan (see `docs/planning/project-plan.md` after revision)
5. The new evaluation framing (vs. Dependabot, not vs. Snyk)

---

**Sign-off:**

- [ ] Sherbano Khan
- [ ] Huiping Qiu (Sophia)
- [ ] Adrian Rosales
