# Arguss — Autonomous npm Supply Chain Remediation

**MICS Capstone (CYBER 295) — Summer 2026**

*Sherbano Khan, Huiping Qiu (Sophia), Adrian Rosales*

---

*This document supersedes `project-overview.md` as of Week 6. See `web-ui-pivot-rationale.md` for what changed and why. The original is preserved as historical record of the Week 2 framing.*

---

## What we're building

Arguss is an autonomous decision-making system for npm supply chain remediation, delivered as a web service. A user points Arguss at a GitHub repository (by URL or by uploading the relevant files), and Arguss produces a remediation plan: which dependency upgrades would address the project's CVEs, which ones the agent would auto-merge given its confidence model, and which ones need human review. When the user grants consent — by providing a GitHub access token — Arguss can enact the plan: open the PRs, watch the user's existing CI verify them, and merge the in-envelope fixes.

The decision-making is autonomous. The action is conditionally autonomous: the user delegates by providing credentials, and once delegated, the agent acts without further per-action consent.

## The wedge

There are three categories of tool an npm developer might reach for to address supply chain vulnerabilities. Arguss occupies a position none of them does cleanly.

**Detection-first tools (Snyk, Socket.dev, Endor Labs).** Strong at finding what's wrong. They produce ranked lists of findings, often with remediation suggestions. They stop there: the user decides what to do. Arguss starts where they stop — taking the detection output and producing a defensible plan of *what to actually do*.

**Auto-PR tools (Dependabot, Renovate).** Strong at taking action. They will happily open and merge a PR for any newer version of a dependency. Their decision model is version availability: if there's a newer version, propose it. They have no risk model. The cost is that they'll merge a malicious patch the day after a maintainer takeover, because the new version is "newer." Arguss has a defensible risk model — trust signals over the upgrade window, pipeline reality, transitive blast radius — that gates whether autonomous action is safe.

**Manual review.** Strong at being careful. The cost is throughput: a security-conscious team can spend hours per week triaging CVE alerts. Arguss surfaces what a developer should look at, prioritized by what we'd defend ourselves. The agent declining to auto-merge is itself a signal: "this is the one a human should look at first."

The contribution: autonomous decision-making with a defensible risk model, in a category that's mostly served by either dumb autonomy or smart-but-passive detection.

## Why this matters now

Agentic systems are increasingly writing, deploying, and updating production code. Detection-with-human-review is becoming commodity. The unsolved problem is not "find the vulnerability" — it is "act on the vulnerability autonomously, in a way the operator can defend." Recent supply chain attacks (xz-utils, recurring npm credential theft, the Solana ecosystem incidents) succeeded because the malicious code was not in the CVE database when adopted. A remediation tool that acts on version metadata alone would have merged those attacks. A remediation tool that gates on trust-signal stability would have escalated them. That is the contribution.

## How it works

Arguss combines three signals into a per-remediation **fix-confidence verdict**: a tier (AUTO_MERGE, REVIEW_REQUIRED, DECLINE), a score (0–100), and structured reasons.

- **Vulnerability lens** — identifies what needs fixing. OSV.dev, GitHub Security Advisories, EPSS exploit prediction scores, CISA KEV flags.
- **Trust lens** — vetoes the auto-merge if maintainer count, ownership, or publish cadence changed during the upgrade window. npm registry, deps.dev, OpenSSF Scorecard, Levenshtein distance against top-1000 packages for typosquat detection.
- **Pipeline lens** — vetoes the auto-merge if the repository's CI does not run meaningful tests. zizmor for workflow analysis plus test-file heuristics.

### The auto-merge envelope

The default envelope we will defend:

> Patch and minor version bumps to known vulnerable packages, where trust signals are unchanged over the upgrade window, blast radius is bounded under a configurable threshold, the repository's CI runs real tests, and those tests pass.

Major version bumps, trust anomalies, unbounded blast radius, missing tests, or failing tests all escalate. The envelope is configurable; the default is conservative on purpose, and we will defend it empirically in evaluation.

### The three input modes

Arguss accepts three ways for a user to supply a project to analyze:

**Mode A — Repo URL (read-only).** User pastes a public GitHub repo URL. Arguss fetches the lockfile and workflows via the GitHub API, runs the three lenses, and shows the proposed plan. Touches nothing in the user's repo. Primary demo flow.

**Mode B — File upload.** User uploads `package-lock.json` (required); optionally `.github/workflows/` and `package.json`. Each additional upload unlocks more of the pipeline analysis. Useful for private projects.

**Mode C — Repo URL + GitHub PAT (opt-in action).** User provides a personal access token. Arguss analyzes the repo *and* can enact: open real PRs against the repo, with the user's consent on each one. This is the "actually do it" mode and the most credentialed shape.

All three modes share the same engine — the differences are purely in input/output handling.

## Deployment

Arguss is a hosted web service running on Fly.io. Users visit the service, choose an input mode, and get a remediation plan. The service does not hold long-lived credentials per user — it operates on per-session inputs only. When a user opts into Mode C, their PAT is held in memory for the duration of that session and discarded.

The web UI is the primary surface. Behind it sit the three lenses, the fix-confidence engine, and the GitHub integration layer (for Modes A and C). A CLI also exists for developer use and CI integration — it shares the same engine.

## Evaluation

We will evaluate Arguss on a frozen-in-time fork of a recognizable mid-size npm project (current candidate: a forked older version of `expressjs/express`) carrying real historical CVEs. The fork is pinned to a commit roughly 12–18 months old so that real CVEs are present with known good fixes.

Metrics:

- **Tier accuracy** on in-envelope vs. out-of-envelope fixes (when the agent said AUTO_MERGE, was the fix safe in retrospect? when it said REVIEW_REQUIRED, was human review warranted?)
- **Auto-merge rate** on in-envelope fixes
- **False-merge rate** (any auto-merged PR that broke detectable downstream behavior)
- **Time-to-fix** vs. baselines

### Comparison baselines

- **vs. Snyk** (or similar detection-first tool): does Arguss find the same vulnerabilities? does it produce more actionable output by combining detection with a remediation plan?
- **vs. Dependabot** (auto-PR tool): when Dependabot would auto-merge, does Arguss agree? when Arguss declines, would Dependabot have introduced risk?
- **vs. manual review**: how does Arguss's REVIEW_REQUIRED queue compare to what a careful developer would have flagged?

### Demo scenarios

Three reconstructed scenarios drive the demo:

1. **Hero case (Scenario A):** The agent processes a CVE backlog cleanly. Most fixes get AUTO_MERGE tier with high score; the user reviews the agent's reasoning panel, then optionally clicks "do it" to enact them via Mode C.
2. **"Agent knows what it doesn't know" (Scenario B):** A high-severity CVE requires a major version bump with breaking changes. The agent correctly returns REVIEW_REQUIRED with `fix_kind.major` as the veto signal. The escalation message explains why a human should look at it.
3. **Trust-signal save (Scenario C):** A patch-level CVE in a package whose maintainer changed during the upgrade window. The agent escalates despite the low version delta, because the trust lens flagged a new maintainer.

## Scope

One ecosystem (npm). One CI/CD platform (GitHub Actions). One deployment target (web service on Fly.io). Prebuilt vulnerability data (OSV.dev). The engineering effort is concentrated on the fix-confidence engine, the three lenses' veto logic, and the threat model for autonomous decision-making — not on building a new scanner.

## Stack

- **Service:** Python with FastAPI, deployed on Fly.io
- **Caching:** SQLite (WAL mode) on a Fly.io volume
- **Decision engine:** pure Python (no external services in the evaluation path)
- **GitHub integration:** GitHub REST API via user-supplied PAT (Modes A and C)
- **Test orchestration:** the repository's own GitHub Actions (Mode C)
- **Escalation messages:** Anthropic's API (Claude) for generating the natural-language explanation when the agent escalates (planned for Week 7)
- **Web UI:** HTMX + Tailwind

## Use cases (MoSCoW)

Prioritized use cases for the semester, mapped to modes, acceptance criteria, and delivery weeks:

**Full detail:** [`use-cases-and-delivery-plan.md`](use-cases-and-delivery-plan.md)

| Priority | ID | Use case | Modes | Status (May 2026) |
|----------|-----|----------|-------|-------------------|
| Must | UC1 | Read-only dependency audit | A, B | Shipped — polish & demo fork |
| Must | UC2 | Auto-remediate low-impact upgrades | C | Verdicts + open PR shipped; CI merge not v1 |
| Must | UC3 | SBOM for compliance | CLI | CLI shipped; web export planned |
| Must | UC4 | Evaluate before granting PAT | A, B → C | Shipped — demo script & threat model sign-off |
| Should | UC5 | Fix-confidence on contested fix | A, B, C | Shipped — scenario B/C for demo |
| Should | UC6 | AI-generated explanations | All | Shipped — pre-cache for demo |
| Could | UC7 | Incident triage | A, B | Partial via UC1; EPSS/KEV Week 10 |
| Won't | UC8 | Org-wide rollout | — | Out of scope |

---

## 14-week plan (revised)

The plan has been revised twice — once at the Week 2 pivot, once at the Week 6 pivot. Below is the current shape. **Per–use-case week mapping** is in [`use-cases-and-delivery-plan.md`](use-cases-and-delivery-plan.md#14-week-delivery-map-by-use-case).

- **Weeks 1–2 (Ideation, scoping, architecture):** ✅ shipped. FastAPI skeleton on Fly.io, SQLite cache, CI/CD, planning docs, Week 2 pivot.
- **Week 3 (Vulnerability lens v1):** ✅ shipped. Lockfile parser, OSV.dev integration, CVSS parsing, CycloneDX SBOM generation, `arguss scan` and `arguss sbom` CLI commands.
- **Week 4 (Trust signal lens v1):** ✅ shipped. npm registry client, maintainer data, Levenshtein typosquat detection, trust delta logic with four veto flags, `arguss trust-snapshot` and `arguss trust-delta` CLI commands.
- **Week 5 (Pipeline lens v1):** ✅ shipped. zizmor subprocess wrapper, test reality assessment, lens integration with severity-weighted-sum subscore + test-reality penalty, `arguss zizmor-scan` and `arguss pipeline-snapshot` CLI commands.
- **Week 6 (Fix-confidence engine + threat modeling):** in progress. FixCandidate and FixConfidence models, the fix-confidence engine (kill switch, idempotency key, audit trail, structured output), `arguss propose-fixes` CLI. Threat model written in parallel. Solution Design & Architecture Presentation due.
- **Week 7 (Request handler + observability):** request handler that ties the lenses and engine together for on-demand analysis. The first piece of the web service's real functionality. Escalation message generation via Claude (separate small PR). 5-point mid-point presentation.
- **Week 8 (Demo polish):** smooth the end-to-end flow, dry runs against the frozen Express fork, prepared inputs for fallback scenarios. Demo / Proof of Concept due.
- **Week 9 (Web UI build):** HTMX dashboard with the three input modes (URL, upload, URL+PAT). Reasoning panel showing the lens evaluations and fix-confidence verdicts. Mode C "do it" path for opt-in PR creation.
- **Week 10 (v2 enrichments):** EPSS, CISA KEV, OpenSSF Scorecard, CycloneDX SBOM export, persistent storage of decisions for replay. Reliability hardening (single-flight per repo, retry safety).
- **Week 11 (Evaluation):** the three demo scenarios reproduced; side-by-side comparison with Snyk and Dependabot on a real npm repo; tuning of fix-confidence score weights based on empirical results. 2-minute pitch.
- **Week 12 (Final deliverable):** project webpage, screenshots, backup demo video, UI polish, final docs. Final Project Deliverables Webpage due.
- **Week 13 (Dry run):** practice final presentation, incorporate instructor feedback.
- **Week 14 (Showcase):** joint final presentation, August 5, 2026.

## Where the intellectual core lives

The fix-confidence engine is the load-bearing piece. It's the function that takes the three lens outputs and produces a verdict the agent will trust. Its outputs include:

- A **tier** (AUTO_MERGE, REVIEW_REQUIRED, DECLINE) — the authoritative decision the agent reads
- A **score** (0–100) — for the dashboard and for empirical tuning in evaluation
- **Reasons** — human-readable explanations of why the verdict came out the way it did
- **Veto signals** — machine-readable IDs of which specific veto conditions fired
- **Audit context** — engine version and evaluation timestamp, so any verdict can be reconstructed after the fact

The engine is pure: it takes inputs and returns a value, with no I/O except a kill switch check. It supports an operator-level disable, an idempotency key on each candidate, and a structured `DECLINE` tier that's treated as a normal outcome (not an error).

Built carefully, the engine is the artifact a reviewer could engage with seriously. It's the answer to "how do you decide what's safe to do autonomously?"
