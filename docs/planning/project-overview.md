# Arguss — Autonomous npm Supply Chain Remediation

**MICS Capstone (CYBER 295) — Summer 2026**

*Sherbano Khan, Huiping Qiu (Sophia), Adrian Rosales*

---

## What we're building

Arguss is an autonomous remediation agent for npm supply chain vulnerabilities, delivered as an installable GitHub App. When installed on a repository, Arguss detects vulnerable dependencies, generates the fix, opens a pull request, waits for the repo's existing CI to verify it, and merges — but only when the fix falls inside a defensible confidence envelope. Outside the envelope, it escalates with a structured explanation and leaves the decision to a human.

## The wedge

Dependabot and Renovate already auto-PR dependency upgrades. They decide whether to act based on version availability, not risk: they will happily open and merge a PR for a malicious package the day after a maintainer takeover, because the new version is "newer." Arguss makes the autonomy decision based on a defensible risk model — trust signals over the upgrade window, transitive blast radius, and whether the repository's pipeline runs meaningful tests. We will open fewer PRs than Dependabot. Every PR we auto-merge will have a reason it was safe to merge without human review.

## Why this matters now

Agentic systems are increasingly writing, deploying, and updating production code. Detection-with-human-review is becoming commodity. The unsolved problem is not "find the vulnerability" — it is "act on the vulnerability autonomously, in a way the operator can defend." Recent supply chain attacks (xz-utils, recurring npm credential theft, the Solana ecosystem incidents) succeeded because the malicious code was not in the CVE database when adopted. A remediation agent that acts on version metadata alone would have merged those attacks. A remediation agent that gates on trust-signal stability would have escalated them. That is the contribution.

## How it works

Arguss combines three signals into a per-remediation **fix-confidence score**.

- **Vulnerability lens** — identifies what needs fixing. OSV.dev, GitHub Security Advisories, EPSS exploit prediction scores, CISA KEV flags.
- **Trust lens** — vetoes the auto-merge if maintainer count, ownership, or publish cadence changed during the upgrade window. npm registry, deps.dev, OpenSSF Scorecard, Levenshtein distance against top-1000 packages for typosquat detection.
- **Pipeline lens** — vetoes the auto-merge if the repository's CI does not run meaningful tests. zizmor for workflow analysis plus test-file heuristics.

### The auto-merge envelope

The default envelope we will defend:

> Patch and minor version bumps to known vulnerable packages, where trust signals are unchanged over the upgrade window, blast radius is bounded under a configurable threshold, the repository's CI runs real tests, and those tests pass.

Major version bumps, trust anomalies, unbounded blast radius, missing tests, or failing tests all escalate. The envelope is configurable; the default is conservative on purpose, and we will defend it empirically in evaluation.

## Deployment

Arguss is an installable GitHub App. The user installs it on a repository in one click. It runs on a hosted Fly.io service, receives webhooks on repository events, and acts using scoped GitHub App credentials. The bot has a named identity, commit signature, and an audit trail. The dashboard becomes an observability view of the agent's reasoning, not the primary UI — the primary UI is the pull request feed and the escalation queue.

## Evaluation

We will evaluate Arguss on a frozen-in-time fork of a recognizable mid-size npm project (current candidate: a forked older version of `expressjs/express`) carrying real historical CVEs. The fork is pinned to a commit roughly 12–18 months old so that real CVEs are present with known good fixes.

Metrics:

- **Auto-merge rate** on in-envelope fixes (% that merged cleanly)
- **Escalation correctness** on out-of-envelope fixes (when the agent declined, was it right to decline?)
- **False-merge rate** (any auto-merged PR that broke detectable downstream behavior)
- **Time-to-fix** vs. a Dependabot baseline running on the same repo

### Demo scenarios

Three reconstructed scenarios drive the demo:

1. **Hero case (Scenario A):** The agent auto-merges most of a CVE backlog cleanly, end-to-end, in roughly 2–3 minutes.
2. **"Agent knows what it doesn't know" (Scenario B):** A high-severity CVE requires a major version bump with breaking changes. The agent correctly declines and escalates with an explanation.
3. **Trust-signal save (Scenario C):** A patch-level CVE in a package whose maintainer changed last week. The agent escalates despite the low version delta, because trust signals flagged anomaly.

## Scope

One ecosystem (npm). One CI/CD platform (GitHub Actions). One deployment target (GitHub App on Fly.io). Prebuilt vulnerability data (OSV.dev). Lightweight observability UI. The engineering effort is concentrated on the agent loop, the fix-confidence engine, and the threat model for autonomous credentialed action — not on building a new scanner.

## Stack

- **Agent service:** Python with FastAPI, deployed on Fly.io
- **Caching:** SQLite (WAL mode) on a Fly.io volume
- **Credentialed action:** GitHub Apps API
- **Test orchestration:** the repository's own GitHub Actions
- **Escalation messages:** Anthropic's API (Claude) for generating the explanation when the agent hands a case to a human
- **Observability dashboard:** HTMX + Tailwind
