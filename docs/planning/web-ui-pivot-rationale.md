# Arguss — Web UI Pivot Rationale

**Date:** May 18, 2026 (Week 6 of 14)

**Status:** Adopted — team decision made verbally; this document is the written record

**Authors:** Adrian Rosales (with input from Sherbano Khan and Huiping Qiu)

---

## Why this document exists

We are making a second pivot. The Week 2 pivot reshaped Arguss from "three-lens scanner" to "autonomous remediation agent" — a sound decision the team committed to in writing. The work since then has been building toward that vision.

This pivot is narrower but real. Arguss remains an autonomous remediation system. What changes is *how it's delivered*: instead of an installable GitHub App that lives inside user repositories and acts continuously, Arguss becomes a web service users visit on demand, with optional GitHub integration when they want to enact what Arguss proposes.

This document records what's changing, what's preserved, why the new direction is stronger, and how the team responded to the previous pivot's commitments under the new shape.

## The realization

The Week 2 pivot rationale committed us to a GitHub App deployment because it produced the most concrete demo: "install the bot, watch it open PRs, see autonomous action in real time." That logic still holds for the *experience* — but the *deliverable* has a problem we underweighted: a demo where all the action happens inside GitHub's PR interface is functional but visually weak. A reviewer watching a 5-minute demo wants to see something happen on a screen they can examine and ask questions about. A list of bot-authored PRs in GitHub's standard UI doesn't lend itself to that.

The realization, in one sentence:

> *Autonomous decision-making and autonomous action are separable. Arguss's contribution is the decision-making (the fix-confidence engine, the three-lens veto logic). The action layer is a deployment choice, not a product feature.*

Once you accept that framing, the GitHub App is one possible action layer among several. A web UI that presents the agent's proposed plan is another. The two aren't in opposition — a web UI can optionally enact via the user's credentials when they consent.

## What we're keeping

- **Project name:** Arguss
- **The three lenses:** vulnerability, trust signals, pipeline — all shipped (Weeks 3–5)
- **The fix-confidence engine:** the agent's decision logic — shipped (Week 6 PR 1)
- **The auto-merge envelope:** patch + minor + trust unchanged + bounded blast radius + tests pass
- **The intellectual core:** autonomous decision-making with a defensible risk model
- **All shipped code:** the lenses, the engine, the CLI, the parsers, the clients — everything runs identically regardless of deployment shape
- **The scope discipline:** npm, GitHub Actions, OSV.dev
- **The Fly.io deployment:** the service still runs there, just exposes different things
- **The threat model framework:** revised but the structure carries over

## What's changing

| Aspect | Before (Week 2 pivot) | After (Week 6 pivot) |
|---|---|---|
| **Deployment** | Installable GitHub App on user repos | Web service users visit; GitHub integration is opt-in per session |
| **Trigger model** | Webhook-driven, continuous, background | User-initiated, on-demand |
| **Credentials** | Long-lived GitHub App credentials per installation | Per-session, user-supplied PAT only when user opts to enact |
| **Primary UI** | Pull request feed in GitHub itself | Web UI on the Arguss service |
| **Action authority** | Bot acts autonomously without per-action consent | User reviews proposed plan; optionally clicks "do it" |
| **Demo surface** | Live install + GitHub PR feed | Live web UI showing the agent's reasoning |
| **Threat model shape** | Long-lived credentials, persistent installations, malicious-user concerns | Per-session inputs, user-supplied PATs, attacker-controlled inputs |
| **Week 7 work** | Agent loop driven by webhooks | Request handler producing on-demand plans |
| **Week 9 work** | GitHub App registration, OAuth, webhooks, scoped credentials | Web UI build, GitHub API integration, optional PR creation |

## The three input modes

The web UI accepts three input shapes, each enabling progressively more capability:

**Mode A — Repo URL (read-only).** User pastes a public GitHub repo URL. Arguss fetches the lockfile and workflows via the GitHub API, runs the three lenses, computes fix-confidence for each candidate, displays the proposed plan. Touches nothing in the user's repo. This is the primary demo flow.

**Mode B — File upload (offline).** User uploads `package-lock.json` (required); optionally `.github/workflows/` and `package.json`. Each additional upload unlocks more of the analysis. Useful for private repos the user can't share by URL.

**Mode C — Repo URL + PAT (opt-in action).** User provides a token. The agent can analyze *and* enact: open real PRs against the repo, with user consent on each one. This is "actually do it" mode.

All three modes share the same engine — the differences are purely in input/output handling.

## Why this is a stronger project, not just a different one

**Better demo.** The web UI lets us put the agent's reasoning on screen in a way GitHub's PR interface can't. We can visualize the three-lens evaluation, the fix-confidence score, the veto signals that fired. A reviewer can see "here's *why* the agent decided to escalate this one" in a way that a list of PRs in GitHub doesn't communicate.

**Simpler threat model.** Most of the Week 2 threat model concerns — compromised App credentials, malicious user installations, long-lived secret rotation — evaporate. The agent doesn't hold long-lived credentials. Each session uses fresh inputs the user provides. New threats appear (malicious lockfile input, PAT handling, attacker-controlled repo URLs) but they're shallower and more familiar.

**Wider demo range.** Mode A means we can demo against any public repo on the spot. The GitHub App version required installation, which means demo prep tied to specific repos. The web UI is point-and-go.

**Honest about what's agentic.** The Week 2 framing called Arguss "autonomous." Under the App model, *both* decision-making and action were autonomous. Under the web UI model, decision-making is autonomous (the engine still decides without human judgment) but action is conditionally autonomous — the user delegates by providing a token. That's a more honest description of what's happening and what we can defend.

**Closer to how supply chain analysis tools actually get used.** The category of tools like Snyk, Socket.dev, and Endor Labs are mostly web services users visit, not always-on agents. Arguss fits that category more naturally as a web UI than as a GitHub App, while still differentiating on autonomous decision-making.

## What this is *not*

Worth being explicit:

- **This is not a retreat from the agentic framing.** The fix-confidence engine still makes autonomous decisions. The auto-merge envelope is unchanged. The "agent knows what it doesn't know" framing carries over directly. What's different is who initiates the work.
- **This is not abandoning the Week 2 pivot.** The remediation focus, the three-lens veto logic, the comparison to Dependabot's risk-blind auto-PR pattern — all preserved. We are not going back to "three-lens scanner with explanations."
- **This is not a UI change.** The dashboard from the original 5W1H was a secondary observability view. Under the Week 2 pivot the dashboard demoted further. Under this pivot the web UI becomes the *primary* surface. Different change.

## What we are giving up

- **The "install and watch the bot work" demo moment.** Replaced by "watch the agent's reasoning on screen and optionally enact." Different shape, arguably more legible.
- **The bot identity in commit history.** Under the new model, when the user clicks "do it," the PR is opened by their own credentials. No named bot persona. Trade-off: less brand recognition for the agent, more honesty about who's acting.
- **The "agent runs continuously without my involvement" story.** Replaced by "agent runs when I ask it to." Less impressive in some framings, more controllable in others.
- **Some Week 9 deployment infrastructure work** that would have been spent on App registration, OAuth flows, and webhook handling. That budget shifts to web UI build instead.

These cuts are accepted on net because the demo gains and threat-model simplification compensate.

## Why now is the right time (again)

- **Week 6 is early enough that the Week 7+ plan can be revised without invalidating shipped work.** The Week 6 PR 1 engine work explicitly assumes nothing about deployment shape — by deliberate design.
- **Five weeks of shipped code survives unchanged.** The lenses, the engine, the parsers, the CLI all live below the deployment-model boundary. The web UI build in Week 9 sits *on top* of this foundation, not in place of it.
- **The Solution Design & Architecture Presentation is due this week.** Locking in the deployment shape now means the presentation reflects the actual direction, not a stale plan.

## What we're worried about (and how we'll mitigate it)

**Pivot fatigue.** This is the second pivot. Two pivots in five weeks is a real pattern. Mitigation: this document. The Week 2 pivot survived because it was justified in writing; this one needs to do the same. Any future pivot would require the same threshold — written rationale, team sign-off, clear preservation of prior work.

**Demo regression.** We're giving up a concrete demo shape (install + watch) for a less-tested one (web UI + reasoning panel). Mitigation: we have Modes A, B, and C as different demo paths. The hero demo is Mode A on a frozen Express fork; if the web UI has any bugs, we can fall back to Mode C with prepared inputs.

**Web UI build cost.** Building a dashboard from scratch in Week 9 has more visual-polish risk than wiring webhooks. Mitigation: HTMX + Tailwind is intentionally low-ceremony; we don't need a polished SPA, we need a functional reasoning panel. The original plan called for HTMX anyway.

**"This is just a scanner with extra steps."** A skeptical reviewer might frame the web UI version as "Snyk with a confidence score." Mitigation: keep the autonomous-decision framing prominent. The fix-confidence engine is the differentiator, not the UI. Mode C demonstrates real autonomous action.

## What about the Week 2 commitments?

The Week 2 pivot rationale had five sign-off items. The status of each under this pivot:

1. **New product framing (autonomous remediation agent):** preserved. Decision-making is still autonomous.
2. **Auto-merge envelope:** preserved exactly. Same envelope, same defaults.
3. **Deployment model (GitHub App on Fly.io):** changed. Now: web service on Fly.io with optional GitHub integration.
4. **Revised 14-week plan:** revised again (see updated project overview).
5. **Evaluation framing (vs. Dependabot):** updated to multi-comparison (see updated project overview).

Three out of five preserved. Two updated. The intellectual core is intact.

## Decision

By signing off on this document, the team agrees to:

1. The shift from GitHub App deployment to web UI primary with opt-in GitHub action
2. The three input modes (URL, file upload, URL+PAT) as the user-facing entry points
3. The corresponding shifts in Week 7 (request handler) and Week 9 (web UI build) work
4. The multi-comparison evaluation framing (Snyk for detection, Dependabot for action, manual review for prioritization)
5. That this is the second and intended-final pivot — further direction changes require a written rationale at this same level of rigor

---

**Sign-off:**

- [ ] Sherbano Khan
- [ ] Huiping Qiu (Sophia)
- [ ] Adrian Rosales

**Revision history**

- 2026-05-18: Initial draft (Adrian Rosales)
