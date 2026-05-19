# Arguss — Threat Model

**Document status:** Draft (Week 6, May 2026). Requires team review and sign-off.

**Scope:** Threats to the Arguss autonomous remediation system and its operators, under the web-service deployment model. Covers the system's behavior across three input modes: read-only public repo analysis (Mode A), file upload (Mode B), and opt-in GitHub action via user-supplied PAT (Mode C).

**Out of scope:** General npm supply chain security (Arguss is a *response* to that, not a complete model of it), threats to the underlying GitHub platform, threats to npm registry infrastructure, threats to Fly.io's hosting infrastructure.

---

## What we're defending

Arguss is a web-based autonomous decision-making system for npm supply chain remediation. A user visits Arguss, provides a project (by URL, by file upload, or by URL + GitHub PAT), and receives a remediation plan with structured reasoning. When the user opts in via Mode C, Arguss can enact the plan: open pull requests against the user's repository using their token.

The system has:

- **Identity:** the Arguss web service, hosted on Fly.io. No bot accounts on GitHub; in Mode C, PR-opening actions happen under the user's own credentials.
- **Persistent credentials:** none per user. The service operates on per-session inputs only. User-supplied PATs (Mode C) are held in memory for the duration of the session and discarded afterward.
- **Server-side state:** a SQLite cache for OSV.dev responses, npm registry data, etc. No user data is cached; only third-party API responses keyed by package and version.
- **Authority:** when granted via Mode C, the authority to open PRs and (in some configurations) merge them. The authority is delegated, not inherited.

The defense surface is: **why is it safe to operate this system, and what happens when our assumptions are wrong?**

## Assumptions we rely on

Threat models live or die on their stated assumptions. We rely on the following; each one is something a reviewer could challenge:

1. **OSV.dev's advisory data is correct.** When OSV says a package version has CVE X with fixed-in version Y, we believe it. A compromise of OSV.dev would let an attacker fabricate fake CVEs that direct Arguss to "fix" by upgrading to malicious versions. We don't independently verify advisories.

2. **The npm registry's package metadata is correct and reasonably stable.** Maintainer lists, publish times, and download counts are what they say they are.

3. **GitHub's REST API behaves as documented.** PR-creation, branch-creation, and CI-status reads return real, current data. The infrastructure isn't lying about state.

4. **Our top-1000 popularity snapshot reflects real-world package popularity.** Search-derived snapshot with known limitations (documented in the trust lens design doc); we accept the gap as a bounded false-positive surface.

5. **The Arguss codebase itself is trustworthy.** Code reviews catch malicious changes before merge. The fix-confidence engine implements the conservative envelope we documented.

6. **Users who provide a PAT in Mode C understand what they're delegating.** The token is held in memory for the session and discarded. The user is consenting to the agent acting on their behalf via that token, within the session's analyses.

7. **Operators understand that Modes A and B are read-only.** Arguss doesn't act on the user's GitHub unless they explicitly opt into Mode C by providing a token.

These assumptions are explicit so that when one fails, we know what we lost.

## Threats

We identify eight threats, grouped by where they originate. Each entry has the form: threat → impact → likelihood → mitigations → residual risk.

### T1: Compromised upstream package

**Threat.** An attacker takes over a maintainer account on npm, publishes a malicious patch version of a popular package. Arguss sees a new version available, treats it as a candidate fix, and (if other signals look clean) recommends auto-merging — or, in Mode C, opens a PR and potentially merges it.

**Impact.** Critical in Mode C; significant elsewhere. In Mode C, a successful exploitation lets the malicious code reach the user's repo through the agent's own action. In Modes A and B, the agent merely *proposes* the merge — it doesn't enact — so the user has a chance to decline. But a confident-looking proposal can still mislead the user.

**Likelihood.** Medium. Maintainer compromise has happened on npm multiple times (the `event-stream`, `ua-parser-js`, and `node-ipc` incidents are public examples). The trust signal lens is specifically designed to detect this pattern.

**Mitigations.**

- **Trust delta veto.** The trust lens vetoes auto-merge if any of: ownership transfer (>50% of maintainers replaced), new maintainer added in upgrade window, cadence anomaly (publish much faster than historical), download collapse (>50% drop).
- **Conservative envelope by default.** The trust veto thresholds are tight on purpose; Week 11 evaluation will measure false-positive rate and tune.
- **Structured reasons in every verdict.** The audit trail records which trust signals justified each AUTO_MERGE decision. Post-incident, a compromised package's auto-merge can be retrospectively reviewed.

**Residual risk.**

- An attacker who takes over a maintainer's account but doesn't change identifiable signals (publishes under the existing identity with normal cadence) defeats the trust veto. Detecting this would require code-level analysis we don't perform.
- Packages with a single sole maintainer are systematically more vulnerable to this attack. We don't currently apply additional caution to them.

### T2: User-supplied PAT mishandling

**Threat.** In Mode C, the user provides a personal access token. Arguss must handle it correctly: don't log it, don't persist it, don't share it across sessions, don't transmit it anywhere unintended.

**Impact.** High. A leaked PAT can be used by an attacker to act on every repository the token has access to.

**Likelihood.** Low if handled correctly. Higher if logging, error reporting, or caching is sloppy.

**Mitigations.**

- **Session-scoped only.** The PAT is held in process memory for the duration of the user's session and discarded when the session ends. Not written to disk, not added to caches, not logged.
- **Token redaction in logs.** Application logs filter out anything matching common PAT patterns (e.g., `ghp_`, `github_pat_`) before writing. Errors surfaced to the user include the PAT being masked.
- **Outbound transmission only to api.github.com.** The PAT is used exclusively as a header on requests to GitHub's REST API. No other destinations.
- **No PAT in URL query strings.** GitHub's API supports both query-string and header authentication; we use only the header form to prevent leakage via web server logs.
- **Scoped tokens encouraged.** UI/documentation directs users to create tokens with minimum scope (`repo` for the specific repo, not org-wide).

**Residual risk.**

- A user who provides a token with broader scope than necessary (e.g., a classic PAT with all repos accessible) accepts that broader exposure. We educate but cannot enforce token scoping.
- A memory snapshot or compromised process could expose the PAT during the session. This is true of any service that holds credentials in memory; the mitigation is process isolation.
- If the user re-uses the same PAT across sessions, our session-scoped handling doesn't protect against attacks that happened in a different session.

### T3: Malicious lockfile input

**Threat.** A user uploads (Mode B) or points Arguss at (Mode A) a malicious or malformed lockfile designed to crash the parser, exploit a parsing bug, or trigger excessive resource consumption.

**Impact.** Low to medium. A crash takes down a single session. A parsing bug could in theory allow arbitrary code execution; standard JSON parsers don't have that surface. Resource exhaustion could DoS the service.

**Likelihood.** Low for malicious-by-design payloads; medium for genuinely malformed lockfiles (which are common in the wild).

**Mitigations.**

- **JSON parsing only.** No `eval`, no dynamic code execution. The parser handles structured data, not arbitrary JavaScript.
- **Bounded resources.** The parser has reasonable limits on graph depth, total dependency count, and per-field size. Pathological inputs are rejected with a clear error rather than processed.
- **Strict format validation.** The parser only accepts `lockfileVersion: 3` and surfaces clear errors for older or non-conforming formats.
- **Sandboxed parsing.** The web service runs in a containerized environment with limited filesystem and network access. A parser exploit can't trivially reach user data or production secrets.

**Residual risk.**

- A novel vulnerability in `json.loads` itself, or in our parsing logic, could let a crafted lockfile cause unexpected behavior. We rely on standard library hardening.
- Genuinely malformed lockfiles produce errors visible to the user, but the user might not understand them. Operational issue, not security.

### T4: Attacker-controlled repository URL

**Threat.** In Mode A, the user provides a GitHub repo URL. An attacker could craft a URL that points to attacker-controlled content (e.g., a malicious fork) and trick the user (or trick the Arguss service) into analyzing it.

**Impact.** Low. The user is choosing what to analyze; if they point at a malicious repo, they've made a security mistake but Arguss isn't the attack vector — they could equally well clone the repo themselves and run any tool against it. Arguss's analysis itself doesn't introduce new risk because we only *read* the repo's lockfile and workflows.

**Likelihood.** Low. Requires the user to be deceived about what they're analyzing.

**Mitigations.**

- **Read-only operations in Mode A.** Arguss fetches the lockfile and workflows via the public GitHub API; it doesn't execute anything from the repo.
- **No code execution from repo contents.** Even if a malicious lockfile or workflow file contains shell-like content, Arguss processes it as structured data only.
- **Clear repo identity in the UI.** The user sees the exact URL they provided in the analysis output. No URL rewriting or redirection.

**Residual risk.**

- A user could be tricked into analyzing a malicious repo and then trusting Arguss's verdict on it. Arguss's analysis is honest; the user's interpretation of the results is theirs. This is an education issue, not a vulnerability.

### T5: CI subversion

**Threat.** A repository's CI is configured to always pass (e.g., test commands wrapped with `|| true`, or no test job at all). In Mode C, the agent observes "tests pass" and auto-merges a fix that breaks production.

**Impact.** High in Mode C. The "auto-merge after CI passes" guarantee evaporates if CI doesn't actually verify anything.

**Likelihood.** Medium. Many repos in the wild have weak or theater-only CI.

**Mitigations.**

- **Test reality assessment.** The pipeline lens checks four conditions: `package.json` has `scripts.test`, the script isn't a no-op (matches known sentinels), the repo has test files, the workflow actually runs the test command. All four must hold for `safe_to_auto_merge=True`.
- **Documented known false positives.** `tsc --noEmit` passes our heuristic but isn't testing. We accept this v1 limitation; it surfaces in escalation messages.
- **No-op sentinel matching.** Conservative pattern matching catches the obvious "echo 'no tests'" and "exit 0" patterns.

**Residual risk.**

- A repo with a real test runner that *happens to pass for the agent's specific fix* but doesn't exercise the affected code paths defeats our heuristic. We assume real tests exercise real code; this is just an assumption.
- CI theater patterns more sophisticated than `|| true` or `exit 0` (e.g., conditional test execution, environment-dependent test selection) are not detected.

### T6: Replay and idempotency in Mode C

**Threat.** In Mode C, the agent retries a fix after a transient failure (network error, GitHub API rate limit) and accidentally opens duplicate PRs or merges the same fix twice.

**Impact.** Low to medium. Duplicate PRs are confusing but recoverable. Double-merges of the same change are no-ops (Git handles this fine). Double-merges of different changes that look the same are dangerous but rare.

**Likelihood.** Low for one-off Mode C sessions; higher for repeated automation against the same repo.

**Mitigations.**

- **Idempotency key.** Every `FixCandidate` has a stable `candidate_id` derived from (package, from_version, to_version, source_finding_id, repo_id). The Mode C action layer will check this ID before acting.
- **Branch-naming convention.** Auto-merge PRs use deterministic branch names (e.g., `arguss/fix-{candidate_id}`). A retry with the same candidate_id targets the same branch.
- **PR-existence check.** Before opening a new PR, check if one already exists for this candidate_id; if so, take no action.

**Residual risk.**

- Two distinct vulnerabilities that map to the same patch produce the same candidate; if the first PR was rejected, the retry inherits the rejection. This is the right behavior, but the operator might not realize what happened.

### T7: Arguss server compromise

**Threat.** An attacker compromises the Arguss service running on Fly.io — either through application code, a dependency, or the hosting infrastructure. They can now influence the analyses Arguss produces and potentially see user sessions in progress.

**Impact.** High. A compromised server can mislead users with bad verdicts, or use in-memory PATs (Mode C sessions in progress) to take actions on user repos.

**Likelihood.** Low for a small project; rises with adoption.

**Mitigations.**

- **Minimal attack surface.** The web service exposes only the analysis endpoints. No public administrative interface, no remote shell, no remote configuration.
- **Stateless across sessions.** Compromising the service doesn't give the attacker access to historical user data because we don't store user data. The SQLite cache holds only third-party API responses.
- **Code review for every change.** Pull requests to the Arguss repo require review by another team member. Malicious changes are visible.
- **Engine version tagging.** Every `FixConfidence` records the engine version that produced it. A version bump with weakened thresholds shows up in the audit trail immediately.
- **Kill switch.** The fix-confidence engine supports an operator-level disable (via environment variable or sentinel file) that halts all auto-merge recommendations without requiring a code change.
- **Dependency hygiene.** Arguss has dependencies of its own (Python packages). We monitor for known CVEs in them; future enhancement: run Arguss against itself.

**Residual risk.**

- An attacker who controls the Arguss service and acts within an active Mode C session has access to the user's PAT for the session's duration. The user has no recourse beyond their session ending.
- A subtle, long-lived attacker who lands many small "improvements" that each pass review but collectively weaken the envelope is hard to defend against. We rely on the visible code-review culture and the small team size.

### T8: Anthropic API compromise / prompt injection

**Threat.** Arguss uses the Anthropic API to generate escalation messages for human reviewers. A malicious CVE description (or other input fed into a prompt) injects instructions that produce misleading guidance.

**Impact.** Low. The AI-generated text is *read by a human*, not acted on by the agent. A reviewer who sees suspicious or contradictory advice will investigate.

**Likelihood.** Low. CVE descriptions are typically vetted before publication; injection-style payloads are obvious.

**Mitigations.**

- **AI output is never on the auto-merge path.** The engine's `tier` is determined by structured signal evaluation; the AI is only used to summarize *why* a particular tier was chosen, for human consumption.
- **Bounded scope.** The AI is given only the specific CVE description, the fix candidate, and the veto signals. It doesn't get the full repository or arbitrary external content.
- **Human-in-the-loop on escalation.** By definition, an escalated PR is one a human reviews. Misleading AI text is a usability problem, not an action problem.
- **Strict separation between engine and presenter.** The Claude integration lives in a separate module (`arguss/engine/explanation.py`, planned for Week 7+) so the engine's purity isn't affected by AI behavior.

**Residual risk.**

- A reviewer who blindly trusts the AI-generated explanation without verifying could be misled. The mitigation is operator education and clear UI presentation; we accept that some operators will be careless.

## Mitigations summary

The mitigations above include several design constraints that land in the Arguss codebase. The fix-confidence engine (Week 6, PR 1) implements four of them as foundational features:

| Constraint | Threats addressed | Where it lands |
|---|---|---|
| Kill switch (env var + file path) | T7 | `arguss/engine/kill_switch.py` |
| Idempotency key on FixCandidate | T6 | `FixCandidate.candidate_id` |
| Audit trail (engine version, evaluated_at) | T1, T7 | `FixConfidence` fields |
| DECLINE as first-class output | T1, T5 | `FixTier.DECLINE` |

Other mitigations live in earlier or later layers:

- Trust delta vetoes (T1) → `arguss/lenses/trust.py` (shipped Week 4)
- Test reality assessment (T5) → `arguss/lenses/pipeline.py` (shipped Week 5)
- Bounded lockfile parsing (T3) → `arguss/core/parser.py` (shipped Week 3)
- Session-scoped PAT handling (T2) → Week 9 web UI
- PAT redaction in logs (T2) → Week 9 web UI
- PR-existence check (T6) → Week 7 action layer
- Branch-naming convention (T6) → Week 7 action layer
- Code review culture (T7) → process, not code

## Residual risk we accept

Even with all mitigations in place, we accept residual risks. Documenting them is part of the threat model's job — these are the risks an operator inherits when they use Arguss.

1. **An attacker who compromises a maintainer's account but doesn't change identifiable signals** (T1 residual). The trust lens won't catch this. Code-level analysis would, but we don't perform it.

2. **A user whose PAT is exposed during an active Mode C session if our process is compromised** (T2 residual). Session memory contents are at risk during an active server compromise.

3. **CI theater patterns more sophisticated than our heuristic** (T5 residual). The pipeline lens catches the obvious cases; the subtle ones get through.

4. **The known false positives in our trust and pipeline lenses** (documented separately). These don't represent security risk; they represent agent unhelpfulness (we escalate when we could have auto-merged). Recoverable.

5. **Our reliance on OSV.dev** (Assumption 1). A compromise of OSV's data would mislead the agent. We don't independently verify advisories.

6. **Users who provide broader-scoped PATs than necessary** (T2 residual). Education problem, not enforceable.

## Operational guidance

For an operator using Arguss in Mode C, the threat model translates to practical guidance:

- **Use scoped PATs.** Create a token with `repo` scope on the specific repository you want analyzed, not an organization-wide token. Revoke tokens when done.
- **Review the first proposal carefully.** Confirm the agent's reasoning matches what you expect before approving auto-merges.
- **Watch for engine version changes in the audit trail.** A version bump is a moment to verify the new defaults haven't loosened the envelope unexpectedly.
- **Don't disable the trust veto thresholds without a documented reason.** They're conservative on purpose; loosening them moves risk from us to you.
- **Treat escalations as designed signal, not noise.** When the agent declines to auto-merge, that's the system telling you a human eye is needed.
- **For Mode A and B users:** the agent's verdict is advisory only. You decide whether to act on the proposed changes.

## Open questions

These are unresolved and documented for future work:

- **What's our policy on auto-merging into security-sensitive packages?** Packages with `security` in their name, packages tagged as security-critical by community lists — should they get a stricter envelope?
- **How do we handle a repository where the agent's previous auto-merge caused a problem?** A learned penalty system could exist; we don't have one in v1.
- **What about transitive vulnerabilities that we can't fix directly?** A CVE in a transitive dep where the direct dep pins the vulnerable version is harder; we don't currently propose forking or patching.
- **What's our supply chain for Arguss itself?** Arguss has dependencies (Python packages); compromising those compromises us. We don't yet run Arguss against Arguss (a Week 10+ candidate).
- **Persistent storage of decisions for replay?** Currently no decisions are stored across sessions. Week 9-10 reliability hardening will revisit.

---

**Team sign-off**

- [ ] Sherbano Khan
- [ ] Huiping Qiu (Sophia)
- [ ] Adrian Rosales

**Revision history**

- 2026-05-18: Initial draft under GitHub App deployment framing (Adrian Rosales)
- 2026-05-19: Revised for web service + opt-in GitHub action framing; dropped T2/T4 from prior version (compromised App credentials, malicious user installation), added T2/T3/T4/T7 for new deployment shape (PAT mishandling, lockfile input, attacker URL, server compromise), updated mitigations summary
