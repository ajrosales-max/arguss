# Arguss — Threat Model

**Document status:** Revision 3 (June 2026). Supersedes the Week 6 draft. Requires team review and sign-off.

**Scope:** Threats to the Arguss autonomous remediation system and its operators, under the deployed web-service model at arguss.fly.dev. Covers the system's behavior across three input modes: read-only repo analysis (Mode A), file upload (Mode B), and opt-in GitHub action via user-supplied PAT through the action wizard (Mode C). This revision documents the system **as built and deployed**, including the wizard session layer, the server-side scan cache, and the expanded AI presentation surface — not the system as planned in Week 6.

**Out of scope:** General npm supply chain security (Arguss is a *response* to that, not a complete model of it), threats to the underlying GitHub platform, threats to npm registry infrastructure, threats to Fly.io's hosting infrastructure.

---

## What we're defending

Arguss is a web-based autonomous decision-making system for npm supply chain remediation. A user visits Arguss, provides a project (by URL, by file upload, or by URL + GitHub PAT), and receives a remediation plan with structured reasoning. When the user opts in via Mode C, Arguss enacts the plan by opening pull requests against the user's repository using their token.

The system has:

- **Identity:** the Arguss web service, hosted on Fly.io (single machine, region dfw), gated by HTTP Basic auth in the current demo posture. No bot accounts on GitHub; in Mode C, PR-opening actions happen under the user's own credentials.
- **Per-user credentials:** none persisted. User-supplied PATs (Mode C) are held in memory for the duration of the action and discarded. They are never written to the database, the cache, or logs (enforced by a log filter and a regression test).
- **Service-level credentials:** the service itself holds secrets in its deployment configuration — the Anthropic API key (explanation prose), the demo Basic-auth password, and an optional read-only `ARGUSS_GITHUB_TOKEN` used solely by Mode A's repository crawl to avoid shared-IP rate exhaustion. A guard test asserts the service token is never referenced on the credentialed action path.
- **Server-side state (revised — this is the largest change since the Week 6 draft):**
  - **Scan cache:** SQLite (WAL mode, persistent Fly volume) stores *full serialized scan results* — findings, candidates, verdicts, dependency lists, Claude-generated executive summaries — keyed by scan hash, plus third-party API responses (OSV, npm registry, deps.dev, Scorecard, EPSS) with per-source TTLs. The earlier claim that "no user data is cached" is no longer accurate and is withdrawn.
  - **Wizard sessions:** the Mode C action wizard (Assessment → Select → Authorize → Process) persists session state in SQLite, keyed by an HttpOnly, SameSite=Lax cookie with a 1-hour TTL. A separate `last_scan_hash` recovery cookie (30-day TTL) restores users to their assessment after expiry. Sessions survive machine restarts. **The PAT is not part of persisted session state.**
  - **Action records:** completed Mode C runs are recorded and viewable at a permalink (`/results/{action_id}`), including per-PR outcomes.
  - A cache schema version gates all stored payloads; entries written under an older schema are treated as misses and recomputed.
- **Authority:** when granted via Mode C, the authority to **open pull requests** for AUTO_MERGE-tier candidates. The current implementation never merges; merging remains a human action. (The original design contemplated merge-after-CI within the envelope; that loop is not in the deployed system. If it ships later, this document must be revised first — see Open questions.)

The defense surface is: **why is it safe to operate this system, and what happens when our assumptions are wrong?**

## Assumptions we rely on

1. **OSV.dev's advisory data is correct.** When OSV says a package version has CVE X with fixed-in version Y, we believe it. A compromise of OSV.dev could direct Arguss to "fix" by upgrading to malicious versions. We don't independently verify advisories.

2. **Enrichment sources are correct: EPSS scores, CISA KEV listings, deps.dev metadata, and OpenSSF Scorecard results.** All are display/prioritization signals. None gate the auto-merge verdict, so a compromise misleads humans but cannot widen the action envelope.

3. **The npm registry's package metadata is correct and reasonably stable.** Maintainer lists, publish times, and download counts are what they say they are.

4. **GitHub's REST API behaves as documented.** PR-creation, branch-creation, and repository reads return real, current data.

5. **Our top-1000 popularity snapshot reflects real-world package popularity.** Known limitations documented in the trust lens design doc; accepted as a bounded false-positive surface.

6. **The Arguss codebase itself is trustworthy.** Code reviews catch malicious changes before merge. The fix-confidence engine implements the conservative envelope we documented.

7. **Users who provide a PAT in Mode C understand what they're delegating.** The wizard's consent step states what Arguss will do (open PRs for AUTO_MERGE candidates only, never merge, never act outside the envelope) and that the PAT is session-only.

8. **Everyone behind the demo Basic-auth credential is mutually trusted.** Cached scan results, action records, and wizard recovery are shared within that boundary (see T9). This is acceptable for the capstone demo posture and would NOT be acceptable for a public multi-tenant deployment.

9. **Operators understand that Modes A and B are read-only.** Arguss doesn't act on the user's GitHub unless they explicitly complete the Mode C wizard with a token.

## Known limitations (tracked, not hidden)

A threat model that names its own gaps is more defensible than one that doesn't. These are open items in the engineering backlog, stated here so reviewers see them in context:

- **The user-supplied ref is not honored on clone.** Mode A and Mode C accept a ref, record it, and display it — but the clone always fetches the default branch. For Mode C this is a correctness bug in a credentialed write path (the analysis and PRs target the default branch regardless of the requested ref). Tracked for fix before any non-default-ref use; the demo uses default branches exclusively.
- **Clones are unauthenticated.** `git clone` uses the plain public URL; private repositories are unsupported even in Mode C. If PAT-authenticated cloning ships, the clone command line must be excluded from logging (the PAT would be URL-embedded).
- **CI theater beyond our heuristic** (see T5 residual) and **identity-preserving maintainer compromise** (see T1 residual) remain undetected by design.

## Threats

Nine threats, grouped by origin. Each entry: threat → impact → likelihood → mitigations → residual risk.

### T1: Compromised upstream package

**Threat.** An attacker takes over a maintainer account on npm and publishes a malicious patch version of a popular package. Arguss sees a new version available, treats it as a candidate fix, and (if other signals look clean) recommends auto-merging — or, in Mode C, opens a PR for it.

**Impact.** High in Mode C: the malicious upgrade arrives in the user's repo as a professional-looking PR opened on their behalf, carrying Arguss's confidence framing. The user still merges by hand, but the proposal's authority increases the chance they merge without scrutiny. Significant in Modes A and B, where a confident-looking proposal can mislead.

**Likelihood.** Medium. Maintainer compromise has happened on npm repeatedly (event-stream, ua-parser-js, node-ipc). The trust signal lens is specifically designed to detect this pattern.

**Mitigations.**

- **Trust delta veto.** The trust lens vetoes auto-merge on: ownership transfer, new maintainer in the upgrade window, cadence anomaly, download collapse. A veto removes the candidate from the set Mode C will act on.
- **Conservative envelope by default.** Veto thresholds are tight on purpose; Week 11 evaluation measures the false-positive cost.
- **Structured reasons in every verdict.** The audit trail records which signals justified each AUTO_MERGE; engine version is stamped on every verdict.
- **Typosquat detection** (Levenshtein against the top-1000 snapshot) covers the adjacent attack of confusable package names.

**Residual risk.**

- An attacker who publishes under an existing maintainer identity with normal cadence defeats the trust veto. Detecting this requires code-level analysis we don't perform.
- Sole-maintainer packages are systematically more exposed; we apply no additional caution to them in v1.

### T2: User-supplied PAT mishandling

**Threat.** In Mode C, the user provides a personal access token through the wizard's Authorize step. Arguss must not log it, persist it, share it across sessions, or transmit it anywhere unintended.

**Impact.** High. A leaked PAT can act on every repository within the token's scope.

**Likelihood.** Low as implemented; the controls below are shipped and tested, not planned.

**Mitigations (all shipped).**

- **Action-scoped, in-memory only.** The PAT lives in process memory for the duration of the action. It is not part of the persisted wizard session, not written to the scan cache or action records, and absent from the recovery-cookie flow.
- **Log redaction, tested.** A logging filter scrubs PAT patterns (`ghp_`, `github_pat_`, bearer tokens) from messages and structured fields; a regression test runs a full mocked action and asserts no log record contains the token. New action-path log lines carry only repo/ref/action-id metadata by construction.
- **Header-only transmission to api.github.com.** Every GitHub call on the action path authenticates via request header through a client constructed with the PAT; an audit of all call sites is recorded in the observability PR. No query-string auth.
- **Service-token separation.** The read-only service `ARGUSS_GITHUB_TOKEN` (Mode A crawls) is configured through the settings layer; a guard test asserts the action path never references it. The two credential planes cannot cross.
- **Fine-grained PAT guidance.** The UI directs users to fine-grained tokens scoped to the single target repository with exactly Contents: Read+write and Pull requests: Read+write, with a short expiry. Token-creation links pre-fill these permissions.
- **Failure honesty.** Authentication and rate-limit failures are mapped to distinct user-facing errors (invalid PAT / insufficient scope / rate limit with reset time / not found), so users aren't induced to retry with broader tokens to "fix" a misdiagnosed error.

**Residual risk.**

- A user who supplies a broader token than necessary accepts that exposure; we educate but cannot enforce.
- A compromised process can read the PAT during an active action (true of any service holding credentials in memory); see T7.

### T3: Malicious uploaded input (Mode B)

**Threat.** A user uploads a malicious or malformed lockfile, package.json, or workflows zip designed to crash the parser, exploit a parsing bug, or exhaust resources.

**Impact.** Low to medium. A crash takes down a request. Resource exhaustion could DoS the single-machine service.

**Likelihood.** Low for malicious-by-design payloads; medium for genuinely malformed files.

**Mitigations.**

- **JSON parsing only; no code execution.** Lockfiles and package.json are processed as structured data.
- **Upload size limits** enforced per field with explicit 413 responses.
- **Format validation.** lockfileVersion 2 and 3 are accepted; other versions are rejected with a styled, explanatory error rather than processed on a best-effort basis.
- **Zip handling bounded** for the optional workflows archive; archive contents are parsed as YAML/text, never executed.
- **zizmor runs as a subprocess against workflow *files*,** not against anything executable; its JSON output is parsed defensively (unknown severities normalized).
- **Containerized service** with limited filesystem scope.

**Residual risk.**

- A novel vulnerability in the standard JSON/zip/YAML parsing stack or in zizmor itself could let crafted input cause unexpected behavior. We rely on upstream hardening and version pinning.

### T4: Attacker-controlled repository URL (Modes A and C)

**Threat.** The user provides a GitHub repo URL. Since the pivot, Mode A doesn't only call the GitHub API — the service performs a **server-side shallow clone** of the named repository onto its own disk. An attacker-chosen URL therefore causes the server to fetch attacker-controlled content.

**Impact.** Low to medium. Repo contents are read as data (lockfile, workflow files), never executed. The new surface relative to the Week 6 draft is resource consumption: very large repositories, slow remotes, or pathological git objects consume server disk, bandwidth, and time on a single shared machine.

**Likelihood.** Low for deliberate attack; medium for accidental (users pointing at enormous monorepos).

**Mitigations.**

- **Shallow, single-branch clone** (depth 1) bounds transfer size.
- **Clone timeout** with a distinct 504 mapped to a clear user message.
- **No execution of repo contents.** Workflows are analyzed by zizmor as text; install scripts are never run; `npm install` is never invoked.
- **Structured clone-failure taxonomy** (timeout / git-binary-missing / not-found) with logging, so anomalous clone behavior is visible rather than collapsed into a generic error.
- **Clear repo identity in the UI** — the canonical owner/repo derived from the URL is what's displayed and what keys the scan.

**Residual risk.**

- Disk-pressure or bandwidth abuse through repeated large-repo scans is rate-limited only by Basic auth and single-machine capacity. Acceptable at demo scale; a public deployment needs per-client quotas.

### T5: CI subversion

**Threat.** A repository's CI is configured to always pass (test commands wrapped with `|| true`, or no test job at all). The agent's "this repo can verify fixes" judgment is wrong, and auto-merge-tier recommendations rest on test theater.

**Impact.** High for the trustworthiness of AUTO_MERGE verdicts. (Lower than the Week 6 framing in one respect: since the deployed system opens PRs but never merges, a wrong test-reality judgment produces over-confident *recommendations*, not unreviewed merges.)

**Likelihood.** Medium. Weak CI is common in the wild.

**Mitigations.**

- **Four-condition test-reality rule:** test script present in package.json, script is not a no-op (sentinel matching), real test files exist, the workflow actually invokes tests. Failing any condition fires a project-level veto: nothing in the repo is eligible for AUTO_MERGE.
- **The veto is global and visible.** Demo target bootstrap-npm-starter exists specifically to show this behavior.
- **Workflow Security score is decoupled from the veto** and the UI states it explicitly ("informs project risk; does not veto fixes — test verification does"), preventing operators from misreading zizmor findings as the action gate.

**Residual risk.**

- Real test suites that don't exercise the affected code paths pass the heuristic.
- CI theater more sophisticated than sentinel patterns (conditional execution, environment-gated tests) is not detected. Documented false positive: `tsc --noEmit` passes the heuristic but isn't testing.

### T6: Replay and idempotency in Mode C

**Threat.** The agent retries after a transient failure (network error, rate limit, machine restart mid-action) and opens duplicate PRs.

**Impact.** Low to medium. Duplicate PRs are confusing but recoverable.

**Likelihood.** Low per session; the deployed environment makes restarts realistic (the Fly machine can stop mid-wizard and cold-start on the next request — observed in production review).

**Mitigations (shipped).**

- **Stable candidate identity.** Every candidate has a deterministic `candidate_id`; branch names derive from it, so a retry targets the same branch.
- **PR-existence check before opening.** A retry finds the existing branch/PR and records the outcome as `already_exists` instead of acting.
- **Honest completion accounting.** The completion view distinguishes opened vs already-open rather than claiming all PRs as new — idempotency is surfaced as a feature, not hidden.
- **Identity derivation is schema-versioned.** When candidate-ID derivation inputs change (as in the scan-counts revision), the cache schema version bumps; stale sessions land on an explicit "selection out of date" notice rather than acting on mismatched candidates.

**Residual risk.**

- Two distinct vulnerabilities mapping to the same upgrade produce one candidate; if its PR was rejected, the retry inherits the rejection. Correct behavior, potentially surprising to the operator.

### T7: Arguss server compromise

**Threat.** An attacker compromises the service on Fly.io — through application code, a dependency, or hosting — and can influence analyses, read server-side state, or abuse in-flight credentials.

**Impact.** High. A compromised server can mislead users with bad verdicts, read the scan cache and session store, exfiltrate the service-level secrets (Anthropic key, service GitHub token, Basic-auth password), and use the PAT of any Mode C action in flight.

**Likelihood.** Low for a small project; rises with adoption.

**Mitigations.**

- **Minimal attack surface.** Analysis and wizard endpoints only; no admin interface, no remote shell. Basic auth in front of everything.
- **Bounded credential blast radius.** Per-user PATs exist only in memory during an action; the persistent secrets are one read-only GitHub token, one Anthropic key, and the demo password. There is no stored credential that can write to any user repository.
- **State, while no longer minimal, contains no credentials.** The cache and session store hold scan results and wizard progress — sensitive as information (see T9), but not usable to act.
- **Code review for every change;** small-team visibility.
- **Engine version stamped on every verdict;** a weakened envelope is visible in the audit trail.
- **Kill switch** (environment variable or sentinel file) halts all auto-merge recommendations without a code change.
- **Structured action-path logging** means anomalous action behavior (unexpected PR loops, failures) is observable rather than silent.
- **Dependency hygiene** for Arguss's own Python dependencies; running Arguss against itself remains a tracked enhancement.

**Residual risk.**

- An attacker resident during an active Mode C action holds that user's PAT for the action's duration.
- A patient attacker landing small envelope-weakening changes that each pass review is hard to defend against; we rely on review culture and the audit trail.

### T8: AI presentation surface — prompt injection and fabrication

**Threat.** Claude-generated prose now appears in four places: the executive summary, the "Ask Arguss" chat panel, Mode C PR bodies, and escalation explanations. Inputs to those prompts include advisory text, package names, repository metadata, and — in the chat — arbitrary user questions. Malicious or adversarial text in any of these could inject instructions producing misleading guidance; separately, the model can fabricate plausible-sounding mechanics unprompted.

**Impact.** Low for the action path, by construction. Medium for human decision quality: production review demonstrated the fabrication failure concretely — the chat described a maximum-risk workflow score as "completely clean" and invented a nonexistent scoring mechanic. In a security tool, confidently wrong prose erodes exactly the trust the tool exists to provide.

**Likelihood.** Injection: low. Fabrication: demonstrated; now structurally mitigated.

**Mitigations.**

- **Engine purity (architectural invariant).** AI output never touches the decision path. Verdicts are computed by a pure function over structured signals; explanation generation is sync-isolated, called from a threadpool, and any failure returns None with graceful UI fallback. A poisoned or failed explanation degrades prose, never decisions.
- **Grounded mechanics.** Score-direction semantics and formula strings in the prompts are generated from the engine's own constants (single shared module, drift-guarded by tests). The prompts instruct the model to explain scores only via those formulas, to cite only the structured counts provided (with a unit glossary), and to say so when data is absent rather than infer.
- **Bounded context.** Prompts receive structured scan data — counts, attributions, top contributors — not raw repository contents or full advisory bodies.
- **Human-in-the-loop.** Every Claude output is read by a person; none is parsed back into the system.

**Residual risk.**

- A reviewer who blindly trusts generated prose can still be misled; grounding reduces but does not eliminate fabrication.
- Advisory titles and package names flow into prompts as third-party text; a crafted advisory could attempt injection. The blast radius is bounded to prose by the invariant above.

### T9: Server-side state as an asset (new in this revision)

**Threat.** The Week 6 draft claimed the service stored no user data. The deployed system stores scan results (including full dependency inventories and vulnerability findings for scanned repos), Claude-generated summaries, action records with PR outcomes, and wizard session state — all inside one Basic-auth boundary, on one persistent volume.

**Impact.** Medium in the demo posture; high if the service were public. A scan result is a curated map of a project's weakest points; an action record names exactly which PRs fix them. Cross-user, the shared cache means any credential-holder can view any cached scan (and a scan of repo X is retrievable by anyone who scans the same X — inherent to hash-keyed caching). Cookie theft within the TTL window resumes a wizard session, though never with the PAT (re-entry of the token is always required to act).

**Likelihood.** Low in the demo posture (small trusted credential set); the threat is primarily a forward-looking constraint on making the service public.

**Mitigations.**

- **Single shared credential boundary, explicitly assumed** (Assumption 8). For the showcase, the public-facing site will be separated from the authenticated scanning service rather than removing auth from the service wholesale.
- **No credentials in state.** PATs are excluded from sessions, cache, and action records by design and by test.
- **Session cookies are HttpOnly and SameSite=Lax** with a 1-hour TTL; the recovery cookie stores only a scan hash.
- **Schema-versioned state** prevents stale or shape-mismatched records from being interpreted incorrectly.
- **Scanned targets are public repositories** in all demo and evaluation scenarios; the information asymmetry of a cached scan is therefore bounded (anyone could run the same scan).

**Residual risk.**

- Multi-tenancy is unsolved by design. Public deployment requires per-user isolation of scans, sessions, and action records; this is documented post-capstone scope, and the showcase plan is built to avoid needing it.

## Mitigations summary

Design constraints from this model and where they live (all shipped unless noted):

| Constraint | Threats | Where it lands |
|---|---|---|
| Kill switch (env var + file) | T7 | engine kill switch |
| Idempotency: candidate_id, branch convention, PR-existence check, honest already-open accounting | T6 | engine models + action layer |
| Audit trail (engine version, timestamps, structured reasons) | T1, T7 | verdict fields |
| DECLINE as first-class output | T1, T5 | verdict tiers |
| Trust delta vetoes + typosquat detection | T1 | trust lens |
| Four-condition test reality, global veto | T5 | pipeline lens |
| Bounded parsing, upload limits, no execution of inputs | T3, T4 | parser + web layer |
| Shallow clone + timeout + structured failure taxonomy | T4 | clone layer |
| PAT: in-memory, header-only, log-redaction with regression test, service-token guard test | T2 | action path + logging config |
| Fine-grained PAT guidance with pre-filled minimal scopes | T2 | wizard authorize step |
| Engine purity: AI never on decision path, graceful degradation | T8 | explanation modules |
| Formula/count grounding derived from engine constants, drift-guarded | T8 | shared formula + glossary modules |
| Cookie hardening, PAT-free sessions, schema-versioned state | T9, T6 | wizard/session layer |
| Code review culture | T7 | process |

## Residual risk we accept

1. Identity-preserving maintainer compromise (T1) — no code-level analysis in v1.
2. PAT exposure during an active action under server compromise (T2/T7).
3. CI theater beyond sentinel heuristics (T5).
4. Lens false positives — agent unhelpfulness, not security risk; escalation is the failure mode.
5. Reliance on OSV.dev and enrichment sources (Assumptions 1–2); enrichments are display-only by design, which caps the damage of a compromised enrichment source at human-misleading rather than action-widening.
6. Broader-scoped user PATs than necessary (T2) — education, not enforcement.
7. Shared visibility of cached scans within the demo auth boundary (T9) — accepted for capstone; blocks public multi-tenant deployment.

## Operational guidance

For Mode C operators:

- **Use fine-grained PATs** scoped to the single target repository with exactly Contents: Read+write and Pull requests: Read+write, with a short expiry. Revoke when done — and revoke immediately any token that was pasted anywhere other than the Authorize form.
- **Arguss opens PRs; you merge them.** Review the PR diff and the verdict reasoning before merging, especially the first time.
- **Watch for engine version changes** in verdicts; a version bump is the moment to re-check that defaults haven't loosened.
- **Treat escalations and vetoes as designed signal.** A trust veto on an available "fix" is the product working, not failing.
- **If an action fails, the error names the real cause** (bad token, missing scope, rate limit with reset time, repo not found). Don't respond to failures by widening token scope unless the error explicitly says scope.
- For Mode A/B users: verdicts are advisory; nothing touches your repository.

## Open questions

- **Merge-after-CI.** The original design's "open PR, wait for CI, merge in-envelope" loop is not deployed; the system opens PRs only. If the merge loop ships, T1/T5/T6 impacts change materially and this document must be revised first.
- **Security-sensitive packages:** should packages that are themselves security tooling get a stricter envelope?
- **Transitive vulnerabilities** where the direct dep pins the vulnerable version: multi-path remediation (parent upgrade / overrides / skip) is designed but not built; its Mode C implications (overrides modify package.json semantics) belong in the next revision.
- **Arguss's own supply chain:** running Arguss against Arguss remains a tracked candidate.
- **Public deployment:** requires per-user isolation of all server-side state (T9), per-client rate/resource quotas (T4), and a real authentication story. Explicitly post-capstone.

---

**Team sign-off**

- [ ] Sherbano Khan
- [ ] Huiping Qiu (Sophia)
- [ ] Adrian Rosales

**Revision history**

- 2026-05-18: Initial draft under GitHub App deployment framing (Adrian Rosales)
- 2026-05-19: Revised for web service + opt-in GitHub action framing
- 2026-06: Revision 3 — documents the system as deployed: corrects the "no user data cached" claim and adds T9 (server-side state: scan cache, wizard sessions, action records); updates T2 with shipped, tested PAT controls and fine-grained scope guidance; expands T4 for server-side cloning; reframes T5/T6 around the PR-only action model with idempotency as shipped; rewrites T8 for the full AI surface (exec summary, chat, PR bodies) including the demonstrated fabrication failure and its structural mitigations; adds Known limitations (ref not honored on clone, unauthenticated clone); records service-level credential separation and the schema-versioned state layer (Adrian Rosales)
