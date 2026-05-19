# Fix-confidence engine — design (Week 6)

Week 5 lenses answer **what is wrong** (CVE, trust, pipeline). Week 6 adds **fix discovery** (findings → `FixCandidate`) and the **fix-confidence engine** (candidates + lens outputs → `FixConfidence`), composed by **`arguss propose-fixes`**. The Week 7 agent loop will consume `FixConfidence` and act on it; this document covers the decision stack through the propose-fixes CLI.

| Layer | Entry point | Role |
|-------|-------------|------|
| Discovery | `arguss.engine.fix_discovery.discover_fix_candidates` | One candidate per CVE finding (v1) |
| Engine | `arguss.engine.fix_confidence.compute_fix_confidence` | Tier/score verdict per candidate |
| Orchestration | `arguss.engine.propose.propose_fixes` | Lockfile → full `ProposalReport` |
| CLI | `arguss propose-fixes <lockfile> [--repo-path PATH]` | JSON report on stdout |

**Engine version tag:** `ENGINE_VERSION = "fix-confidence-v1.0.0"` (bump when veto logic or weights change)

## Structured output — `FixConfidence`

| Field | Why it exists |
|-------|----------------|
| **`tier`** (`FixTier`) | **Authoritative decision** for automation: `AUTO_MERGE`, `REVIEW_REQUIRED`, or `DECLINE`. The agent reads tier only — not score. `DECLINE` is first-class (kill switch, project halt), not an error state. |
| **`score`** (0–100) | **Human/dashboard signal** and Week 11 tuning input. Higher ≈ closer to auto-merge comfort. `0` only for `DECLINE`; `REVIEW_REQUIRED` floors at 1. Behavior never branches on score in v1. |
| **`reasons`** | **Audit-readable prose**: sorted tuple explaining the verdict. Positive one-liner for `AUTO_MERGE`; enumerated veto explanations for review/decline. |
| **`veto_signals`** | **Machine-readable veto IDs** (sorted). Empty when `AUTO_MERGE`. Enables logging, metrics, and agent UX without parsing prose. |
| **`candidate_id`** | Echoes `FixCandidate.candidate_id` so verdict records join to proposals across retries and storage. |
| **`evaluated_at`** | Timezone-aware UTC timestamp for post-hoc timelines (“what did we know at merge time?”). |
| **`engine_version`** | Which rule set produced the verdict when weights/logic change later. |

Inputs: `FixCandidate`, optional `TrustDelta`, optional `PipelineSnapshot`, optional `project_veto` (hook only in v1 — no consumer wired).

## Evaluation order

Each step can **downgrade** authority; terminal steps stop evaluation. Multiple review vetoes **stack** (all appear in `veto_signals`).

| Order | Condition | Tier |
|-------|-----------|------|
| 1 | Kill switch active | `DECLINE` (terminal) |
| 2 | `project_veto=True` | `DECLINE` (terminal) |
| 3 | `FixKind.MAJOR` | `REVIEW_REQUIRED` |
| 4 | `trust_delta is None` | `REVIEW_REQUIRED` |
| 5 | `not trust_delta.safe_to_auto_merge` | `REVIEW_REQUIRED` (+ per-flag signals) |
| 6 | `pipeline_snapshot is None` | `REVIEW_REQUIRED` |
| 7 | `not pipeline_snapshot.test_reality.safe_to_auto_merge` | `REVIEW_REQUIRED` |
| — | None of the above | `AUTO_MERGE` |

**Rationale:** operator disable (threats: compromised credentials/code) wins first; project halt second; semver risk and lens vetoes before any auto-merge. Major bumps never auto-merge even when trust and CI are clean.

## Score formula (v1 weights)

For `REVIEW_REQUIRED`, start at **100** and subtract per fired signal (then `max(1, score)`):

| `veto_signal` | Reduction |
|---------------|-----------|
| `fix_kind.major` | 50 |
| `trust.unavailable` | 20 |
| `pipeline.unavailable` | 25 |
| `pipeline.test_reality` | 25 |
| `trust.ownership_transferred` | 15 |
| `trust.new_maintainer` | 15 |
| `trust.cadence_anomaly` | 15 |
| `trust.download_collapse` | 15 |

`AUTO_MERGE` → 100. `DECLINE` → 0. Weights are **empirically tunable in Week 11** against labeled outcomes; tier logic can evolve independently.

## Kill switch

Administrative **off** without redeploying code (threats 2 & 3):

1. **Env:** `ARGUSS_KILL_SWITCH` ∈ `1`, `true`, `yes` (case-insensitive)
2. **File:** path from `ARGUSS_KILL_SWITCH_FILE_PATH`, default `/tmp/arguss_kill_switch` — active if the file **exists**

When active, every candidate gets `DECLINE`, `veto_signals=("kill_switch",)`, score 0. Use during incidents, suspected compromise, or before revoking App credentials. Checked **first** on every `compute_fix_confidence` call.

## Idempotency — `FixCandidate.candidate_id`

Derived at construction (callers cannot set it): SHA-256 of
`package|from_version|to_version|fix_kind|source_finding_id|repo_id`, truncated to **16 hex chars**.

`repo_id` is the **resolved absolute path** of the repo root passed into discovery (from `propose_fixes`: `--repo-path` or the lockfile’s parent directory).

Enables the Week 7 agent loop to **deduplicate retries** (same upgrade path + finding + repo → same key), avoid duplicate PRs, and key idempotent merge decisions. Distinct fix paths (different `to_version` or finding) get distinct IDs.

## Audit trail

Store or log full `FixConfidence` (or JSON equivalent) with `candidate_id`, `tier`, `veto_signals`, `reasons`, `evaluated_at`, `engine_version`. Together with referenced `TrustDelta` / `PipelineSnapshot` snapshots, operators can reconstruct **why** auto-merge was allowed or blocked after an incident without re-running the engine.

## `veto_signal` taxonomy

Prefixed IDs for stable analytics and agent messaging:

| ID | Source |
|----|--------|
| `kill_switch` | Operator disable |
| `project_veto` | Project-level halt hook |
| `fix_kind.major` | Semver major bump on candidate |
| `trust.unavailable` | No `TrustDelta` |
| `trust.ownership_transferred` | `TrustFlag.OWNERSHIP_TRANSFER` |
| `trust.new_maintainer` | `TrustFlag.NEW_MAINTAINER` |
| `trust.cadence_anomaly` | `TrustFlag.CADENCE_ANOMALY` |
| `trust.download_collapse` | `TrustFlag.DOWNLOAD_COLLAPSE` |
| `pipeline.unavailable` | No `PipelineSnapshot` |
| `pipeline.test_reality` | `TestReality.safe_to_auto_merge` is false |

Add new signals by extending `_collect_review_vetoes`, `_SCORE_REDUCTION`, and tests — keep IDs namespaced (`trust.*`, `pipeline.*`).

## Cross-module dependencies

- **Trust:** Engine trusts `TrustDelta` from `arguss.lenses.trust.fetch_delta`. Veto flags are read from `trust_delta.flags` when `safe_to_auto_merge` is false.
- **Pipeline:** Engine reads `PipelineSnapshot.test_reality` only (not zizmor subscore for tier).
- **Fix kind:** `FixKind` on the candidate is set by `fix_discovery` via `classify_fix_kind(from, to)`; engine does not re-classify.

## Fix discovery (v1)

The engine consumes `FixCandidate`s. The fix-discovery layer produces them from vulnerability findings. The v1 implementation (**Option A**) generates **exactly one candidate per finding**, using OSV’s minimum fix version as the target.

### Data on `Finding` (CVE lens)

| Field | Source |
|-------|--------|
| `advisory_id` | OSV vulnerability ID (`GHSA-…`, `CVE-…`) → `FixCandidate.source_finding_id` |
| `fixed_versions` | All `fixed` events from OSV `affected` ranges for the dependency’s package (sorted lex for storage) |

Non-CVE lenses leave these at defaults (`advisory_id=None`, `fixed_versions=()`).

### Selection algorithm (`discover_fix_candidates`)

1. Refuse if `advisory_id is None` (log warning; no `source_finding_id` to record).
2. Refuse if `fixed_versions` is empty (log warning).
3. Filter to versions **strictly greater than** `dependency.version` using **semver** (`compare_versions` / `pick_lowest_version_gt` in `fix_kind.py`) — not lex order.
4. Pick the **semver-lowest** survivor as `to_version`.
5. Set `fix_kind = classify_fix_kind(from, to)` and build one `FixCandidate`.

If no version passes step 3 (e.g. OSV `fixed` ≤ installed), return `[]` and log.

### Known v1 simplifications (Week 10+)

- **No smart target selection.** We use OSV’s minimum applicable `fixed` directly, not “latest patch within current minor” or latest on npm. When OSV says fixed in `1.20.3`, we propose `1.20.3` even if `1.20.6` exists and is equally safe.
- **No alternative paths.** One finding → one candidate. No “minimum fix” vs “latest minor” vs “latest major” choices.
- **No per-package coalescing.** Three CVEs on the same package all fixed in `1.20.3` → three candidates with the same `to_version`. Display can dedupe; the engine evaluates each separately.

These simplifications are deliberate: v1 proves the stack end-to-end. Each can be relaxed independently when there is a real need.

### Follow-up (display vs target)

`Finding.remediation` text uses the **lex-first** entry in `fixed_versions` when multiple exist; the **proposal target** uses **semver-lowest** `> from_version`. Wording can disagree when lex order ≠ semver order. Cosmetic for v1; align in a small follow-up if it confuses operators.

## Propose-fixes orchestration (`propose_fixes`)

**Module:** `arguss/engine/propose.py`

| Step | Behavior |
|------|----------|
| Parse lockfile | `parse_lockfile(lockfile_path)` |
| CVE findings | `VulnerabilityLens(cache).scan(deps)` |
| Per finding | `discover_fix_candidates(finding, repo_id)` |
| Skipped | Findings with zero candidates → `skipped_findings` (`advisory_id` or `title`), sorted lex |
| Pipeline | **`fetch_pipeline_snapshot(repo_root)` once** per report |
| Trust | **`fetch_delta` per candidate**; `TrustClientError` → pass `None` (do not abort run) |
| Verdict | `compute_fix_confidence(candidate, trust_delta, pipeline_snapshot)` per candidate |
| Summary | Tier counts derived from `entries` (must match) |

**Cache:** `propose_fixes` opens its own SQLite `Cache` via `settings.db_path`. Fine for CLI v1. **TODO in `propose.py`:** accept an optional existing `Cache` for Week 7+ agent loop reuse.

**Output types:** `ProposalReport` → `entries` (`ProposalEntry`: finding + candidate + verdict), `skipped_findings`, `ProposalSummary`.

## `arguss propose-fixes` CLI

- **Args:** path to `package-lock.json` (must exist).
- **Options:** `--repo-path` (repo root; default lockfile parent).
- **Stdout:** JSON `ProposalReport` via `asdict` + `Finding.model_dump()`; enums/datetimes via shared `_json_default`.
- **Exit 0** when the report is produced, including when vulnerabilities exist.
- **Exit 1** on `ParserError` or `ZizmorClientError` only (v1).

### `arguss scan` hint (stderr)

After `arguss scan` (json or pretty), a one-line hint is printed on **stderr** (not stdout):

> For actionable remediation proposals, run: `arguss propose-fixes <path-to-package-lock.json>`

**Why stderr:** default `scan` output is JSON on stdout for tooling; mixing the hint into stdout would break `json.loads` on the scan result. Operators still see the hint in the terminal; scripts piping stdout remain valid.

## Open questions (Week 7)

- **Per-tier agent behavior:** `AUTO_MERGE` → merge delegated PR? `REVIEW_REQUIRED` → open PR only? `DECLINE` → skip proposal entirely or still notify?
- **Presenting `veto_signals`:** Single summary vs grouped by lens; which signals are “repairable” (add CI) vs inherent (major bump) in the same verdict.
- **Wiring `project_veto`** to repo-level halt signals from the agent loop.

## v1 limitations (explicit)

1. **Static `AUTO_MERGE` reason** — Template is fix-kind only (e.g. “patch-level upgrade; trust signals unchanged; CI verifies tests”). Per-instance detail (maintainer names, test counts, zizmor counts) lives in the referenced `TrustDelta` / `PipelineSnapshot`, not copied into `reasons`. **Week 11 candidate:** enrich reasons from snapshots at evaluation time.

2. **Trust invariant dependency** — The engine assumes `safe_to_auto_merge ⇔ len(flags) == 0` as enforced by `fetch_delta`. If construction breaks that invariant, trust vetoes may not fire when flags are present but `safe_to_auto_merge` is wrongly `True`. Documented inline in `_collect_review_vetoes`; trust lens must preserve the invariant.

3. **Forgiving score lookup** — `_score_for_review` uses `dict.get(signal, 0)`. New `veto_signal` IDs without a `_SCORE_REDUCTION` entry reduce tier correctly but **silently contribute 0** to score. Acceptable for v1; **Week 11 hardening** could raise on unknown signals.

4. **Path-based `repo_id`** — `candidate_id` hashes the resolved absolute repo root. The same clone at two paths on one machine yields different IDs. Acceptable for v1 (local-only agent). **Week 10+:** consider normalizing to upstream URL or a content hash of repo identity.

5. **OSV failures are silent at propose time** — `VulnerabilityLens.scan` catches `OsvError` and returns **zero findings** (same as “no CVEs”), so `propose-fixes` succeeds with an empty report instead of exit 1. Not changed in Week 6 PR 2; **follow-up issue** when planning docs land: propagate OSV unreachable as a hard CLI error.

6. **Remediation text vs fix target** — See [Follow-up (display vs target)](#follow-up-display-vs-target) under fix discovery.

## Code map

| Module | Role |
|--------|------|
| `arguss/core/models.py` | `Finding` (+ `advisory_id`, `fixed_versions`), `FixCandidate`, `FixConfidence`, `FixKind`, `FixTier` |
| `arguss/lenses/vulnerability.py` | Populates CVE fields; `_extract_fixed_versions` |
| `arguss/engine/fix_kind.py` | `classify_fix_kind`, `compare_versions`, `pick_lowest_version_gt` |
| `arguss/engine/fix_discovery.py` | `discover_fix_candidates` |
| `arguss/engine/kill_switch.py` | `is_kill_switch_active` |
| `arguss/engine/fix_confidence.py` | `compute_fix_confidence`, `ENGINE_VERSION` |
| `arguss/engine/propose.py` | `propose_fixes`, `ProposalReport` |
| `arguss/cli.py` | `propose-fixes` command; scan hint on stderr |
| `tests/test_fix_confidence.py` | 27 engine tests |
| `tests/test_propose_fixes.py` | 17 unit + 1 integration test |
