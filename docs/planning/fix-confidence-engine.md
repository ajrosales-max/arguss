# Fix-confidence engine — design (Week 6 PR 1)

Week 5 lenses answer **what is wrong** (CVE, trust, pipeline). This engine answers **whether Arguss may act** on a specific remediation: given a `FixCandidate` and pre-computed lens outputs, it returns a `FixConfidence` verdict. It does **not** run lenses, discover fixes, or open PRs — the CLI (PR 2) and agent loop (Week 7) compose inputs and act on outputs.

**Entry point:** `arguss.engine.fix_confidence.compute_fix_confidence`
**Version tag:** `ENGINE_VERSION = "fix-confidence-v1.0.0"` (bump when veto logic or weights change)

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
- **Fix kind:** `FixKind` on the candidate is expected to match `classify_fix_kind(from, to)` at proposal time (PR 2); engine does not re-classify.

## Open questions (Week 7)

- **Per-tier agent behavior:** `AUTO_MERGE` → merge delegated PR? `REVIEW_REQUIRED` → open PR only? `DECLINE` → skip proposal entirely or still notify?
- **Presenting `veto_signals`:** Single summary vs grouped by lens; which signals are “repairable” (add CI) vs inherent (major bump) in the same verdict.
- **Wiring `project_veto`** to repo-level halt signals from the agent loop.

## v1 limitations (explicit)

1. **Static `AUTO_MERGE` reason** — Template is fix-kind only (e.g. “patch-level upgrade; trust signals unchanged; CI verifies tests”). Per-instance detail (maintainer names, test counts, zizmor counts) lives in the referenced `TrustDelta` / `PipelineSnapshot`, not copied into `reasons`. **Week 11 candidate:** enrich reasons from snapshots at evaluation time.

2. **Trust invariant dependency** — The engine assumes `safe_to_auto_merge ⇔ len(flags) == 0` as enforced by `fetch_delta`. If construction breaks that invariant, trust vetoes may not fire when flags are present but `safe_to_auto_merge` is wrongly `True`. Documented inline in `_collect_review_vetoes`; trust lens must preserve the invariant.

3. **Forgiving score lookup** — `_score_for_review` uses `dict.get(signal, 0)`. New `veto_signal` IDs without a `_SCORE_REDUCTION` entry reduce tier correctly but **silently contribute 0** to score. Acceptable for v1; **Week 11 hardening** could raise on unknown signals.

## Code map

| Module | Role |
|--------|------|
| `arguss/core/models.py` | `FixCandidate`, `FixConfidence`, `FixKind`, `FixTier` |
| `arguss/engine/fix_kind.py` | `classify_fix_kind` |
| `arguss/engine/kill_switch.py` | `is_kill_switch_active` |
| `arguss/engine/fix_confidence.py` | `compute_fix_confidence`, `ENGINE_VERSION` |
| `tests/test_fix_confidence.py` | 27 unit tests |
