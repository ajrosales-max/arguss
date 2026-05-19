# Cursor prompt — Week 6, PR 1: `feature/fix-confidence-engine`

This is the first of two PRs for Week 6 (the conceptual heart of the project). Goal: build the `FixCandidate` and `FixConfidence` data models, the engine that produces a `FixConfidence` from a `FixCandidate` plus the three lens outputs, and the supporting infrastructure (kill switch, idempotency key, audit trail). **No CLI command in this PR** — that lands in PR 2.

**Branch name:** `feature/fix-confidence-engine`

**Estimated time:** 1-2 days of focused work.

**Scope discipline:** This PR produces a working `compute_fix_confidence(candidate, lens_outputs) -> FixConfidence` function with full test coverage. The agent loop that consumes `FixConfidence` is Week 7. The CLI command that exercises this engine end-to-end is PR 2.

---

## Before pasting into Cursor

Start from clean main with Week 5 merged:

```bash
git checkout main
git pull
git log --oneline -5             # verify feature/pipeline-lens is merged

uv run pytest                     # should be 153 passed, 1 skipped, 6 deselected

git checkout -b feature/fix-confidence-engine
```

---

## The prompt to paste into Cursor

I'm working on Week 6 PR 1 of the Arguss capstone — `feature/fix-confidence-engine`. Week 5 (pipeline lens) is fully merged. This PR builds the fix-confidence engine: data models for representing remediation proposals and confidence assessments, plus the engine that combines the three lens outputs into a confidence verdict per remediation.

Project context: Arguss is an autonomous remediation agent for npm supply chain vulnerabilities (see `docs/planning/pivot-rationale.md` and `docs/planning/project-overview.md`). Up until now, the lenses identify what's wrong; they don't propose what to do about it. This PR introduces the `FixCandidate` (a structured remediation proposal) and the `FixConfidence` (whether the agent should auto-merge, escalate, or decline). The Week 7 agent loop will consume `FixConfidence` and act on it; the Week 6 work is to build the decision logic that the agent loop will trust.

## The threat model context (informing this design)

We're building this knowing the agent will eventually act with delegated GitHub App credentials. The eight threats we're explicitly defending against:

1. **Compromised upstream package** — attacker takes over a maintainer, publishes malicious patch
2. **Compromised Arguss credentials** — attacker gets the App's private key
3. **Compromised Arguss code** — malicious change to Arguss itself loosens vetoes
4. **Malicious user installation** — bad actor installs Arguss for laundering
5. **CI subversion** — repo's CI configured to always pass
6. **Replay / idempotency** — retries cause duplicate PRs or double-merges
7. **Race conditions** — concurrent scans of the same repo
8. **Anthropic API compromise** — prompt injection via CVE descriptions

Four of these surface design constraints that land in this PR's code:

- **Kill switch** (threats 2, 3): the engine must be disable-able by an operator without code changes
- **Idempotency key** (threat 6): every `FixCandidate` has a stable identity; the engine surfaces it for callers to deduplicate retries
- **Audit trail** (threats 2, 3): `FixConfidence` carries enough context to reconstruct why a decision was made after the fact
- **DECLINE as first-class** (threats 1, 5): the engine commonly returns DECLINE; not an error, not a fallback

The threat model document itself is being written in parallel and isn't a precondition for this code, but these four constraints are.

## What to build

### 1. The FixCandidate and FixConfidence models — `arguss/core/models.py`

Add to the existing models file (view it first to avoid duplication). Use Python 3.12 syntax conventions matching the existing models.

```python
from enum import Enum

class FixKind(Enum):
    """The semver delta of a remediation."""
    PATCH = "patch"    # e.g. 1.20.0 -> 1.20.1
    MINOR = "minor"    # e.g. 1.20.0 -> 1.21.0
    MAJOR = "major"    # e.g. 1.20.0 -> 2.0.0


class FixTier(Enum):
    """The agent's authority level for a specific fix.

    AUTO_MERGE: engine has high confidence; agent may merge without human review
    REVIEW_REQUIRED: agent opens a PR but does not auto-merge
    DECLINE: agent does not propose this fix (e.g., breaking change with no clear path)
    """
    AUTO_MERGE = "auto_merge"
    REVIEW_REQUIRED = "review_required"
    DECLINE = "decline"


@dataclass(frozen=True)
class FixCandidate:
    """A proposed remediation for a specific finding on a specific dependency.

    One FixCandidate represents one possible action: 'upgrade X from A to B'.
    A given finding can produce multiple candidates (multiple fix paths exist).
    """
    package: str                          # npm package name
    from_version: str
    to_version: str
    fix_kind: FixKind                     # derived from semver delta
    source_finding_id: str                # ID of the CVE/finding motivating this fix
                                          # e.g. "GHSA-qwcr-r2fm-qrc7"
    repo_id: str                          # stable identifier for the repo
                                          # (e.g. "github.com/owner/name" or absolute path)
    candidate_id: str                     # idempotency key: sha256 of the above fields,
                                          # truncated to 16 hex chars. Computed at construction
                                          # via __post_init__ or a class method. Always derived,
                                          # never passed in by the caller.


@dataclass(frozen=True)
class FixConfidence:
    """The engine's verdict on a FixCandidate."""
    candidate_id: str                     # echoes the FixCandidate's idempotency key
    tier: FixTier                         # the agent's authority level
    score: int                            # 0-100, higher = more confident in auto-merge
    reasons: tuple[str, ...]              # human-readable reasons (sorted, for determinism).
                                          # When tier == AUTO_MERGE: explains why we approved
                                          # (typically a brief positive justification)
                                          # When tier == REVIEW_REQUIRED or DECLINE: explains
                                          # which veto conditions fired
    veto_signals: tuple[str, ...]         # machine-readable IDs of the specific signals that
                                          # forced a non-AUTO_MERGE tier. Empty when AUTO_MERGE.
                                          # Examples: "trust.ownership_transferred",
                                          # "trust.new_maintainer", "pipeline.test_reality",
                                          # "fix_kind.major", "kill_switch"
    evaluated_at: datetime                # timezone-aware UTC
    engine_version: str                   # for audit trail: which engine produced this verdict
                                          # (use arguss.__version__ or a module constant)
```

### 2. The FixKind classifier — `arguss/engine/fix_kind.py` (new module)

Helper to classify a version delta:

```python
def classify_fix_kind(from_version: str, to_version: str) -> FixKind:
    """Classify the semver delta between two versions.

    Uses semver semantics: major if from.major != to.major, minor if same major
    but different minor, patch otherwise. Handles common prefix patterns ('v1.2.3',
    '~1.2.3', etc.) by stripping non-numeric leading characters.

    Returns FixKind.MAJOR for any unparseable version (conservative: we don't
    know what kind of change this is, so we assume it's major).
    """
```

Use `packaging.version` from the standard ecosystem or implement a minimal semver parser. If you implement, keep it small — just major/minor/patch extraction with prefix stripping. Don't try to handle prerelease tags or build metadata for v1.

### 3. The kill switch — `arguss/engine/kill_switch.py` (new module)

```python
def is_kill_switch_active() -> bool:
    """Check if the engine is administratively disabled.

    Two ways to activate the kill switch:
    1. Environment variable ARGUSS_KILL_SWITCH set to '1', 'true', 'yes' (case-insensitive)
    2. A file exists at ARGUSS_KILL_SWITCH_FILE_PATH (default: /tmp/arguss_kill_switch)

    When the kill switch is active, compute_fix_confidence returns DECLINE for
    every candidate with veto_signal 'kill_switch' and reason 'engine
    administratively disabled via kill switch'.

    Returns True if active, False otherwise. Never raises.
    """
```

Simple, but exists for a reason. The threat model requires an operator-level disable that doesn't need a code change. This is that.

### 4. The fix-confidence engine — `arguss/engine/fix_confidence.py` (new module)

The core function. Takes a `FixCandidate` and the three lens outputs (or rather, the structured trust delta + pipeline snapshot + the relevant CVE finding), produces a `FixConfidence`.

```python
def compute_fix_confidence(
    candidate: FixCandidate,
    trust_delta: TrustDelta | None,
    pipeline_snapshot: PipelineSnapshot | None,
    project_veto: bool = False,
) -> FixConfidence:
    """Compute the engine's verdict for a remediation candidate.

    Inputs:
        candidate: the FixCandidate being evaluated
        trust_delta: the trust signal delta for this package across the upgrade
                     window. None means trust signals couldn't be computed
                     (e.g., package not on registry) — treated as a soft block.
        pipeline_snapshot: the repo's pipeline snapshot. None means the repo
                           context isn't available — treated as a hard block
                           (no CI verification = no auto-merge).
        project_veto: optional escape hatch. If True, force tier=DECLINE
                      regardless of other signals. The Week 6 design exposes
                      this hook; no consumer wires it yet.

    Returns FixConfidence with tier, score, reasons, and audit context.

    Evaluation order (each can downgrade tier):
        1. Kill switch active → DECLINE (terminal)
        2. project_veto → DECLINE (terminal)
        3. FixKind.MAJOR → REVIEW_REQUIRED (major bumps never auto-merge)
        4. trust_delta is None → REVIEW_REQUIRED (can't verify trust)
        5. trust_delta.safe_to_auto_merge is False → REVIEW_REQUIRED
           (with specific TrustFlag values as veto_signals)
        6. pipeline_snapshot is None → REVIEW_REQUIRED (no CI to verify)
        7. pipeline_snapshot.test_reality.safe_to_auto_merge is False
           → REVIEW_REQUIRED (with the specific reasons_blocked as veto_signals)

    If none of 1-7 triggered, tier = AUTO_MERGE.

    Score (0-100):
        Starts at 100 if AUTO_MERGE. Reduced by signal strength for
        REVIEW_REQUIRED. 0 for DECLINE.

    For REVIEW_REQUIRED, score reductions:
        - FixKind.MAJOR: -50 (major bumps are inherently risky)
        - Each trust veto signal: -15
        - Pipeline test_reality fail: -25
        - Trust unavailable: -20
        - Pipeline unavailable: -25
    Floor at 1 for REVIEW_REQUIRED (DECLINE is the only tier with score=0).

    The score is for the dashboard and for empirical tuning in Week 11.
    The tier is what the agent reads.

    Reasons (tuple of human-readable strings):
        - AUTO_MERGE: a one-line positive justification
          (e.g., "patch-level upgrade; trust signals unchanged; CI verifies tests")
        - REVIEW_REQUIRED: enumerated reasons each veto fired
        - DECLINE: the terminal reason (kill switch / project_veto)

    veto_signals (tuple of machine-readable IDs):
        - kill_switch
        - project_veto
        - fix_kind.major
        - trust.unavailable
        - trust.ownership_transferred
        - trust.new_maintainer
        - trust.cadence_anomaly
        - trust.download_collapse
        - pipeline.unavailable
        - pipeline.test_reality
    """
```

Important design notes:

- **The engine doesn't run the lenses.** It receives already-computed lens outputs (`TrustDelta`, `PipelineSnapshot`). Composing the lenses is the CLI's job (PR 2) and eventually the agent loop's job (Week 7).
- **Each veto is independent.** Multiple can fire simultaneously; all of their signals appear in `veto_signals`. The tier is determined by the most-restrictive veto.
- **The kill switch is checked FIRST.** Operator disable wins over everything.
- **`project_veto` is checked SECOND.** Per the Week 6 design, this hook exists but no consumer wires it yet. The parameter defaults to False; eventually the agent loop will pass True when project-level signals indicate "halt all auto-merges for this repo."

### 5. The MODULE_VERSION constant

```python
# In arguss/engine/fix_confidence.py:
ENGINE_VERSION = "fix-confidence-v1.0.0"
```

This appears in every `FixConfidence` for audit purposes. Bumping this constant (e.g., when veto thresholds are tuned in Week 11) is the equivalent of a versioning event — historical audit records still show which engine version produced them.

### 6. Tests — `tests/test_fix_confidence.py` (new file)

Required tests covering each evaluation step. Use unit-test discipline: each test exercises one decision path.

**Model and identity:**
1. `FixCandidate.candidate_id` is deterministic — same inputs produce same ID
2. Different inputs produce different IDs (sanity check, not a collision proof)
3. `FixCandidate` is frozen — modifying fields raises

**FixKind classifier:**
4. `classify_fix_kind("1.2.3", "1.2.4")` → PATCH
5. `classify_fix_kind("1.2.3", "1.3.0")` → MINOR
6. `classify_fix_kind("1.2.3", "2.0.0")` → MAJOR
7. `classify_fix_kind("v1.2.3", "v1.2.4")` → PATCH (handles 'v' prefix)
8. `classify_fix_kind("garbage", "1.0.0")` → MAJOR (conservative on unparseable)

**Kill switch:**
9. Environment variable activates kill switch
10. File path activates kill switch
11. Neither active → not active
12. Kill switch active → `compute_fix_confidence` returns DECLINE with reason mentioning kill switch
    (use `monkeypatch.setenv` and `monkeypatch.setattr` to avoid touching real env)

**Engine evaluation:**
13. Clean patch-level fix with safe trust delta + safe pipeline → AUTO_MERGE, score 100
14. Clean minor-level fix with safe signals → AUTO_MERGE (minor bumps still auto-merge per envelope)
15. Major-level fix → REVIEW_REQUIRED with `fix_kind.major` in veto_signals
16. Trust delta is None → REVIEW_REQUIRED with `trust.unavailable`
17. Trust delta has OWNERSHIP_TRANSFER → REVIEW_REQUIRED with `trust.ownership_transferred`
18. Trust delta has NEW_MAINTAINER → REVIEW_REQUIRED with `trust.new_maintainer`
19. Pipeline snapshot is None → REVIEW_REQUIRED with `pipeline.unavailable`
20. Pipeline test_reality fail → REVIEW_REQUIRED with `pipeline.test_reality`
21. project_veto=True → DECLINE with `project_veto`
22. Multiple vetoes simultaneously → all in `veto_signals`, tier is the most restrictive
23. AUTO_MERGE reason is informative (not empty, mentions the fix kind)

**Audit trail:**
24. `FixConfidence.evaluated_at` is timezone-aware UTC
25. `FixConfidence.engine_version` matches the module constant
26. `FixConfidence.candidate_id` matches the input candidate's

**Determinism:**
27. Same inputs → same outputs (the engine is pure given fixed clock/env)
    (achievable via `monkeypatch.setattr` on the timestamp function)

### 7. Design doc — `docs/planning/fix-confidence-engine.md` (new file)

One page covering:

- The structured output (tier + score + reasons + veto_signals) and why each field exists
- The evaluation order (kill switch first, then project_veto, then fix_kind, then trust, then pipeline)
- The score formula (signal reduction table) and that it's empirically tunable in Week 11
- The kill switch mechanisms and when to use them
- The idempotency key derivation and what it enables (deduplication of retries by the agent loop)
- The audit trail fields (evaluated_at, engine_version) and what they enable (post-hoc review)
- The veto_signal taxonomy (the prefixed IDs) and how to add new signals
- Open questions for Week 7: how the agent loop should react to each tier; what to do when veto_signals contains both repairable conditions and inherent ones

## Critical rules

1. **The engine is pure.** It takes inputs, returns a value. No I/O during evaluation except the kill switch check (which has documented hooks for testing).

2. **The kill switch is checked first, every time.** Don't optimize this away. The whole point is that an operator can flip it on and immediately stop all auto-merges, even mid-batch.

3. **`project_veto` is a hook, not a feature.** It accepts a boolean parameter, defaults to False, no consumer wires it yet. The seam exists for Week 7+ work; we don't fill it now.

4. **Tier transitions are not graded.** A fix is AUTO_MERGE, REVIEW_REQUIRED, or DECLINE. No "soft AUTO_MERGE" or "preliminary REVIEW." The agent reads the tier and acts.

5. **The score is for humans and evaluation, not for the agent.** The agent reads `tier`. The dashboard reads `score`. Don't write code that switches behavior based on the numeric score.

6. **No new dependencies.** Stay with stdlib + what's already in pyproject.toml. If you need semver parsing and `packaging` isn't already pinned, use a minimal handwritten parser.

7. **Stop after each major step:**
   - (a) Models change (FixCandidate, FixConfidence, FixKind, FixTier)
   - (b) FixKind classifier module
   - (c) Kill switch module
   - (d) Fix-confidence engine module
   - (e) Tests
   - (f) Design doc

   Let me review between each.

## How to work

Generate code one file at a time. Stop after each step. The engine module (step d) is the conceptual core; I want to read it carefully before tests are written against it.

## Verification commands

After Cursor finishes, I will run:

```bash
uv run pytest tests/test_fix_confidence.py -v
uv run pytest                                              # full suite still green
uv run ruff check arguss/engine/                            # if applicable
uv run mypy arguss/engine/                                  # if applicable

# Sanity check: import the engine, call it on a synthetic candidate, see the output
uv run python -c "
from datetime import datetime, UTC
from arguss.core.models import FixCandidate, FixKind
from arguss.engine.fix_confidence import compute_fix_confidence

candidate = FixCandidate(
    package='lodash',
    from_version='4.17.20',
    to_version='4.17.21',
    fix_kind=FixKind.PATCH,
    source_finding_id='GHSA-test',
    repo_id='example/repo',
    candidate_id='',  # will be computed in __post_init__
)
verdict = compute_fix_confidence(candidate, trust_delta=None, pipeline_snapshot=None)
print(f'Tier: {verdict.tier.value}')
print(f'Score: {verdict.score}')
print(f'Veto signals: {verdict.veto_signals}')
print(f'Reasons: {verdict.reasons}')
"
# Should output: tier=REVIEW_REQUIRED, multiple veto signals (trust.unavailable, pipeline.unavailable),
# score in the 40-60 range, reasons listing both unavailables.

# Kill switch sanity check
ARGUSS_KILL_SWITCH=1 uv run python -c "
... same as above ...
"
# Should output: tier=DECLINE, veto_signals=('kill_switch',), reasons mention the switch
```

All of those must produce reasonable output before the PR opens.

## Out of scope for this PR (explicitly)

- The `arguss propose-fixes` CLI command (PR 2)
- Fix discovery from CVE findings (PR 2)
- Composing the lenses to feed the engine (PR 2)
- The agent loop that consumes `FixConfidence` (Week 7)
- The threat model document itself (parallel, separate file)
- Wiring `project_veto` to a real signal (Week 7+)
- A "dry run" mode that records what the engine would have decided without acting (Week 7)
- Persistent storage of `FixConfidence` records for replay (Week 9-10 reliability hardening)
- Configurable thresholds via config file (Week 11 evaluation)
