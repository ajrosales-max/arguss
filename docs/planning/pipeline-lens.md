# Pipeline lens — design (Week 5 PR 2)

The pipeline lens combines **zizmor** (GitHub Actions static analysis) with a **test reality** heuristic: does the repository's CI actually run meaningful tests? It feeds the unified score and (via `TestReality.safe_to_auto_merge`) the future fix-confidence veto path.

## Two consumers (same pattern as trust)

| Consumer | Field | Meaning |
|----------|-------|---------|
| **PRS / dashboard** | `PipelineSnapshot.subscore` (0–100) | Severity-weighted sum of zizmor findings + fixed penalty when test reality fails. Capped at 100. |
| **Agent veto (Week 6+)** | `TestReality.safe_to_auto_merge` | Binary: all four test-reality conditions must hold. Exposed separately from subscore — not redundant. |

## `PipelineSnapshot`

| Field | Role |
|-------|------|
| `repo_path` | Absolute repository root analyzed |
| `workflow_files` | Sorted repo-relative paths under `.github/workflows/` |
| `zizmor_findings` | Normalized output from `ZizmorClient` (PR 1) |
| `test_reality` | Four-condition assessment |
| `subscore` | PRS input |

## Test reality — four conditions (all required)

| Condition | Check |
|-----------|--------|
| `has_test_script` | `package.json` exists and `scripts.test` is a non-empty string |
| `not test_script_is_no_op` | Test script does not match sentinel no-op patterns |
| `has_test_files` | At least one `*.test.*` / `*.spec.*` file or file under `test/`, `tests/`, `__tests__/`, `spec/` |
| `workflow_runs_tests` | At least one workflow file contains `npm|yarn|pnpm|bun` + `test` invocation in a `run:` step (regex) |

`safe_to_auto_merge` is **True** only when all four hold. No partial credit (no "3 of 4 → 0.75").

`reasons_blocked` lists human-readable failure modes (sorted lexicographically) when not safe; empty when safe. Reasons are **short-circuited**: if `package.json` is missing, only `"no package.json in your submission"` is emitted for script-related failures (not `"package.json has no scripts.test"`). If `.github/workflows/` does not exist, only `"no .github/workflows in your project"` is emitted (not `"no GitHub Actions workflow runs tests"`).

### Known false positive (accepted v1)

`tsc --noEmit` in `scripts.test` is treated as a **real** test script (not a no-op). It does not run tests, but the static heuristic cannot distinguish it from `jest` / `vitest`. Documented limitation — do not special-case in v1.

### Package manager aliases

Workflow detection uses:

```text
\b(npm|yarn|pnpm|bun)\s+(?:run\s+)?test\b
```

Fixture **yarn-tests** validates `yarn test` end-to-end.

## Subscore formula

| zizmor severity | Points |
|-----------------|--------|
| informational | 2 |
| low | 5 |
| medium | 15 |
| high | 30 |

| Component | Points |
|-----------|--------|
| Test reality failure penalty | 40 (when `not safe_to_auto_merge`) |
| Cap | 100 |

```text
subscore = min(sum(weights per finding) + penalty, 100)
```

## `PipelineLens.scan()` and dependencies

`scan(deps)` **ignores** `deps`. Pipeline analysis is **per-repo**; the dependency list exists only because the lens interface was designed for npm package lenses. Pass `repo_path` at construction; `arguss scan` sets it from the project root (parent of `package-lock.json` when a lockfile path is given).

If `repo_path` is **None**, the lens returns the legacy **stub** `LensScore` (score 50) for backward compatibility.

## Graceful degradation

Missing `.github/`, `package.json`, or test files does **not** raise. The snapshot is always returned with appropriate `False` flags and populated `reasons_blocked`. Only **zizmor binary failure** (`ZizmorClientError`) propagates.

## Out of scope

- Fix-confidence wiring (Week 6)
- Code coverage analysis (Week 10+)
- CI theater (`|| true`, masked failures)
- Detecting `tsc --noEmit` as non-testing
- Multi-CI platforms (GitHub Actions only)
- Test framework config introspection
- Configurable test-reality rules file

## Open questions (Week 6)

- How `safe_to_auto_merge` combines with trust `TrustDelta` in fix-confidence
- Whether PRS should weight misconfiguration (zizmor) vs CI-quality (test reality) differently in the lens score itself

## References

- `arguss/lenses/pipeline.py` — `fetch_pipeline_snapshot`, `PipelineLens`, test reality helpers
- `arguss/lenses/_zizmor_client.py` — subprocess wrapper (PR 1)
- `arguss/core/models.py` — `TestReality`, `PipelineSnapshot`, `ZizmorFinding`
- `tests/test_pipeline_lens.py` — six repo fixtures under `tests/fixtures/repos/`
