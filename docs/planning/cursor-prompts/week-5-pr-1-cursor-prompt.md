# Cursor prompt — Week 5, PR 1: `feature/zizmor-wrapper`

This is the first of two PRs for the Week 5 pipeline lens. Goal: wrap the `zizmor` CLI as a Python subprocess, parse its JSON output, normalize to a `ZizmorFinding` dataclass, and add an inspection CLI command. **No lens integration in this PR** — that lands in PR 2.

**Branch name:** `feature/zizmor-wrapper`

**Estimated time:** 1-2 days of focused work.

**Scope discipline:** This PR produces `arguss zizmor-scan <workflows-dir>` printing normalized JSON output of zizmor findings. The pipeline lens itself remains a stubbed placeholder.

---

## Before pasting into Cursor

zizmor 1.25.2 is already installed (`uv add zizmor` was run successfully). Confirm before starting:

```bash
git checkout main
git pull
git log --oneline -5            # verify feature/trust-delta is merged

uv run zizmor --version          # should print "zizmor 1.25.2" or newer
uv run pytest                    # should be 100 pass, 1 skipped, 4 deselected

git checkout -b feature/zizmor-wrapper
```

---

## The prompt to paste into Cursor

I'm working on Week 5 PR 1 of the Arguss capstone — `feature/zizmor-wrapper`. Week 4 (trust signal lens) is fully merged. This PR wraps the zizmor CLI as a Python subprocess, parses its JSON output, normalizes findings, and adds an inspection CLI command. The pipeline lens itself remains a stubbed placeholder; PR 2 will do the lens integration and test reality assessment.

Project context: Arguss is an autonomous remediation agent for npm supply chain vulnerabilities (see `docs/planning/pivot-rationale.md`). The pipeline lens has two roles in the agent framing: (a) flag workflow misconfigurations as risk signals (this is zizmor's job), and (b) determine whether a repository's CI actually verifies changes well enough for the agent to safely auto-merge (this is the "test reality" assessment in PR 2). This PR only addresses (a).

## The actual zizmor JSON schema (v1.25.2)

I ran zizmor against a real workflow and captured the output. Build to this exact schema — do NOT guess at field names from training data. zizmor's output is a top-level JSON array, where each element looks like:

```json
{
  "ident": "unpinned-uses",
  "desc": "unpinned action reference",
  "url": "https://docs.zizmor.sh/audits/#unpinned-uses",
  "determinations": {
    "confidence": "High",
    "severity": "High",
    "persona": "Regular"
  },
  "locations": [
    {
      "symbolic": {
        "key": {
          "Local": {
            "prefix": null,
            "given_path": "/path/to/workflow.yml"
          }
        },
        "annotation": "action is not pinned to a hash (required by blanket policy)",
        "route": {
          "route": [
            {"Key": "jobs"},
            {"Key": "test"},
            {"Key": "steps"},
            {"Index": 0},
            {"Key": "uses"}
          ]
        },
        "feature_kind": {"Subfeature": {"after": 0, "fragment": {"Raw": "actions/checkout@v4"}}},
        "kind": "Primary"
      },
      "concrete": {
        "location": {
          "start_point": {"row": 6, "column": 14},
          "end_point": {"row": 6, "column": 33},
          "offset_span": {"start": 100, "end": 119}
        },
        "feature": "actions/checkout@v4",
        "comments": []
      }
    }
  ],
  "ignored": false
}
```

Key facts about this schema:

- **Top level is a JSON array.** Parse with `findings = json.loads(stdout)` directly, NOT `json.loads(stdout)["findings"]`.
- **Severity is nested:** `determinations.severity`, not top-level. Values are title-case strings: `"Informational"`, `"Low"`, `"Medium"`, `"High"`. No `"Critical"` in zizmor 1.25.2.
- **Each finding can have multiple locations.** The first location with `symbolic.kind == "Primary"` is the canonical location; others are `"Related"` (supporting context).
- **`ignored: false`** appears on every finding. If `ignored: true`, skip that finding (it was suppressed via configuration).
- **No remediation field exists.** We'll synthesize one using the URL.
- **`feature` under `concrete`** is the raw text snippet (e.g., `"actions/checkout@v4"`). Useful for the finding's display.
- **`row` and `column` are 0-indexed** in zizmor's output. Convert to 1-indexed for human-friendly display.

## What to build

### 1. The ZizmorFinding model — `arguss/core/models.py`

Add to the existing models file (view it first to avoid duplication):

```python
from typing import Literal

@dataclass(frozen=True)
class ZizmorFinding:
    """Normalized finding from zizmor static analysis of a workflow file."""
    ident: str                                    # e.g. "unpinned-uses", "artipacked"
    severity: Literal["informational", "low", "medium", "high"]
    confidence: Literal["unknown", "low", "medium", "high"]   # lowercased from zizmor's title-case
    description: str                              # zizmor's `desc` field
    file: str                                     # workflow file path, basename or repo-relative
    line: int                                     # 1-indexed line of primary location
    column: int                                   # 1-indexed column of primary location
    feature: str                                  # raw text snippet at the location
    annotation: str                               # zizmor's per-location annotation
    audit_url: str                                # zizmor's `url` for doc link
```

Severity literal does NOT include "critical" — zizmor 1.25.2 doesn't emit it. If a future zizmor version adds it, we'll extend the literal then.

### 2. The zizmor client — `arguss/lenses/_zizmor_client.py` (new file)

Subprocess wrapper. Mirror the structural patterns of `_osv_client.py` and `_trust_client.py` (typed errors, named timeout constants, no surprises). Public surface:

```python
class ZizmorClient:
    """Subprocess wrapper around the zizmor CLI."""

    def __init__(self, binary: str | None = None, timeout_seconds: int = 30) -> None:
        """binary defaults to looking up 'zizmor' on PATH via shutil.which.
        Raises ZizmorClientError at construction if zizmor is not found.
        """

    def scan_workflows(self, workflows_dir: Path) -> list[ZizmorFinding]:
        """Run zizmor against a .github/workflows/ directory or a single workflow file.

        Returns normalized findings (excluding ignored ones). If workflows_dir
        doesn't exist or contains no .yml/.yaml files, returns an empty list.

        Raises ZizmorClientError if the subprocess fails for reasons other than
        findings being present, or if the output cannot be parsed.
        """

    def version(self) -> str:
        """Return zizmor's version string."""
```

Implementation notes:

- **Use `subprocess.run`, not `subprocess.Popen` plus pipes.** Capture stdout and stderr; pass `text=True` for string output; set `timeout`.
- **The flag is `--format json`** (verified). The full command is approximately: `zizmor --format json <path>`.
- **zizmor exits with code 13 when findings are present**, 0 when clean. Both are success cases for the wrapper. Other exit codes are errors.
- **Capture both stdout and stderr.** Findings go to stdout as JSON; informational messages and warnings go to stderr. Include stderr in error messages when the subprocess fails unexpectedly.
- **The directory argument**: pass the workflows directory or a specific .yml file to zizmor. zizmor handles file discovery.
- **Workflow file discovery is zizmor's job.** Don't enumerate workflows ourselves.

Error class:

```python
class ZizmorClientError(Exception):
    """Raised when the zizmor subprocess fails in an unrecoverable way."""
```

### 3. Severity and confidence normalization

zizmor's JSON uses title-case strings. Lowercase them for our model. Module-level constants:

```python
_ZIZMOR_SEVERITY_MAP: dict[str, str] = {
    "Informational": "informational",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
}

_ZIZMOR_CONFIDENCE_MAP: dict[str, str] = {
    "Low": "low",
    "Medium": "medium",
    "High": "high",
    # "Unknown" is theoretical; not observed in 1.25.2 output but reserved
    "Unknown": "unknown",
}
```

If zizmor emits a value not in the map, log a warning and default to `"medium"` for severity and `"unknown"` for confidence. Don't crash.

### 4. JSON parsing — `_parse_zizmor_output`

Write a parser that:

- Accepts the raw stdout string
- Calls `json.loads(stdout)` — top level is a list
- For each finding in the list:
  - Skip if `ignored` is `True`
  - Find the primary location (`location["symbolic"]["kind"] == "Primary"`); if no Primary exists, use the first location
  - Extract `concrete.location.start_point.row` and `.column` (0-indexed) → convert to 1-indexed for our model
  - Extract `concrete.feature` for the snippet
  - Extract `symbolic.annotation` for the per-location annotation
  - Extract `determinations.severity` (title-case) → map to our lowercase literal
  - Extract `determinations.confidence` → map to our lowercase literal
  - Extract `ident`, `desc`, `url` from finding top-level
  - For the `file` field, get `symbolic.key.Local.given_path` and convert to basename (e.g., `"ci.yml"`)
- Returns `list[ZizmorFinding]`

Skip with a warning log if a finding has no usable location (no `locations` array, or all locations malformed).

### 5. The CLI command — extend `arguss/cli.py`

Add a new subcommand for development inspection:

```python
@app.command()
def zizmor_scan(
    workflows_dir: Path = typer.Argument(
        ...,
        help="Path to a .github/workflows/ directory or a specific workflow file",
        exists=True,
    ),
) -> None:
    """Run zizmor against a workflows directory and print normalized findings as JSON."""
```

Use the same JSON serialization pattern as `arguss trust-snapshot`. Findings serialize via `dataclasses.asdict`. Exit 0 even when findings are present (findings aren't a CLI error); exit 1 only on `ZizmorClientError`.

### 6. Tests — `tests/test_zizmor_client.py` (new file)

Use `unittest.mock.patch` on `subprocess.run` rather than running zizmor in unit tests. Build a realistic mock fixture: a JSON string matching the actual zizmor 1.25.2 schema (use the schema example from this prompt as a template).

Required tests:

1. **Clean run, no findings.** Mocked subprocess returns code 0, stdout is `"[]"`. Returns empty list.

2. **Findings present.** Mocked subprocess returns code 13, stdout contains 3 well-formed findings. Returns 3 `ZizmorFinding` objects with correct fields including converted line numbers (1-indexed).

3. **Severity mapping all four values.** Test with mocked findings using `"Informational"`, `"Low"`, `"Medium"`, `"High"` — each maps correctly to its lowercase form.

4. **Confidence mapping.** Same shape as severity test.

5. **Unknown severity falls back to medium.** Mocked output with `"Critical"` (or `"Catastrophic"` or anything not in the map) → finding parses, severity is `"medium"`, warning logged.

6. **Ignored findings are filtered out.** Mocked output with 3 findings where one has `"ignored": true` → returns 2 findings.

7. **Primary location is preferred.** Mocked output where a finding has two locations: one with `"kind": "Related"` first, one with `"kind": "Primary"` second. The Primary location's row/column/feature appear in the result.

8. **Fallback to first location when no Primary.** Mocked output where all locations are `"kind": "Related"` → returns finding with first location's data, no crash.

9. **Subprocess timeout.** Mocked subprocess raises `subprocess.TimeoutExpired` → client raises `ZizmorClientError` with a clear message.

10. **Subprocess returns unexpected exit code** (not 0, not 13). Mocked subprocess returns code 1 with stderr "fatal: something broke" → client raises `ZizmorClientError` including the stderr text.

11. **zizmor not on PATH.** Mocked `shutil.which` returns None at construction → client raises `ZizmorClientError`.

12. **Malformed JSON.** Mocked subprocess returns stdout that isn't valid JSON → client raises `ZizmorClientError`.

13. **Finding with no locations array.** Mocked output has a finding with `"locations": []` → parser skips it with a warning, doesn't crash.

14. **CLI command exits cleanly.** `CliRunner` test that `zizmor-scan` exits 0 with valid JSON output when findings are mocked, exits 1 on `ZizmorClientError`.

Plus one **integration test** marked `@pytest.mark.integration` that runs the real zizmor binary against `tests/fixtures/workflows/sample-with-findings/ci.yml` (the fixture below). Asserts:
- The subprocess completes without crashing
- At least 2 findings are returned (zizmor reliably flags unpinned actions in our sample)
- All findings have populated required fields
- At least one finding has `ident == "unpinned-uses"` (the most stable rule name)

Don't assert exact counts beyond "≥2" — zizmor's rule set evolves.

### 7. The integration test fixture

Create `tests/fixtures/workflows/sample-with-findings/ci.yml`:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
      - run: npm test
```

This produces (in zizmor 1.25.2 with default settings): `artipacked` (Medium), `excessive-permissions` (Medium), and two `unpinned-uses` (High) findings. Total 4 findings — sufficient for integration verification.

### 8. Documentation

Update `arguss/lenses/_zizmor_client.py` module docstring to document:
- The subprocess pattern and why (zizmor is a CLI, not a Python library)
- The 30-second timeout and what happens at the limit
- The severity normalization decision and the title-case → lowercase map
- The Primary-location-preferred policy

No separate design doc yet — PR 2 will create `docs/planning/pipeline-lens.md`.

## Critical rules

1. **The pipeline lens itself is unchanged.** It still returns the fake stub. Only the zizmor client and CLI command land in this PR. PR 2 will wire the client into the lens.

2. **No test reality assessment in this PR.** The "does CI actually run tests" logic is PR 2. Don't sneak it in.

3. **No new dependencies beyond zizmor.** Already added via `uv add zizmor`. Don't add more.

4. **The subprocess pattern is the only IPC.** Don't try to import zizmor as a Python library (the pip package wraps a Rust binary). Don't call its internals.

5. **Build to the schema shown in this prompt, not to your training data.** Field names like `ident`, `desc`, `determinations.severity` are real and stable. Don't translate them to `rule`, `description`, top-level `severity` based on assumptions about other tools.

6. **Stop after each major step:** (a) models change, (b) zizmor client class, (c) severity/confidence mapping + JSON parser, (d) CLI command, (e) tests, (f) integration fixture. Let me read between steps.

## How to work

Generate code one file at a time. Stop after each step. The zizmor client interface needs my review before tests are written against it.

## Verification commands

After Cursor finishes, I will run:

```bash
uv run pytest tests/test_zizmor_client.py -v
uv run pytest                                              # full suite still green
uv run ruff check arguss/lenses/_zizmor_client.py arguss/cli.py
uv run mypy arguss/lenses/_zizmor_client.py arguss/cli.py

# CLI sanity checks
uv run arguss zizmor-scan tests/fixtures/workflows/sample-with-findings/ci.yml
uv run arguss zizmor-scan tests/fixtures/workflows/sample-with-findings/
uv run arguss zizmor-scan /nonexistent/path                # should exit non-zero with a clear error

# Integration test (runs real zizmor)
uv run pytest tests/test_zizmor_client.py -v -m integration
```

All of those must produce reasonable output before the PR opens.

## Out of scope for this PR (explicitly)

- Test reality assessment (PR 2)
- Pipeline lens integration with the unified scoring engine (PR 2)
- The `PipelineSnapshot` model (PR 2)
- The pipeline lens's `subscore` aggregation (PR 2)
- Updating the unified PRS to use the pipeline lens's real output (PR 2)
- Multi-CI-platform support (out of scope entirely for this project)
- Custom zizmor rules or configuration (use defaults)
- Persona filtering (we always use the default "Regular" persona)
