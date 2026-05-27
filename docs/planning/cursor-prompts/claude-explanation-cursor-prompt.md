# Cursor prompt — `feature/claude-explanation`

This PR adds a Claude-backed explanation module that generates prose for human reviewers of Arguss PRs. It wires into Mode C's PR body generator so that pull requests get both the existing deterministic bullet list of reasoning AND a natural-language paragraph from Claude.

**Branch name:** `feature/claude-explanation`

**Estimated time:** 1-2 days.

**Scope discipline:** This PR builds the module and wires it into **Mode C only**. CLI integration (the `arguss propose-fixes` command's output) is a separate follow-up PR. Don't touch the CLI in this PR even though the module is general-purpose.

---

## Before pasting into Cursor

```bash
git checkout main
git pull
git log --oneline -3                     # verify Mode C (week-7-mode-c-complete) is at top

uv run pytest                             # baseline: should be 278 passed, 1 skipped

git checkout -b feature/claude-explanation

# Add the Anthropic SDK as a runtime dependency
uv add anthropic
```

---

## The prompt to paste into Cursor

I'm working on a follow-up to Week 7 PR 3 (Mode C). This PR adds an AI-powered explanation module that generates prose for PR bodies. The architectural ground rules are critical and the entire design hinges on them:

**Ground rules (non-negotiable):**

1. **AI output is NEVER on the auto-merge path.** The fix-confidence engine's tier decision is determined by structured signal evaluation. Claude only generates prose about *why* a verdict was reached, for human reviewers reading the PR. Removing the Claude call entirely doesn't change the agent's decisions; it only removes a layer of explanation.

2. **The function is sync.** It runs in a threadpool from the async handler, same pattern as everything else (per Week 7 PR 1's sync-with-threadpool decision).

3. **Failure is non-fatal.** If the Anthropic API is unavailable, slow, rate-limited, returns garbage, or the API key is missing, the caller must fall back to the existing deterministic PR body. A Claude failure is a UX degradation, not a correctness problem.

4. **The PAT and the Anthropic API key are separate concerns.** The PAT is per-request user credentials. The Anthropic API key is service-level configuration (env var). Never confuse them.

5. **The Claude integration lives in `arguss/engine/explanation.py`** — engine layer, not web. Even though the only consumer in this PR is Mode C, the inputs (FixCandidate, FixConfidence, Finding) are engine concepts.

## What to build

### 1. Settings — add Anthropic API configuration to `arguss/settings.py`

Add two new settings:

```python
# In arguss/settings.py

class Settings(BaseSettings):
    # ... existing settings ...

    anthropic_api_key: str | None = None
    """Anthropic API key for explanation generation. If unset, the
    explainer is disabled and callers fall back to deterministic output."""

    anthropic_explanation_model: str = "claude-sonnet-4-6"
    """The Claude model to use for explanation generation. Sonnet is the
    default; haiku is faster/cheaper; opus is highest quality."""
```

Load from env vars as usual (`ANTHROPIC_API_KEY`, `ANTHROPIC_EXPLANATION_MODEL`).

### 2. The explanation module — `arguss/engine/explanation.py` (new)

```python
"""Generate human-readable prose explanations of fix-confidence verdicts.

The Claude integration lives here, separated from the decision engine
(arguss/engine/fix_confidence.py is pure and unaffected by this module).

Architectural ground rule: AI output is NEVER on the auto-merge path.
This module produces prose for human reviewers. Removing it entirely
doesn't change the agent's decisions; it only removes prose enrichment
in PR bodies and other human-facing surfaces.

Failure mode: any failure (missing API key, network error, API timeout,
rate limit, malformed response) returns None. Callers MUST handle None
by falling back to a deterministic alternative.
"""

from __future__ import annotations

import logging
from typing import Final

from anthropic import Anthropic, APIError, APITimeoutError

from arguss.core.models import Finding, FixCandidate, FixConfidence
from arguss.settings import settings


_MAX_TOKENS: Final[int] = 512
_API_TIMEOUT_SECONDS: Final[float] = 15.0

_LOG = logging.getLogger(__name__)


_SYSTEM_PROMPT = """You explain software dependency upgrade decisions to engineers reviewing pull requests.

Be concise, technical, and honest about uncertainty. Write 3-5 sentences of plain Markdown prose. Do NOT include a preamble like "Here's an explanation:" — write the explanation directly. Do NOT repeat the structured data verbatim; synthesize it into context that helps a human reviewer decide.

If the agent is confident (AUTO_MERGE), explain why the fix is safe in context. If the agent is escalating (REVIEW_REQUIRED), explain what specifically concerns the agent and what the human should verify. If the agent is declining (DECLINE), explain why the fix should not be applied."""


def explain_verdict_to_human(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
) -> str | None:
    """Generate a prose explanation of the verdict for human reviewers.

    Returns the prose string on success, or None on any failure (missing
    API key, network error, API timeout, rate limit, malformed response).
    Callers MUST handle None by falling back to a deterministic alternative.

    This function is sync (call from a threadpool in async contexts).
    """
    if not settings.anthropic_api_key:
        _LOG.debug("Anthropic API key not configured; skipping explanation")
        return None

    user_prompt = _build_user_prompt(candidate, verdict, finding)

    try:
        client = Anthropic(
            api_key=settings.anthropic_api_key,
            timeout=_API_TIMEOUT_SECONDS,
        )
        message = client.messages.create(
            model=settings.anthropic_explanation_model,
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
    except APITimeoutError:
        _LOG.warning("Anthropic API timeout during explanation generation")
        return None
    except APIError as exc:
        _LOG.warning("Anthropic API error during explanation generation: %s", exc)
        return None
    except Exception as exc:
        _LOG.warning("Unexpected error during explanation generation: %s", exc)
        return None

    # Extract text from the response. Anthropic returns a list of content blocks;
    # for our simple text-only prompt, we expect exactly one TextBlock.
    if not message.content:
        _LOG.warning("Anthropic response had empty content")
        return None

    first_block = message.content[0]
    text = getattr(first_block, "text", None)
    if not isinstance(text, str) or not text.strip():
        _LOG.warning("Anthropic response had no usable text")
        return None

    return text.strip()


def _build_user_prompt(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
) -> str:
    """Construct the user prompt from structured inputs."""
    reasons_block = "\n".join(f"- {r}" for r in verdict.reasons) or "- (no reasons)"
    veto_signals = ", ".join(verdict.veto_signals) if verdict.veto_signals else "none"

    return f"""A package vulnerability fix candidate has been evaluated:

**Package:** {candidate.package}
**Upgrade:** {candidate.from_version} → {candidate.to_version} ({candidate.fix_kind.value})
**Vulnerability:** {finding.advisory_id or "(no advisory ID)"}
**Title:** {finding.title}

**Engine verdict:** {verdict.tier.value} (score: {verdict.score}/100)
**Veto signals fired:** {veto_signals}

**Structured reasons:**
{reasons_block}

**CVE description (excerpt):**
{(finding.description or "(no description)")[:1500]}

Explain this decision in 3-5 sentences of plain Markdown prose suitable for a PR body. Write directly without preamble."""
```

Critical implementation notes:

- **Sync API client.** `Anthropic(...)` is the sync class; `AsyncAnthropic(...)` is the async variant. We want sync per our threadpool architecture.

- **`timeout=15.0`** at the client level. If Claude is slow, we don't want to hold up PR creation.

- **All exceptions caught.** Network errors, timeouts, API errors, malformed responses — all return None. Never propagate to the caller.

- **CVE description truncated to 1500 chars** in the prompt. Some advisories have multi-page descriptions; we don't need to send all of it.

- **Logging at `warning` level for failures**, `debug` for "key not configured." Failures matter; missing-by-design configuration doesn't.

- **No PAT, no user data**, no secrets in the prompt. Only the package, version, advisory, verdict, reasons. The Anthropic API doesn't see anything user-specific.

### 3. Wire into Mode C — modify `arguss/web/github_action.py`

Update `_render_pr_body` to optionally include a Claude-generated paragraph above the existing "Why the agent is confident" section.

Change the function signature:

```python
def _render_pr_body(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
    explanation: str | None = None,  # NEW
) -> str:
    ...
```

In the body template, insert a new section between "What this PR does" and "Why the agent is confident":

```python
explanation_section = ""
if explanation:
    explanation_section = f"""

### Context

{explanation}
"""
```

Then in the f-string body, add `{explanation_section}` after "What this PR does" and before "Why the agent is confident".

When explanation is None or empty, the section is empty string — no header, no extra whitespace, clean fallback.

### 4. Wire into Mode C — modify `open_fix_pr` in `arguss/web/github_action.py`

In `open_fix_pr`, before constructing the PR body (right before the `_post_pull_request` call in the full workflow path, AND in `_resume_open_pr`), generate the explanation:

```python
from arguss.engine.explanation import explain_verdict_to_human

# ... existing code, then where the PR body is needed:
explanation = explain_verdict_to_human(candidate, verdict, finding)
```

Pass `explanation` to `_post_pull_request` so it can be threaded into `_render_pr_body`.

Update `_post_pull_request`'s signature too:

```python
def _post_pull_request(
    client: httpx.Client,
    owner: str,
    name: str,
    *,
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
    branch: str,
    default_branch: str,
    context: str,
    explanation: str | None = None,  # NEW
) -> ActionResult:
    # ... call _render_pr_body(..., explanation=explanation) ...
```

The explanation generation happens for AUTO_MERGE candidates only (since Mode C only acts on AUTO_MERGE). The function works for all tiers, but it only gets called in the AUTO_MERGE code path because that's all Mode C does.

### 5. Tests — `tests/test_explanation.py` (new file)

The Anthropic client should be mocked in all tests except an explicit integration test.

**Unit tests (8-10 cases):**

1. `test_explain_verdict_returns_prose_on_success` — mock client returns a response with text; verify the text is returned
2. `test_explain_verdict_returns_none_when_api_key_missing` — `settings.anthropic_api_key = None`; function returns None without calling the client
3. `test_explain_verdict_returns_none_on_api_error` — mock client raises `APIError`; function returns None
4. `test_explain_verdict_returns_none_on_api_timeout` — mock client raises `APITimeoutError`; function returns None
5. `test_explain_verdict_returns_none_on_unexpected_exception` — mock client raises RuntimeError; function returns None (not propagated)
6. `test_explain_verdict_returns_none_when_response_empty` — mock client returns response with empty content; None
7. `test_explain_verdict_returns_none_when_response_has_no_text` — content block has no text attribute; None
8. `test_explain_verdict_strips_response_whitespace` — response text has leading/trailing whitespace; result is stripped
9. `test_explain_verdict_uses_configured_model` — verify the model from settings is passed to the API call
10. `test_explain_verdict_prompt_contains_advisory_id` — verify the user prompt has the structured data (advisory ID, package, versions)

**Integration test (1, marked `@pytest.mark.integration`):**

11. `test_explain_verdict_integration_with_real_api` — skips unless `ANTHROPIC_API_KEY` is set in env. Real API call against the configured model. Asserts the response is a non-empty string but doesn't pin specific content (Claude's output varies).

**Mode C regression tests** — verify the existing Mode C tests still pass. The new `explanation` parameter has a default of None, so existing call sites work unchanged. Specifically:

- `tests/test_scan_with_action_endpoint.py` — should pass without modification
- The "PR body includes candidate_id" test should still pass (the deterministic structure is preserved)

Add one new test:

12. `test_open_fix_pr_pr_body_includes_explanation_when_available` — mock `explain_verdict_to_human` to return a known string; verify the PR body posted to GitHub contains that string in a "Context" section

13. `test_open_fix_pr_pr_body_falls_back_when_explanation_returns_none` — mock `explain_verdict_to_human` to return None; verify the PR body has no "Context" section but otherwise is well-formed

### 6. Update `pyproject.toml`

Cursor's `uv add anthropic` should have done this. Verify the dependency is listed and the version is recent.

### 7. Documentation — `docs/planning/explanation-design.md` (new file, small)

One page covering:

- Why we have this module (humans benefit from prose; the engine is structured)
- The architectural ground rules (AI never on the decision path; sync; graceful fallback)
- The current consumers (Mode C PR bodies) and the deferred ones (CLI propose-fixes output, web UI)
- The settings (api key and model name)
- The failure model (any error returns None; caller falls back)
- A note about caching being deferred (filed as a separate issue)
- A note that the threat model document (T8: AI prompt injection) anticipated this work; updating it is a separate concern

## Critical rules

1. **The engine does NOT change.** No edits to `arguss/engine/fix_confidence.py`, `propose.py`, the lenses, or the parser. The explanation module is new code in a new file; it READS from engine outputs but doesn't modify them.

2. **`explain_verdict_to_human` is sync.** It uses the sync Anthropic client. Async callers wrap it in `run_in_threadpool`.

3. **All exceptions inside the function are caught and return None.** Never raise to the caller.

4. **Missing API key is graceful, not exceptional.** Returns None silently (with debug log). Users without keys can still use Mode C; they just get the deterministic PR body.

5. **The Claude prompt contains no PAT, no user repository content, no secrets.** Only structured engine outputs and the CVE description. This is a safety invariant — verify by reading the `_build_user_prompt` function.

6. **The CLI is NOT touched in this PR.** `arguss/cli.py` doesn't change. The CLI integration is a follow-up.

7. **Stop after each major step:**
   - (a) Settings + the explanation module + its unit tests
   - (b) Wiring into Mode C (modifying `github_action.py`) + the regression tests
   - (c) Documentation

   Let me review between (a) and (b).

## Verification commands

```bash
uv run pytest tests/test_explanation.py -v
uv run pytest tests/test_scan_with_action_endpoint.py -v   # Mode C regression
uv run pytest                                               # full suite green
uv run ruff check arguss/engine/explanation.py arguss/web/github_action.py
uv run mypy arguss/engine/explanation.py arguss/web/github_action.py

# Local smoke test (requires real ANTHROPIC_API_KEY in env)
ANTHROPIC_API_KEY=sk-ant-... uv run uvicorn arguss.api:app --reload &
sleep 2
# ... Mode C call with a real test repo
# Verify the PR body contains a "Context" section with Claude prose

# Smoke test WITHOUT a key (should still work, just no Context section)
unset ANTHROPIC_API_KEY
uv run uvicorn arguss.api:app --reload &
sleep 2
# ... same Mode C call
# Verify the PR body is well-formed but has no Context section
```

## Out of scope for this PR (explicitly)

- CLI integration (`arguss propose-fixes` output) — separate PR
- Web UI integration (Week 9)
- Caching of explanations — filed as a follow-up issue
- Async variant of `explain_verdict_to_human` — sync only for v1
- Updating the threat model document (T8 already covers this conceptually)
- Streaming responses from Claude (we want the full prose at once)
- Multi-turn conversations or RAG (just structured one-shot prompts)
- Per-tier prompt customization (one system prompt handles all tiers; Claude infers tone from the input)
