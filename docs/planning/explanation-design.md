# Explanation layer — design (Week 7+)

Arguss separates **decisions** (structured, deterministic) from **human-facing prose** (optional LLM enrichment). The fix-confidence engine in `arguss/engine/fix_confidence.py` produces authoritative `FixTier` verdicts. The explanation module in `arguss/engine/explanation.py` turns the same structured inputs into Markdown paragraphs for reviewers — without feeding back into automation.

**Related docs:** `fix-confidence-engine.md` (tiers and vetoes), `web-service-architecture.md` (Mode C PR opening), `docs/threat-model.md` (T8).

**Code map:**

| Concern | Module |
|---------|--------|
| Verdict engine (no AI) | `arguss/engine/fix_confidence.py` |
| Prose explanations | `arguss/engine/explanation.py` |
| Mode C PR bodies | `arguss/web/github_action.py` (`_try_explanation`, `_render_pr_body`) |
| Settings | `arguss/settings.py` |

---

## Why this module exists

| Surface | Audience | Format |
|---------|----------|--------|
| Engine (`FixConfidence`) | Agent, APIs, logs | Structured: `tier`, `score`, `veto_signals`, `reasons` |
| Explanation (`explain_verdict_to_human`) | Humans reviewing PRs | Prose Markdown (3–5 sentences) |

Humans need synthesis: what the upgrade is, why the agent chose a tier, and what to verify on escalation. The engine already encodes that in `reasons` and `veto_signals`; repeating those bullets verbatim in every PR is tedious. The explanation layer **summarizes** structured verdict data plus a bounded CVE excerpt — it does not re-score or re-tier.

**Removing `arguss/engine/explanation.py` (and its call sites) does not change agent decisions.** `compute_fix_confidence` and Mode C eligibility (`AUTO_MERGE` only) are unchanged. PRs still open with deterministic sections; only the optional `### Context` block disappears.

---

## Architectural ground rules

These are non-negotiable design constraints (also reflected in T8 mitigations in `docs/threat-model.md`; updating that document to reference this module is a **separate** follow-up).

| Rule | Implementation |
|------|----------------|
| **AI never on the decision path** | `tier` comes only from `fix_confidence`. Explanation runs **after** the verdict, only for human surfaces. |
| **Sync API** | `explain_verdict_to_human` is synchronous; async routes call it from a threadpool (`github_action` path). |
| **Graceful fallback** | Any failure → `None`. Callers use deterministic PR body content (reasons list, advisory link). |
| **PAT ≠ Anthropic key** | Mode C uses a GitHub PAT in the request body (`SecretStr`). `ANTHROPIC_API_KEY` is server/env config for explanations only — never mixed in prompts as a credential users paste for scans. |
| **Bounded prompt** | User prompt includes package, versions, tier, veto list, structured reasons, and CVE description **truncated to 1500 chars**. `max_tokens=512`, API timeout 15s. |

---

## Settings

Loaded from environment (`.env` locally, Fly secrets in production):

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key (`sk-ant-…`). If unset, explainer returns `None` immediately (debug log only). |
| `ANTHROPIC_EXPLANATION_MODEL` | Model id (default `claude-sonnet-4-6`). Sonnet balances quality/latency; Haiku is a valid cheaper choice. |

`Settings.anthropic_api_key` is `str | None` (empty env → `None`). `validate_settings(require_ai=True)` is for future CLI paths that **require** AI; Mode C and the web service do **not** require a key at startup.

**Never commit:** `.env`, real `ANTHROPIC_API_KEY` values, or GitHub PATs. Gitleaks and `secret-scan.yml` target `sk-ant-` patterns among other secrets.

---

## Failure model — always `None`

`explain_verdict_to_human` returns `str | None`:

| Condition | Behavior |
|-----------|----------|
| Missing `ANTHROPIC_API_KEY` | `None` (no API call) |
| `APITimeoutError` | Log warning, `None` |
| `APIError` (rate limit, 4xx/5xx) | Log warning, `None` |
| Empty or non-text response | Log warning, `None` |
| Unexpected exception | Log warning, `None` |

Callers **must** branch on `None`. Mode C wraps the call in `_try_explanation` so PR creation still succeeds.

There is no retry-until-success loop in v1 — avoiding hung scans and runaway spend.

---

## Consumers and deferred work

| Consumer | Status |
|----------|--------|
| **Mode C** (`POST /scan/with-action` → `github_action`) | **Shipped.** AUTO_MERGE PRs get optional `### Context` prose when the API key is set and the call succeeds. |
| **`arguss propose-fixes` CLI** | **Deferred.** JSON report stays structured-only; no `--explain` in v1. |
| **Web UI “Explain this fix” (Week 9)** | **Deferred.** HTMX explainer endpoint planned in project timeline; not wired in current dashboard. |

Mode C still only opens PRs for `AUTO_MERGE` candidates; explanations do not promote `REVIEW_REQUIRED` or `DECLINE` to auto-merge.

---

## PR body shape

Deterministic skeleton from `_render_pr_body` in `arguss/web/github_action.py`:

1. Title line: package and version bump
2. Advisory link and finding title
3. **Fix-confidence verdict** line (tier + score)
4. **What this PR does** (lockfile change)
5. Optional **`### Context`** — only when explanation string is non-empty (AI prose)
6. **`### Why the agent is confident`** — bullet list from `verdict.reasons` (always present for AUTO_MERGE PRs)

Example structure when AI succeeds:

```markdown
## Arguss auto-fix: lodash 4.17.20 → 4.17.21

Fixes [GHSA-…](…): …

**Fix-confidence verdict:** AUTO_MERGE (score: 100/100)

### What this PR does
Upgrades `lodash` from `4.17.20` to `4.17.21` in `package-lock.json`.

### Context

<3–5 sentences from Claude>

### Why the agent is confident
- ✅ …
```

When explanation returns `None`, sections 1–4 and 6 render unchanged; section 5 is omitted.

---

## Prompt design (v1)

**System:** Role = explain dependency upgrade decisions to engineers; 3–5 sentences; plain Markdown; no preamble; synthesize rather than copy structured fields verbatim.

**User:** Built from `FixCandidate`, `FixConfidence`, and `Finding` — package, versions, `fix_kind`, advisory id/title, tier, score, veto signals, enumerated reasons, CVE description excerpt (≤1500 chars).

The model is instructed to address AUTO_MERGE vs REVIEW_REQUIRED vs DECLINE tone even though Mode C only attaches prose to AUTO_MERGE PRs today — keeping one prompt useful for future CLI/UI consumers.

---

## Caching (deferred)

`Settings.ai_explanation_ttl_days` and the `ai_explanations` SQLite table exist from early scaffolding, but **`explain_verdict_to_human` does not read or write that cache yet**. Adding cache lookup/write is a **separate issue** (keyed by candidate + verdict fingerprint + prompt version) to reduce API cost and demo latency.

Until then, each successful Mode C PR may incur one Anthropic call per AUTO_MERGE candidate.

---

## Threat model cross-reference (T8)

`docs/threat-model.md` **T8: Anthropic API compromise / prompt injection** anticipated this split:

- Impact stays low because text is human-read, not agent-acted.
- Mitigations: not on auto-merge path, bounded inputs, engine/presenter separation.

This design doc implements that separation in code. **Updating T8 wording** (e.g. planned Week 7+ → shipped, link here) is intentionally **out of scope** for this doc-only change set.

---

## Operational notes

- **Cost:** Bound `max_tokens` and short prompts; set an Anthropic console spending cap in production.
- **`--no-ai` (CLI):** Skips AI features on scan paths; Mode C explanations are independent unless the deployment sets `ANTHROPIC_API_KEY`.
- **Observability:** Warnings on failure paths; never log API keys or PATs.
- **Testing:** `tests/test_explanation.py` mocks the Anthropic client; engine tests do not depend on network.

---

## Dependency graph (conceptual)

```text
Finding + FixCandidate
        │
        ▼
 compute_fix_confidence ──► FixConfidence (tier authoritative)
        │
        │ (optional, human only)
        ▼
 explain_verdict_to_human ──► str | None
        │
        ▼
 _render_pr_body (### Context if Some)
```

The agent loop and merge automation read **only** the left branch `tier`.
