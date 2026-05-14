# Cursor prompt — CVSS vector parsing enhancement

This is a continuation of `feature/vulnerability-lens`. The lens currently extracts severity from OSV's `database_specific.severity` string ("CRITICAL", "HIGH", "MEDIUM", "LOW") and maps to representative CVSS values, which quantizes the lens score into {25, 50, 75, 95}. This enhancement parses OSV's `severity[].score` CVSS vectors directly to produce precise scores.

**Stays on branch:** `feature/vulnerability-lens`
**Estimated time:** 2-3 hours of focused work. Most of it is implementing the CVSS 3.x base score formula, which is well-documented but has a few subtleties.

---

## Why we're doing this now

The lens-score quantization in v1 is harmless on its own but cascades into other features:

- **Week 6 remediation ranker** ranks proposed upgrades by "risk reduction per change." If lens scores quantize, the ranking is coarse — two different upgrades might appear to reduce risk by the same amount when one actually reduces it more.
- **Week 8 demo scenario #1** narrates blast radius via specific CVE scores. "This is a CVSS 9.8 critical RCE" lands better than "this is a high-severity issue scored 75."
- **Week 9 dashboard visualization** uses score gradients to color-code findings. Quantized scores produce ugly clusters.

Fixing it now means everything downstream inherits precise scores.

---

## What this enhancement does

1. Adds a CVSS 3.x base score parser to `arguss/lenses/vulnerability.py` (or a small helper module if the lens file gets too long)
2. Updates `_extract_cvss` to use the parser before falling back to severity strings
3. Adds tests for the parser against known CVSS vectors with known scores
4. Updates `docs/qanda/vulnerability-lens.md` to reflect the new behavior

## What this enhancement does NOT do

- CVSS 4.0 parsing (rare in OSV data today; defer to Week 10 if needed)
- CVSS temporal or environmental score adjustments (only base scores)
- A standalone CVSS library or PyPI package wrapper (keep it internal, simple)
- Changes to the lens's external interface (scan signature, return shape, etc.)

---

## Before pasting into Cursor

You're already on `feature/vulnerability-lens`. Verify the previous commit is in:

```bash
git status                          # On branch feature/vulnerability-lens, clean
git log --oneline -3                # Should show your earlier lens work
uv run pytest -v                    # All 53 tests still green
```

---

## The prompt to paste into Cursor

I'm extending the vulnerability lens to parse CVSS:3.x base score vectors directly, instead of quantizing scores to severity buckets. The lens currently maps "HIGH" → 7.5 (and similar fixed values for other severity strings), which produces only 4 distinct lens scores ({25, 50, 75, 95}) across all findings. This change parses the CVSS vector string (e.g., `CVSS:3.1/AV:N/AC:L/...`) into a precise base score.

**The work:**

1. Add a CVSS 3.x base score calculator. Either inline in `arguss/lenses/vulnerability.py` or as a small helper module `arguss/lenses/_cvss.py` — your judgment based on length. If the parser exceeds ~80 lines, prefer a separate module.

2. Update `_extract_cvss` in `arguss/lenses/vulnerability.py` to call the parser before falling back to the severity-string lookup. New extraction order:
   - **Pass 1 (NEW):** Walk `vuln["severity"][i]` entries. For each entry where `type == "CVSS_V3"` and `score` is a vector string, parse it and return the base score. Use the highest CVSS score across entries if multiple are present.
   - **Pass 2:** `vuln["database_specific"]["cvss_score"]` (existing direct-numeric path).
   - **Pass 3:** `vuln["database_specific"]["cvss"]["score"]` (existing alternative nesting).
   - **Pass 4:** `vuln["database_specific"]["severity"]` string lookup (existing fallback).
   - **Pass 5:** Return None.

3. Tests for the CVSS parser. At minimum:
   - The path-to-regexp vector you already have: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` should compute to **7.5**.
   - A "Critical" vector with all max-impact components: should compute to a value > 9.0.
   - A "Low" vector with minimal impact: should compute to a value < 4.0.
   - A vector with unchanged scope and a high-impact triad (CIA all High): well-known result.
   - An invalid vector string should return None, not raise.
   - An empty or missing vector should return None.

4. Update the existing scan-level tests in `tests/test_vulnerability_lens.py` to reflect that scores are no longer quantized to fixed values. Where a test asserts `score == 75.0`, change it to `score >= 70.0` (or similar range-based assertion). The exact values depend on the test mock data.

5. Update `docs/qanda/vulnerability-lens.md`:
   - Remove the "Why does the lens score quantize to 25/50/75/95?" question (or rewrite it to "Why did v1 quantize, and what changed?")
   - Add a new question explaining the CVSS vector parsing

**The CVSS 3.x base score algorithm:**

This is well-documented. The official spec is at https://www.first.org/cvss/v3.1/specification-document. Here's the structure:

```
CVSS 3.1 base score formula:

ISS (Impact Subscore Subscore) = 1 - ((1 - C) × (1 - I) × (1 - A))
  where C, I, A are the confidentiality, integrity, availability scores
  (each mapped from H=0.56, L=0.22, N=0)

Impact = if Scope == "Unchanged":  6.42 × ISS
         else (Scope == "Changed"): 7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15

Exploitability = 8.22 × AV × AC × PR × UI
  where:
    AV (Attack Vector):    N=0.85, A=0.62, L=0.55, P=0.20
    AC (Attack Complexity): L=0.77, H=0.44
    PR (Privileges Required, Scope-dependent):
      If Scope == "Unchanged":  N=0.85, L=0.62, H=0.27
      If Scope == "Changed":    N=0.85, L=0.68, H=0.50
    UI (User Interaction):  N=0.85, R=0.62

Base Score = if Impact <= 0: 0
             else if Scope == "Unchanged": min(10, ceil_to_one_decimal(Impact + Exploitability))
             else: min(10, ceil_to_one_decimal(1.08 × (Impact + Exploitability)))

ceil_to_one_decimal(x) rounds UP to the nearest 0.1 (not standard rounding).
```

**Subtleties to handle:**

- **Round-up vs round-half.** CVSS uses *ceiling* to one decimal, not standard rounding. `7.493` → `7.5`. `7.451` → `7.5`. `7.401` → `7.5`. Implement this explicitly.
- **PR scoring depends on Scope.** This is the most-forgotten part of CVSS. The PR multiplier changes based on whether Scope is Unchanged or Changed.
- **Invalid metrics return None.** If the vector has unknown letters (e.g., `AV:X` instead of `AV:N`), or is malformed, return None rather than raising. Let the fallback chain handle it.
- **The vector prefix can be `CVSS:3.0` or `CVSS:3.1`.** Both use the same algorithm. Accept either.

**Parser interface (suggested):**

```python
def parse_cvss3_vector(vector: str) -> float | None:
    """Parse a CVSS 3.x vector string and return the base score.

    Returns None if the vector is malformed, has unknown metric values,
    or isn't a CVSS 3.x vector (e.g., CVSS 2.0, CVSS 4.0).
    """
```

Internal helpers as needed — you can decompose this however makes sense.

**Verification commands I'll run:**

```bash
# Parser unit tests
uv run pytest tests/test_vulnerability_lens.py::TestCvssParser -v

# Full lens tests
uv run pytest tests/test_vulnerability_lens.py -v

# Full suite still green
uv run pytest

# The money shot — REAL CVSS scores in the output
uv run arguss scan tests/fixtures/lockfiles/real-world.json --format pretty

# JSON inspection of finding scores
uv run arguss scan tests/fixtures/lockfiles/real-world.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = data['lens_scores']['cve']['findings']
scores = sorted({f['score'] for f in findings}, reverse=True)
print(f'Distinct scores: {scores}')
print(f'CVE lens score: {data[\"lens_scores\"][\"cve\"][\"score\"]}')
print(f'Overall: {data[\"overall\"]}')
"
```

After this change, the distinct scores list should look like `[75.0, 73.0, 65.0, 50.0, 39.0, 25.0]` (something with multiple values, not just {25, 50, 75, 95}). The CVE lens score should reflect the actual maximum CVSS in the data, which for the express tree is probably ~75 (path-to-regexp ReDoS).

**Start by:** Showing me your CVSS parser implementation (just the `parse_cvss3_vector` function and any helpers). Verify it against the test cases I listed before integrating it into the lens. I want to review the algorithm before you wire it up.

After my review, integrate it into `_extract_cvss` and update the tests.

---

## A few well-known CVSS vectors with known scores

Use these as test cases to validate your parser:

| Vector | Expected base score |
|---|---|
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 7.5 (path-to-regexp ReDoS — what your fixture has) |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 (well-known max-impact unchanged-scope) |
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 (max-impact changed-scope, capped) |
| `CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N` | 2.5 (low-impact local with all friction) |
| `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 (CVSS 3.0 of same vector — same result) |

These are publicly documented in NIST's CVSS calculator. If your parser produces different values, the algorithm has a bug.

---

## Common pitfalls

**"My parser produces 7.4 for path-to-regexp instead of 7.5."** Likely a rounding issue. CVSS uses ceiling-to-one-decimal, not standard rounding. A computed `7.401` should round UP to `7.5`. Implement `math.ceil(x * 10) / 10` explicitly.

**"The score for a Changed-scope vector seems too low."** The 1.08 multiplier for Changed scope is easy to forget. And PR uses different values when Scope is Changed.

**"All scores come out as 10.0."** You're probably treating an undefined metric value as the max. Check that `AC:X` (invalid value) returns None, not a default high score.

**"Some real OSV vectors have extra metrics I don't recognize."** OSV sometimes appends environmental or temporal metrics (E:F, RL:O, etc.). For base score, ignore everything except the 8 base metrics: AV, AC, PR, UI, S, C, I, A. Parse only those; ignore the rest.

**The CLI output still shows quantized scores.** Restart your shell or clear `__pycache__/` — Python sometimes caches the old bytecode.

---

## Why a separate module might be worth it

If your CVSS parser ends up >80 lines, put it in `arguss/lenses/_cvss.py` instead of bloating `vulnerability.py`. Two reasons:

1. **Testability.** The parser is a pure function with deterministic inputs/outputs. Easier to test in isolation than buried in the lens.
2. **Reuse.** When you add EPSS/KEV in Week 10, the trust lens might also want CVSS for cross-referencing. Having the parser in a shared module saves duplication.

If under 80 lines, inlining it in `vulnerability.py` is fine.

---

## Commit, PR, merge

After the enhancement is done and verified:

```bash
uv run pytest -v
uv run ruff format .
uv run ruff check .
uv run mypy arguss

# Verify scoring is no longer quantized
uv run arguss scan tests/fixtures/lockfiles/real-world.json --format pretty

git add -A
git commit -m "week3: parse CVSS 3.x vectors for precise vulnerability scoring"
git push
```

The PR description from the previous commit on this branch can be expanded:

```markdown
## Summary

Replaces the fake vulnerability lens with a real OSV-backed implementation. The express@4.17.0 fixture now produces 12 real CVE findings across body-parser, cookie, express, path-to-regexp, qs, send, and serve-static — with specific upgrade target versions in the remediation field.

Includes CVSS 3.x vector parsing for precise scoring. Previously v1 quantized severities to {25, 50, 75, 95} via severity-string lookup; the parser now extracts exact CVSS base scores from OSV's severity[] vectors (e.g., 7.5 for path-to-regexp ReDoS, computed from CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

## What's in this PR

### Vulnerability lens (`arguss/lenses/vulnerability.py`)
- ... (existing summary from prior commit)

### CVSS parser (`arguss/lenses/_cvss.py` or inline)
- Parses CVSS:3.0 and CVSS:3.1 base score vectors
- Uses the official FIRST.org base score formula
- Returns None for malformed or non-CVSS-3.x vectors (falls back to severity-string extraction)
- Tested against well-known CVSS vectors with documented expected scores

### Q&A doc updates
- Removed the obsolete "Why does the lens score quantize?" question
- Added "How does the lens compute CVSS base scores?" with algorithm details
```

---

## What you should have at the end

1. CVSS parser implementation (well-tested, returns float or None)
2. `_extract_cvss` updated to use parser first, fall back as before
3. New parser tests pass against well-known CVSS vectors
4. Existing lens tests updated where they assumed quantized scores
5. Full suite at 60+ tests, all green
6. **Real scan shows non-quantized scores** — at least 5+ distinct score values across findings
7. Q&A doc updated

When all of that's true, ping me with:

- The "Distinct scores" output from the verification snippet
- The CVE lens score (should match the precise CVSS of the worst finding)
- How long it took
- Anything tricky about the CVSS parsing
