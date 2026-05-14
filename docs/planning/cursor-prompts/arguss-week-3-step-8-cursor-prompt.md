# Cursor prompt — Week 3, Step 8: CycloneDX SBOM generator

This branch adds a CycloneDX 1.5 SBOM generator. It produces a valid CycloneDX JSON document from the parser's output, exposed via a new CLI subcommand `arguss sbom <path>`.

**Branch name:** `feature/sbom-generator`
**Estimated time:** 2-3 hours of focused work.
**Step from Week 3 plan:** Step 8.

---

## Why this matters for the project

SBOMs are part of your "Why" story (EO 14028 mandates them for federal software, SSDF requires them, industry adoption is climbing). Having a real, validated SBOM generator that produces output Snyk-compatible tools can consume:

- Adds a tangible compliance-aligned deliverable to the showcase
- Demonstrates the parser output is rich enough to produce real industry artifacts
- Is a free win — your dependency graph already has everything an SBOM needs
- Pairs well with the vulnerability lens for the final demo ("here's the SBOM, here are the vulnerabilities in it")

This branch is short on novel engineering but produces a genuinely useful output that ages well.

---

## What this branch does

1. Implements a CycloneDX 1.5 SBOM generator in `arguss/core/sbom.py`
2. Adds an `arguss sbom <path>` CLI subcommand that writes the SBOM to stdout or a file
3. Adds tests verifying the output structure and validity
4. Adds documentation explaining the SBOM design and what it includes/excludes
5. Optional: validates output against the official CycloneDX schema as part of the test suite

## What this branch does NOT do

- CycloneDX 1.6 (latest spec, but most consumers still target 1.5)
- SPDX format (different SBOM standard; we're picking one)
- Vulnerability annotations inside the SBOM (CycloneDX supports this; it'd require running the lens during SBOM generation; defer to v2)
- Cryptographic signing of the SBOM (defer to v2)
- A pull-from-URL option (just file paths for now)

---

## Before pasting into Cursor

Start from clean main:

```bash
git checkout main
git pull
git checkout -b feature/sbom-generator

git log --oneline -5    # confirm integration-tests merged
ls arguss/core/         # see models.py, parser.py, cache.py — no sbom.py yet
```

---

## The prompt to paste into Cursor

I'm implementing Week 3 Step 8: a CycloneDX 1.5 SBOM generator. The full spec is in `docs/planning/week-3-plan.md` under Step 8.

**The goal:** `arguss sbom <path>` produces a CycloneDX 1.5 JSON SBOM from a project's `package-lock.json`. Reuses the existing parser; no new external API calls.

**File to create: `arguss/core/sbom.py`**

Public function: `generate_sbom(deps, project_name, project_version) -> dict[str, Any]`.

Returns a JSON-serializable dict ready to write to disk or send as an HTTP response. NOT a Pydantic model — CycloneDX has many optional fields and our v1 only populates a subset; using `dict[str, Any]` keeps the surface small.

**CycloneDX 1.5 structure (the parts we generate):**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-13T...",
    "tools": {
      "components": [
        {
          "type": "application",
          "vendor": "Arguss",
          "name": "arguss",
          "version": "0.1.0"
        }
      ]
    },
    "component": {
      "type": "application",
      "bom-ref": "pkg:project/<project-name>@<version>",
      "name": "<project-name>",
      "version": "<version>"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/<dep-name>@<dep-version>",
      "name": "<dep-name>",
      "version": "<dep-version>",
      "purl": "pkg:npm/<dep-name>@<dep-version>",
      "scope": "required"
    },
    ...
  ],
  "dependencies": [
    {
      "ref": "pkg:project/<project-name>@<version>",
      "dependsOn": ["pkg:npm/<direct-dep1>@<v>", ...]
    },
    {
      "ref": "pkg:npm/<dep1>@<v>",
      "dependsOn": ["pkg:npm/<sub-dep1>@<v>", ...]
    }
  ]
}
```

**Key implementation requirements:**

1. **purl format.** Each dep becomes `pkg:npm/<name>@<version>`. Scoped packages like `@types/node` need the `@` URL-encoded as `%40`: `pkg:npm/%40types/node@<version>`. This is the [purl spec for npm](https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#npm).

2. **Component deduplication.** A dep can appear multiple times in the dep tree at different paths (we resolved logical relationships in the parser, but the same `name@version` is one component in the SBOM). Dedupe by `name@version` before emitting components.

3. **The `dependencies` array is the LOGICAL graph, not physical.** This is where the parser's logical graph work pays off. Build the dependency relationships using each `Dependency.parents` field — parent (or "root" for project root) `dependsOn` this dep.

4. **Root component bom-ref.** Use a custom purl-style ref for the project itself: `pkg:project/<name>@<version>`. (purl doesn't have a standard scheme for "the thing being analyzed"; this is a convention.)

5. **Determinism.** The SBOM should be reproducible — same input always produces same output (except timestamps and UUIDs, which are inherently new each run). Sort components by `(name, version)`. Sort `dependsOn` arrays alphabetically. This makes diffing two SBOMs across runs meaningful.

6. **No external dependencies.** Don't pull in `cyclonedx-bom` or similar libraries. Build the dict by hand. ~150 lines of code total. This keeps Arguss's own dep tree minimal (which matters for a supply chain tool).

**CLI subcommand in `arguss/cli.py`:**

Add a new `@app.command()` for `sbom`:

```python
@app.command()
def sbom(
    path: str = typer.Argument(..., help="Path to project root or package-lock.json"),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write SBOM to this file. Default: stdout.",
    ),
    project_name: str | None = typer.Option(
        None,
        "--name",
        help="Project name for the SBOM root component. Default: directory name.",
    ),
) -> None:
    """Generate a CycloneDX 1.5 SBOM for the given project."""
    ...
```

Behavior:
- If `--output` is provided, write to file and print "SBOM written to <file>"
- Otherwise, print JSON to stdout (pretty-printed with `indent=2`)
- If `--name` is provided, use it; otherwise derive from the directory name

**Tests: `tests/test_sbom.py`**

Cover:

1. Minimal SBOM has correct top-level structure (bomFormat, specVersion, serialNumber, components, dependencies)
2. Empty deps list produces a valid SBOM (no components, dependencies array has only the root)
3. Scoped packages produce correctly-URL-encoded purls (`@types/node` → `pkg:npm/%40types/node@<v>`)
4. Components are deduplicated (same `name@version` at multiple paths → one component)
5. Dependency graph uses logical relationships (root depends on direct deps; direct deps depend on their transitives)
6. Output is deterministic (same input → same output except timestamps and UUIDs)
7. End-to-end: parse `tests/fixtures/lockfiles/real-world.json`, generate SBOM, verify component count matches dep count

**Validation (optional but recommended):**

Add a separate test that validates the output against the official CycloneDX schema using `cyclonedx-bom` (pip install only — not a dependency of Arguss itself). Mark this test `@pytest.mark.skipif(not has_cyclonedx_tool(), ...)` so it's skipped when the validator isn't installed.

If skipping the validation test entirely is cleaner, that's fine — the unit tests cover the structural requirements.

**Documentation: `docs/qanda/sbom-generator.md`**

Cover:

1. **What is a CycloneDX SBOM and why do we generate one?**
2. **What's in the SBOM we generate?** (the component list with names, versions, purls; the dependency graph)
3. **What's NOT in the SBOM?** (vulnerability annotations, hashes, supplier info, licenses — all defer to v2)
4. **What spec version do we use and why?** (1.5; 1.6 is newer but tooling lags)
5. **How does the dependency graph in the SBOM relate to our internal model?** (uses logical parents from the parser; same data, different format)
6. **How do we handle scoped npm packages in purls?** (URL-encoding per purl spec)

**Verification commands I'll run:**

```bash
# Unit tests pass
uv run pytest tests/test_sbom.py -v

# Full suite still green
uv run pytest

# Lint and types
uv run ruff check .
uv run ruff format --check .
uv run mypy arguss

# Generate an SBOM from the real-world fixture
uv run arguss sbom tests/fixtures/lockfiles/real-world.json -o /tmp/test-sbom.json

# Inspect the output structure
python3 -c "
import json
sbom = json.load(open('/tmp/test-sbom.json'))
print(f'Spec: {sbom[\"specVersion\"]}')
print(f'Format: {sbom[\"bomFormat\"]}')
print(f'Components: {len(sbom[\"components\"])}')
print(f'Dependencies: {len(sbom[\"dependencies\"])}')
print(f'Tool: {sbom[\"metadata\"][\"tools\"][\"components\"][0][\"name\"]}')
print(f'Root: {sbom[\"metadata\"][\"component\"][\"name\"]}')
print()
print('First 3 components:')
for c in sbom['components'][:3]:
    print(f'  {c[\"name\"]}@{c[\"version\"]} → {c[\"purl\"]}')
"

# Optional: validate against CycloneDX schema (requires `pip install cyclonedx-bom`)
# (You don't need to run this; it's just a verification path)
```

After this branch, the real-world SBOM should have:
- 50 components (matches dep count from the parser)
- 51 dependency entries (root + each non-leaf dep)
- All purls in `pkg:npm/...` format
- Components sorted by `(name, version)`

**Start by:** Showing me the `generate_sbom` function and helpers (`_purl`, `_build_dependency_graph`). I want to review the purl construction and the dependency graph building before you wire up tests and CLI. Don't write the CLI subcommand or tests yet.

After my review, implement the CLI subcommand. Then tests. Then the Q&A doc.

---

## How to work through this with Cursor

**After Cursor shows you `sbom.py`:**

The two parts to read carefully are `_purl` (scoped package URL encoding) and `_build_dependency_graph` (uses each Dependency's `parents` field to construct the CycloneDX `dependencies` array). The rest is straightforward dict construction.

**Quick mental test for the dependency graph:**

For your `with-transitive.json` fixture (chalk@4.1.2 with ~7 deps):

- The project root depends on `chalk`
- `chalk` depends on `ansi-styles`, `supports-color` (its declared deps)
- `ansi-styles` depends on `color-convert`
- `color-convert` depends on `color-name`

The `dependencies` array should reflect all of this, with each entry's `ref` being a purl and `dependsOn` being a sorted list of purls.

**After tests are written:**

Run them. Then run the end-to-end generation against `real-world.json`. Open the output file in your editor. The first 100 lines should look like a real SBOM — bomFormat, specVersion, serialNumber, metadata, and the start of the components array with real express-tree packages.

**Optional validation:**

If you want to verify CycloneDX compliance externally:

```bash
pip install cyclonedx-bom    # NOT in our pyproject.toml — local-only verification
cyclonedx validate --input-file /tmp/test-sbom.json
```

Should print "BOM is valid". If it errors, your output doesn't match the spec — investigate which field is wrong.

---

## Common pitfalls

**Scoped packages produce broken purls.** If `@types/node` becomes `pkg:npm/@types/node@1.0.0` instead of `pkg:npm/%40types/node@1.0.0`, validators will reject it. The `@` character has special meaning in purls and must be encoded.

**Component count doesn't match dep count.** Probably a deduplication bug — same package@version producing multiple components. Or the opposite: real distinct packages being merged because the dedup key is too broad.

**The dependency graph is missing entries.** Every package that has children should appear as a `ref` in the `dependencies` array. Leaf packages (no children) don't need an entry. The root project always has an entry (its `dependsOn` is the direct deps).

**Output is non-deterministic.** Two runs produce different SBOMs even with the same input (besides timestamps/UUIDs). Likely cause: dict iteration order in a Python version where it's not guaranteed insertion-ordered, or `set` iteration without sorting. Fix: explicitly sort everything you emit as a list.

**SBOM doesn't have a root component.** `metadata.component` is required for a valid SBOM. Make sure the root is being added.

---

## Commit, PR, merge

```bash
uv run pytest -v
uv run ruff format .
uv run ruff check .
uv run mypy arguss

# Verify SBOM generation works end-to-end
uv run arguss sbom tests/fixtures/lockfiles/real-world.json -o /tmp/test-sbom.json
ls -la /tmp/test-sbom.json    # should exist and be a few KB
python3 -m json.tool /tmp/test-sbom.json | head -30    # should be valid JSON

# Commit
git add -A
git commit -m "week3: cyclonedx 1.5 sbom generator + arguss sbom cli subcommand"
git push -u origin feature/sbom-generator

# Open PR
gh pr create --base main --head feature/sbom-generator \
  --title "Week 3 Step 8: CycloneDX 1.5 SBOM generator" \
  --body "Generates valid CycloneDX 1.5 JSON SBOMs from the parser output. Adds 'arguss sbom <path>' CLI subcommand with stdout or file output. The SBOM reflects the logical dependency graph (which package needs which) rather than the physical lockfile layout. Aligns with EO 14028 SBOM compliance requirements.

Component count, dependency graph, and purl format verified against tests/fixtures/lockfiles/real-world.json (50 components, 51 dependency entries).

Out of scope for v2: vulnerability annotations inside the SBOM, hashes, supplier info, license data, cryptographic signing."
```

---

## What you should have at the end

1. `arguss/core/sbom.py` exists with `generate_sbom()` and helpers
2. `arguss/cli.py` has the new `sbom` subcommand
3. `tests/test_sbom.py` with 7+ tests, all passing
4. `docs/qanda/sbom-generator.md` documenting the design
5. Full test suite at 70+ tests, all green
6. `arguss sbom tests/fixtures/lockfiles/real-world.json` produces a valid CycloneDX 1.5 JSON document
7. Optionally: validates against the official CycloneDX schema via `cyclonedx-bom`

When all of that's true, ping me with:

- The SBOM inspection output (component count, dependency count, first few components)
- Time taken
- Anything Cursor surprised you with

This wraps Week 3. After this merges, you have a complete Week 3 deliverable set:
- Parser with logical dep graph
- OSV client with caching and batching
- Real vulnerability lens with CVSS vector parsing
- Integration tests against real production data
- Working CycloneDX SBOM generator

Then we start Week 4 (trust signal lens) — the next big build.
