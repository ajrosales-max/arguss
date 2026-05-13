# Cursor prompt — Week 3, Step 2+3: parser + CLI wiring

This is the second branch of Week 3. Goal: implement the package-lock.json v3 parser and wire it into the CLI to replace the `_fake_deps()` placeholder.

**Branch name:** `feature/parser`

**Estimated time:** 3-5 hours of focused work. This is the meaty branch of the week — give it the attention it deserves. Parser bugs propagate everywhere.

**Steps from the Week 3 plan combined into this branch:** Step 2 (parser module + tests) and Step 3 (CLI wiring). They go together because the CLI change is small and depends on the parser being done.

---

## Before pasting into Cursor

Start from clean main with the fixtures merged:

```bash
git checkout main
git pull
git checkout -b feature/parser

# Verify the fixtures from the previous branch are present
ls tests/fixtures/lockfiles/
# Should show: README.md, minimal.json, real-world.json, with-transitive.json

# Verify the existing tests still pass
uv run pytest
```

If anything is missing or red, fix it before continuing. The parser work depends on the fixtures being there.

---

## The prompt to paste into Cursor

I'm working on Week 3 of the Arguss capstone. The fixtures branch has merged and now I'm implementing the package-lock.json v3 parser and wiring it into the CLI.

The full spec is in `docs/planning/week-3-plan.md` — please refer to **Steps 2 and 3** in that document for the complete file contents and acceptance criteria.

**What to build, in this order:**

1. `arguss/core/parser.py` — implements `parse_lockfile(path)` per the spec in Step 2. Use the exact code I provided in the Week 3 plan; don't paraphrase or restructure.

2. `tests/test_parser.py` — implements the test suite from Step 2. Use the exact tests I provided.

3. **Stop and let me verify.** Run `uv run pytest tests/test_parser.py -v` myself. If anything fails, we'll diagnose together before continuing.

4. After parser tests are green, update `arguss/cli.py` per Step 3:
   - Add the import: `from arguss.core.parser import ParserError, parse_lockfile`
   - Replace the `_fake_deps()` call with `parse_lockfile(project_path)` wrapped in a `try/except ParserError`
   - Delete the `_fake_deps()` function entirely
   - Don't touch anything else in the file

5. Verify the existing canary tests in `tests/test_skeleton.py` still pass — the canary test passes a minimal lockfile, which the real parser should handle fine.

**Critical rules:**

1. **Follow the Week 3 plan literally.** Use the exact function names, exact docstrings, exact algorithm. The plan's parser code has been thought through carefully; deviation introduces bugs.

2. **Don't expand the scope.** The parser supports lockfile v3 only. Don't add v1 or v2 support. Don't add npm workspaces support. Don't add support for other package managers. These are explicitly out of scope per the project plan.

3. **Don't refactor the test suite.** I provided specific test names and assertions. Use them as-is. If a test fails, that's information about what's wrong with the parser, not a sign that the test is wrong.

4. **Don't add helper utilities or abstractions.** The parser is a single function (`parse_lockfile`) plus a handful of small private helpers (`_resolve_lockfile_path`, `_load_lockfile`, `_validate_lockfile_version`, `_extract_direct_dep_names`, `_build_dependency`, `_parse_package_path`). That's it. If you find yourself wanting to add a `Parser` class or a `LockfileLoader` abstraction, stop — they're not needed.

5. **Don't add new dependencies.** Pydantic models are already imported. Path, json, etc. are stdlib. That's all you need.

6. **Test against real fixtures.** The Week 3 plan's tests reference `tests/fixtures/lockfiles/minimal.json`, `with-transitive.json`, and `real-world.json` — these exist now. Use them.

**Important subtleties to watch for:**

- **Scoped package names** like `@types/node` contain a `/`. The path-splitting logic in `_parse_package_path` has to handle this correctly. Test case for it is in the spec.
- **The root package** lives at `packages[""]` (empty string key). Direct deps are read from its `dependencies` and `devDependencies` fields. The root itself is excluded from the returned list.
- **`workspaces` entries** in `packages` won't start with `node_modules/`. The parser skips them silently (out of scope for v1).
- **`link: true` or `extraneous: true`** entries are package-lock.json artifacts that don't represent real installed dependencies. Skip them.

**Verification commands I'll run after you finish:**

```bash
uv run pytest tests/test_parser.py -v        # all parser tests green
uv run pytest                                # full suite still green
uv run arguss scan tests/fixtures/lockfiles/minimal.json
uv run arguss scan tests/fixtures/lockfiles/with-transitive.json --format pretty
uv run arguss scan tests/fixtures/lockfiles/real-world.json --format pretty
uv run ruff check .
uv run mypy arguss
```

The CLI scans should now show real dep names in the findings (not "fake-package") because the parser is feeding real data to the still-fake lenses. The lens scores will still be the fake hardcoded values (75, 40, 50) because the lenses themselves haven't been updated yet — that's Step 6's work.

**Start by:** Confirming you have access to `docs/planning/week-3-plan.md` in the workspace and you've read Steps 2 and 3. Then implement `arguss/core/parser.py` first. Show me the file contents before any tests run. Stop after the parser is written and wait for me to review.

After my review and approval, implement `tests/test_parser.py`. Then stop again so I can run the tests myself.

After tests are green, do the CLI wiring in Step 3.

---

## How to work through this with Cursor

**Pause-and-verify discipline matters more here than for fixtures.** The parser has subtle correctness requirements that won't show up as obvious errors — they show up as wrong dep counts, wrong parent relationships, or wrong path arrays. The fixtures-based tests catch these, but only if you actually run them.

The flow should be:

1. Paste the prompt
2. Cursor writes `parser.py`. **Read it before doing anything else.** Pay attention to `_parse_package_path` — that's where most bugs hide
3. Cursor writes `test_parser.py`
4. You run `uv run pytest tests/test_parser.py -v`
5. Tests pass? Continue. Tests fail? Don't ask Cursor to "fix it" — read the failure, understand why it failed, then either fix the test or fix the code
6. Cursor updates `cli.py`
7. You run the full verification suite

**If a test fails and Cursor's reflex is to weaken the test:** push back hard. The test is checking real behavior; if the test fails, the parser is wrong. Letting Cursor change the test to make the implementation pass is how subtle bugs slip into production.

---

## Reading the parser code: what to look for

Spend 5-10 minutes actually reading `parser.py` after Cursor generates it. You should be able to answer these:

1. **What happens when given a directory vs a file?** The path resolution logic in `_resolve_lockfile_path` handles both. Trace through both code paths in your head.

2. **What's the difference between `path` and `parents` on a `Dependency`?** Path is the full chain from root to this package (e.g., `["root", "chalk", "ansi-styles"]`). Parents is the immediate parent (e.g., `["chalk"]`). The path is for blast radius visualization; parents is for graph traversal.

3. **Why does `_parse_package_path` split on `/node_modules/`?** Because npm encodes nested installations using `/node_modules/` as a separator. `node_modules/foo/node_modules/bar` means "bar is installed under foo because foo needed a version different from the top-level bar."

4. **What happens with scoped packages like `@types/node`?** The package name contains a `/`, but it's NOT a `node_modules` separator. The split-on-`/node_modules/` approach handles this correctly because the split only happens on the full string `/node_modules/`, not just `/`.

5. **Why is the root package excluded from the result?** Because the root represents the project itself, not a dependency. The whole point of the parser is to enumerate what the project depends ON.

If you can answer these without re-reading the code, you understand the parser. If you can't, ask Cursor to walk you through it before continuing.

---

## After the work is done

```bash
# Final verification
uv run pytest tests/test_parser.py -v
uv run pytest
uv run arguss scan tests/fixtures/lockfiles/real-world.json --format pretty
uv run ruff check .
uv run mypy arguss

# Stage and commit
git add arguss/core/parser.py tests/test_parser.py arguss/cli.py
git commit -m "week3: package-lock.json v3 parser + cli integration"
git push -u origin feature/parser

# Open the PR
gh pr create --base main --head feature/parser \
  --title "Week 3 Step 2-3: lockfile parser + CLI integration" \
  --body "Implements package-lock.json v3 parser per docs/planning/week-3-plan.md. Replaces _fake_deps() in CLI with real parser output. Tests cover minimal, transitive, scoped packages, version rejection, and the real-world fixture. The two non-CVE lenses remain fake-stubbed until Week 4 (trust) and Week 5 (pipeline)."
```

Wait for CI green, then merge. After merge:

```bash
git checkout main
git pull
git checkout -b feature/osv-client
```

Then come back to me for the OSV client prompt.

---

## Common pitfalls and how to spot them

**The real-world fixture has more or fewer deps than expected.** The Week 3 plan's test asserts `len(deps) > 20`. Your fixture has 50, so this should pass easily. If it fails:
- Either the parser is dropping deps (bug in the parser)
- Or the fixture changed since I wrote the plan (unlikely but possible)
Run `uv run python -c "from arguss.core.parser import parse_lockfile; print(len(parse_lockfile('tests/fixtures/lockfiles/real-world.json')))"` to see the exact count.

**Scoped package test fails:** This means `_parse_package_path` is mishandling `node_modules/@scope/pkg`. Check that the split happens on the full string `/node_modules/`, not just `node_modules/`. If `_parse_package_path("node_modules/@types/node")` returns `["@types", "node"]` instead of `["@types/node"]`, that's the bug.

**The canary test in `test_skeleton.py` fails:** This means the parser doesn't handle the empty/minimal lockfile case correctly. The canary writes `{"lockfileVersion": 3, "packages": {}}` — the parser should return an empty list, not crash.

**Mypy complains about untyped lockfile data:** The `dict[str, Any]` annotation on the parsed JSON is intentional. Don't let Cursor add Pydantic models for lockfile entries — the data is too heterogeneous and the validation isn't worth the schema complexity.

**Real-world scan still shows score 57:** That's correct! The lens scores are still fake (75 + 40 + 50 weighted = 57). The parser is working — you're now feeding real deps to fake lenses. Step 6 replaces the vulnerability lens with a real one and the score will reflect real findings.

---

## What you should have at the end

1. `arguss/core/parser.py` exists and works for v3 lockfiles
2. `tests/test_parser.py` exists with ~10 tests, all green
3. `arguss/cli.py` no longer references `_fake_deps`
4. Scanning a real lockfile produces real dep names in the JSON output
5. The full test suite (including the canary) is still green
6. Lint and mypy clean
7. PR open, CI green, ready to merge

When that's all true, ping me with:

- The real-world fixture's dep count from the parser (just to confirm we're seeing the same shape)
- Anything that didn't work as expected
- How long it took

Then we'll start `feature/osv-client`.
