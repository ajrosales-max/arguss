# Parser — Q&A

A walkthrough of `arguss/core/parser.py` in question-and-answer form. Useful for code review, capstone presentations, and onboarding new team members.

**File covered:** `arguss/core/parser.py`
**Last verified:** Week 3 (May 2026)

---

## 1. What happens when given a directory vs a file?

The `_resolve_lockfile_path` helper handles both cases.

If the path is a **directory**, it appends `package-lock.json` and returns that. If the file doesn't exist at that path, it raises `ParserError("No package-lock.json found in ...")`.

If the path is a **file** (or anything that's not a directory), it returns the path as-is. If the file doesn't exist, it raises `ParserError("Lockfile not found: ...")`.

This dual behavior matches what users expect from the CLI: `arguss scan ./my-project` should just work, and so should `arguss scan ./my-project/package-lock.json`. The same code path handles both.

---

## 2. What's the difference between `path` and `parents` on a Dependency?

Both fields describe a dependency's position in the tree, but at different granularities.

`path` is the **full chain from the project root** to this package. Example for `ansi-styles` installed under `chalk`:

```python
path = ["root", "chalk", "ansi-styles"]
```

`parents` is just the **immediate parent** — the package one level up:

```python
parents = ["chalk"]
```

For a direct dep `chalk` itself:

```python
path = ["root", "chalk"]
parents = ["root"]
```

The two fields exist because they're used differently:

- **`path`** powers blast radius visualization. To show "this CVE in `ansi-styles` came from your direct dep `chalk`," we walk the path backward.
- **`parents`** powers graph traversal. When the remediation ranker simulates "what if we upgrade `chalk`?" it needs to find all packages whose parent chain includes `chalk` — that's a parents-based query.

Storing both upfront is redundant in information, but free in cost, and saves recomputation during scoring.

---

## 3. Why does `_parse_package_path` split on `/node_modules/`?

Because npm's lockfile v3 encodes nested dependency installations using `/node_modules/` as a separator between levels.

When npm has to install two different versions of the same package because different parents need them, it nests one inside the other's `node_modules` folder. The lockfile path reflects that:

```
node_modules/foo                          → foo at top level
node_modules/foo/node_modules/bar         → bar installed under foo
                                            (because foo needs a version of bar
                                            different from any top-level one)
```

By splitting on the literal string `/node_modules/`, we extract the chain of package names from root to this specific installation. This is exactly the transitive path we need for blast radius analysis.

---

## 4. What happens with scoped packages like `@types/node`?

Scoped npm packages have a `/` in their name (e.g., `@types/node`, `@scope/pkg`). Naively splitting paths on `/` would break these.

The parser avoids this by splitting on the **full string** `/node_modules/`, not just `/`.

A lockfile entry like `node_modules/@types/node` is processed:

1. The path starts with `node_modules/` — strip the prefix → `@types/node`
2. Split on `/node_modules/` — no match, so the result is `["@types/node"]`
3. Package name is preserved intact

For a nested scoped package like `node_modules/foo/node_modules/@types/node`:

1. Strip the leading prefix → `foo/node_modules/@types/node`

   Wait — let's trace this more carefully. The code splits *first*, then strips:

   ```python
   parts = pkg_path.split("/node_modules/")
   # parts = ["node_modules/foo", "@types/node"]
   parts[0] = parts[0].removeprefix("node_modules/")
   # parts = ["foo", "@types/node"]
   ```

2. Result: `["foo", "@types/node"]` — chain is `foo → @types/node`, with the scoped name intact.

This is the most subtle part of the parser and the most likely place for bugs. The test `test_scoped_packages` guards against regressions.

---

## 5. Why is the root package excluded from the result?

The lockfile's `packages` dict has an entry at the empty-string key (`packages[""]`) representing the project itself. The parser's first check inside the main loop is `if pkg_path == "": continue` — it skips this entry.

The reason: we're enumerating what the project **depends on**, not the project itself. Including the root would be like a grocery list that includes "the grocery list" as an item.

The root entry isn't useless, though — `_extract_direct_dep_names` reads from `packages[""].dependencies` and `packages[""].devDependencies` to figure out which packages should be marked as `direct=True`. So we use the root's *metadata* (which deps it declares) but exclude the root itself from the output list.

---

## Architectural observations

A few higher-level notes that often come up in review:

### Why a single function instead of a class?

The parser has one input (a path), one output (a list of Dependency objects), and no state between calls. There's no benefit to wrapping it in a class — that would just add a constructor and a method call without changing behavior.

If the parser later needed to maintain state (cached parses, progress callbacks, configurable validation rules), a class might make sense. For now, a single function with small private helpers is the right level of abstraction.

### Why is `data` typed as `dict[str, Any]` instead of a Pydantic model?

Lockfile entries are heterogeneous — different package types (regular, scoped, link, workspace) have wildly different shapes. Defining a Pydantic model for every variant would be either incomplete (and break on edge cases) or extremely complex (and not actually catch bugs in the data we care about).

Instead, we validate the fields we use explicitly (`pkg_data.get("version")`, `pkg_data.get("link")`) and ignore everything else. This is a pragmatic trade: less type safety in exchange for resilience against lockfile format variation.

### Why only support lockfile v3?

Three reasons:

1. **v3 is current.** It's been npm's default since npm 7 (released October 2020). Any modern Node.js project produces v3.
2. **v1 and v2 have different shapes.** v1's `dependencies` tree is authoritative; v2's `packages` flat list is. Supporting all three would mean three parser implementations.
3. **Capstone scope.** Adding v1/v2 support would consume weeks for marginal value. Documented as future work.

The parser raises a clear error message pointing users at how to regenerate a v3 lockfile rather than silently producing wrong results.

### Why is the result sorted?

`deps.sort(key=lambda d: (d.name, d.version))` makes the output deterministic. Two runs of the parser against the same lockfile produce identical output, which means:

- Test assertions can check specific positions in the list
- Cache keys based on dep lists are stable (the same deps in the same order produce the same hash)
- Diff-based tooling (CI output comparison, regression testing) works correctly

Sorting is cheap (the dep count is hundreds, not millions) and the determinism is worth the cost.

---

## What this parser doesn't do (deliberate scope limits)

Documented for review and for the team's future-work backlog:

- **Lockfile v1 and v2** — raises an error pointing at npm 7+ for upgrade
- **npm workspaces** — workspace entries don't start with `node_modules/` so they're silently filtered out
- **Yarn lockfiles** — different format entirely; would need a separate parser
- **pnpm lockfiles** — same, different format
- **Resolution of version ranges to specific versions** — the lockfile already did this; we trust it
- **Validation of integrity hashes** — that's npm's job at install time
- **Detection of typosquats or suspicious packages** — that's the trust signal lens's job, not the parser's

Every one of these is a legitimate feature for a future version. None of them belong in the parser as long as the project is npm-focused and capstone-scoped.

How are logical dependency relationships resolved?
The parser runs in two passes:
Pass 1 reads the lockfile's packages dict and produces Dependencies from the physical layout — the actual paths under node_modules/. This captures where files live on disk.
Pass 2 walks each package's declared dependencies field and builds a logical graph: which package declared a need for which other package. The Dependencies' parents and path are then updated to reflect logical relationships rather than physical layout.
Why this matters: npm often installs a transitive dep at the top level of node_modules/ when no version conflict requires nesting. The lockfile's physical path then loses information about which package brought it in. By reading each package's dependencies field, we reconstruct the logical relationship that the original package.json files declared.
Multi-parent case: if multiple packages need the same dep (e.g., both body-parser and cookie-signature need safe-buffer), all are listed in parents. The path uses the shortest route from root to the dep, with lexicographic tiebreaking for determinism.
