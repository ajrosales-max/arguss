# package-lock.json parser (Q&A)

## What does `parse_lockfile` do?

It reads npm **lockfileVersion 3** `package-lock.json` (or a directory containing it) and returns a sorted list of `Dependency` models: name, version, ecosystem, `direct`, `parents`, and `path`.

## Two passes — physical then logical

**Pass 1 (unchanged):** Walk `packages` entries under `node_modules/…` (skip root, link, extraneous, non-`node_modules` keys). Each row becomes one `Dependency` with:

- **`direct`:** whether the name appears under the root package’s `dependencies` or `devDependencies` (same as npm’s “direct” notion for the project).
- Initial **`path`** and **`parents`:** derived from the **physical** install path (hoisting / nesting in `node_modules`).

**Pass 2 (`_resolve_logical_relationships`):** Re-reads the full `packages` map and rebuilds **`parents`** and **`path`** from **who depends on whom** in the lockfile:

- For **`packages[""]`** (the project root), edges are built from both **`dependencies`** and **`devDependencies`** (so dev-only installs still get `root` as a logical parent when nothing else depends on them).
- For every other package entry, only **`dependencies`** are used (a library’s devDependencies are not installed when you depend on that package).

Child names that are not in the pass-1 dependency set (optional installs not present, etc.) are skipped.

## What do `parents` and `path` mean after pass 2?

- **`parents`:** Sorted list of logical parent package names (or `"root"`). A package can have multiple parents if several packages declare it in their `dependencies`.
- **`path`:** Shortest path from `"root"` to this package along those logical edges. If two paths have the same length, the predecessor is chosen by **lexicographically smallest parent** name so output is stable.

Unreachable edge cases fall back to `["root", "<name>"]` for `path` while `parents` still default to `["root"]` when nothing else recorded the child.

## What is explicitly out of scope?

- Lockfile v1/v2, npm workspaces-only paths, other package managers — same as Week 3 plan.
