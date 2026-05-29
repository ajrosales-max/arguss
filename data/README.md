# Static data for Arguss

## Files

| File | Purpose |
|------|---------|
| `npm-top-1000-YYYY-MM.txt` | Typosquat baseline for the trust lens (see below). Current: `npm-top-1000-2026-05.txt`. |

## `npm-top-1000-YYYY-MM.txt`

One npm package name per line, sorted lexicographically. Lines starting with `#` are ignored. Used by the trust lens
(`arguss.lenses.trust`) as the typosquat baseline: Levenshtein distance is
computed against this set.

### Source

We originally aimed to vendor a snapshot from
[anvaka/npmrank](https://github.com/anvaka/npmrank) GitHub **Releases**, but that
repository has **no published release assets** (the Releases API returns an
empty list). The checked-in list is therefore generated with
`scripts/refresh-top-1000.py`, which:

1. Seeds a curated set of widely depended-on package names.
2. Paginates the **npm Registry search** endpoint (`/-/v1/search`) for a fixed
   set of short two-letter `text` queries (the API requires `text` length
   2–64), deduplicates, then **retains all curated seed names** plus other
   matches in lexicographic order until 1000 lines are filled (so popular
   unscoped packages are not dropped when many `@scope/…` names sort first).

This is a **slow-moving heuristic** list (not a formal PageRank export). Regenerate
once per semester or when npm search behavior shifts materially.

### Refresh (manual; not CI)

From the repository root:

```bash
uv run python scripts/refresh-top-1000.py
# or an explicit filename:
uv run python scripts/refresh-top-1000.py -o data/npm-top-1000-2026-08.txt
```

The loader in `arguss/lenses/trust.py` picks the **lexicographically last**
`npm-top-1000-*.txt` in this directory so newer `YYYY-MM` stamps win when
multiple files exist.

Requires outbound HTTPS to `registry.npmjs.org`. If you see HTTP 429, rerun
after a few minutes; the script backs off between pages.

## Refresh cadence

The list is refreshed manually before evaluation milestones, not on a schedule.
Recommended cadence: once per semester, or before major evaluation pushes
(Week 11 evaluation, Week 14 showcase). The list's accuracy is bounded by
popularity rankings that shift slowly; intra-semester drift is negligible
for typosquat detection.

## To refresh

```bash
uv run python scripts/refresh-top-1000.py
git add data/npm-top-1000-*.txt
git commit -m "data: refresh top-1000 npm list"
```

The trust lens loader picks the newest file by sort order, so old snapshots
can remain in the repo as historical record.
