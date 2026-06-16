# Static data for Arguss

## Files

| File | Purpose |
|------|---------|
| `npm-top-1000-YYYY-MM.txt` | Typosquat baseline for the trust lens (see below). Current: `npm-top-1000-2026-06.txt`. |

## `npm-top-1000-YYYY-MM.txt`

One npm package name per line, in download-rank order. Lines starting with `#` are ignored. Used by the trust lens
(`arguss.lenses.trust`) as the typosquat baseline: Levenshtein distance is
computed against this set (order is irrelevant to the frozenset loader).

### Source

The checked-in list is generated with `scripts/refresh-top-1000.py`, which exports
the top 1000 package names from a download-ranked upstream source:

1. **npm-high-impact** ([wooorm/npm-high-impact](https://github.com/wooorm/npm-high-impact)) —
   fetched from `registry.npmjs.org` (built from ecosyste.ms download counts).
2. **npm-rank** ([tristan-f-r/npm-rank](https://github.com/tristan-f-r/npm-rank)) —
   fallback release asset if (1) is unavailable.

This is a **download-ranked export**, not an npm search relevance heuristic. Regenerate
once per semester or when upstream ranking methodology shifts materially.

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

Requires outbound HTTPS to `registry.npmjs.org` (and GitHub for the npm-rank
fallback). If all sources fail, keep the existing checked-in file.

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

Keep only the newest snapshot in the repo; delete older `npm-top-1000-*.txt`
files when refreshing.
