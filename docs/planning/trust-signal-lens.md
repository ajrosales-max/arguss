# Trust signal lens — design (Branch 1 snapshot)

This document describes the **Week 4 Branch 1** trust snapshot layer: frozen `TrustSnapshot` records built from the npm registry, the npm downloads API, and a **bundled** top-1000 popularity list. Branch 1 does **not** wire trust into unified scoring or the real `TrustLens` scan path; that is **Branch 2** (`feature/trust-delta`). The public inspection surface today is **`arguss trust-snapshot <package> <version>`** and the `fetch_snapshot` API used by tests.

## Consumers

| Consumer | When | What it uses |
|----------|------|----------------|
| **PRS / risk rollup** | Present and future | `TrustSnapshot.subscore` (0–100, higher = riskier). Same shape as other lens subscores feeding the existing path. |
| **Agent veto / fix confidence** | Branch 2 onward | **TrustDelta**: diffs between successive snapshots and structured fields (maintainers, cadence, typosquat, downloads). Week 6 fix-confidence will consume the structured snapshot, not only the scalar. |

## `TrustSnapshot` fields

| Field | Justification |
|-------|----------------|
| `package`, `version` | Identity of the evaluated coordinate (npm ecosystem). |
| `captured_at` | When this snapshot was materialized (UTC). Enables TTL, audits, and delta windows. |
| `maintainer_count`, `maintainer_logins` | Maintainer breadth from the packument (sorted logins for stable equality and storage). Feeds sole-maintainer risk and future maintainer-churn deltas. |
| `published_at` | When this **version** was published (from npm `time`). |
| `days_since_previous_publish` | Calendar **whole days** between this version’s publish time and the chronologically previous version’s publish time; `None` if this is the **first** published version in `time`. Supports cadence anomalies and Branch 2 deltas. |
| `typosquat_distance`, `typosquat_nearest` | Min Levenshtein distance to the bundled top-1000 set; nearest name at that distance (ties broken lexicographically). If the package is **in** the top-1000, distance is `0` and nearest is **self**. If the list is missing/empty, both are `None`. |
| `weekly_downloads` | Last-week download count from `api.npmjs.org`; `None` when unavailable (e.g. 404); `0` is a real reported zero. |
| `subscore` | Weighted combination of simple v1 signals (capped at 100). See below. |

## v1 subscore weights

Implemented as `TRUST_SUBSCORE_WEIGHTS` in `arguss/lenses/trust.py`. Contributions **sum** and are **capped at 100**.

| Signal | Default points | Condition |
|--------|------------------|-----------|
| Sole maintainer | 30 | `maintainer_count == 1` |
| Young package | 20 | First package publish within the last **90** days |
| Typosquat distance 1 | 25 | Package **not** in top-1000 **and** min distance `== 1` |
| Typosquat distance 2 | 15 | Package **not** in top-1000 **and** min distance `== 2` |
| Low weekly downloads | 10 | `weekly_downloads` is not `None` and **< 1000** |

Threshold `young_package_days` is **90**; `low_weekly_downloads_threshold` is **1000**.

## Cache strategy

- **Source** in SQLite `api_cache`: `npm` (same table pattern as OSV).
- **Keys**: `npm:packument:{package}` with JSON `{"packument": ...}`; `npm:downloads:last-week:{package}` with `{"downloads": <int>}` or `{"downloads": null}` when unknown.
- **TTL**: `settings.cache_ttl_hours` (default **24** hours), applied on `set_api_response` for both packument and downloads.
- **Semantics**: Within TTL, a key is treated as **immutable** for that window—no refresh of the same key until expiry. New coordinates or cold cache perform live fetches.

Scoped names use path encoding via `urllib.parse.quote(package, safe="@")` (e.g. `@scope/name` → `@scope%2Fname` in the URL path segment).

## Top-1000 list

- **Checked into** `data/npm-top-1000-*.txt` (newest matching file by sorted glob at import time). Not fetched at runtime.
- **Refresh**: manual / scripted (see `data/README.md`). Not part of CI.

## Known limitations and interpretation notes

### 1. Sub-day publish gaps show as `0` days

`days_since_previous_publish` uses Python `timedelta.days`, which counts **whole calendar days** between the previous version’s publish timestamp and this version’s. If two releases fall on the **same calendar day** (common for pre-releases then a stable tag), the gap is **0** by design—not a bug. Human review and Branch 2 cadence logic may want wall-clock hours or same-day flags for nuance.

### 2. `@types/*` and sole-maintainer false positives

Many **DefinitelyTyped** packages list a **single** maintainer entry (often a shared bot-style account) in the npm packument. That triggers the **sole-maintainer +30** contribution even though the project is organizationally healthy. Treat as a **known false positive** in v1: acceptable for PRS with human context, or address later with a **namespace allowlist** (e.g. down-weight or exclude `@types/` from sole-maintainer scoring) or maintainer allowlists.

## Intentionally out of scope (Branch 1 / Week 4)

Deferred to **Week 10** (or later) unless otherwise scheduled:

- **deps.dev** integration
- **OpenSSF Scorecard** direct API
- **GitHub** repository metadata (stars, org, CODEOWNERS)
- Typosquat variants that mix scoped vs unscoped names (v1 is **exact package name** vs top-1000 only)

## Open questions (Branch 2 / Week 6)

- What **publish cadence** pattern counts as an anomaly (same-day 0 vs hours vs burst of pre-releases)?
- How should **TrustDelta** weight maintainer login churn vs count-only changes?
- Should **`@types/`** (or other namespaces) have **fixed rules** before Scorecard-era enrichment?
- When weekly downloads are **missing** (`None`), should the low-downloads contribution be neutral, imputed, or explicitly flagged for the agent path?

## References

- Model: `arguss/core/models.py` — `TrustSnapshot`
- Fetcher: `arguss/lenses/trust.py` — `fetch_snapshot`, typosquat, subscore
- HTTP client: `arguss/lenses/_trust_client.py` — `TrustRegistryClient`
- Tests: `tests/test_trust_snapshot.py`
- Data: `data/README.md`
