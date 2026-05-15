# Trust signal lens — design (Branches 1 & 2)

This document covers **Week 4 Branch 1** (`TrustSnapshot`, npm client, cache, top-1000) and **Branch 2** (`TrustDelta`, veto flags, real **`TrustLens`** aggregation). Public CLIs: **`arguss trust-snapshot`**, **`arguss trust-delta`**, and **`arguss scan`** (trust lens uses per-dependency snapshots; **`TrustDelta`** is not embedded in `ProjectScore` until fix-confidence consumes it in Week 6).

## Consumers

| Consumer | When | What it uses |
|----------|------|----------------|
| **PRS / risk rollup** (`scan`) | Now | **`TrustSnapshot.subscore`** per dependency, aggregated by **`TrustLens`** as the **top-10 mean** (fallback: mean of all if &lt; 10 deps). Same 30% weight in unified scoring. |
| **Agent veto / fix-confidence** | Week 6+ | **`TrustDelta`** between two versions (`flags`, `safe_to_auto_merge`). Emitted by **`fetch_delta`** / **`trust-delta`** today; **not** wired into the agent loop yet. |

## `TrustDelta` and `TrustFlag` (Branch 2)

`TrustDelta` is the structured diff between two **`TrustSnapshot`** records for the same package (`from_version` → `to_version`). It is the **agent veto signal**: `safe_to_auto_merge` is `True` only when **`flags`** is empty.

### `TrustFlag` enum

| Flag | Meaning |
|------|--------|
| `OWNERSHIP_TRANSFER` | Fewer than **50%** of the **from** maintainers appear in **to** (intersection size &lt; 0.5 × `len(from.maintainer_logins)`). Conservative: maintainer churn that looks like a takeover pattern. |
| `NEW_MAINTAINER` | At least one login in **to** that was not in **from** (`len(maintainers_added) > 0`). |
| `CADENCE_ANOMALY` | See **Cadence anomaly rule** below (all three conditions). |
| `DOWNLOAD_COLLAPSE` | `weekly_downloads_change_pct` is defined and **&lt; −0.5** (more than 50% drop week-over-week). |

Flags are stored sorted by **`TrustFlag.value`** for deterministic JSON and tests.

### `TrustDelta` fields (summary)

| Field | Role |
|-------|------|
| `maintainers_added` / `maintainers_removed` | Sorted set differences of `maintainer_logins`. |
| `ownership_transferred` | Boolean per intersection rule above. |
| `days_between_publishes` | Whole days between `from` and `to` **`published_at`**. |
| `publish_cadence_anomaly` | Result of `_is_cadence_anomaly(packument, from_version, to_version)`. |
| `weekly_downloads_change_pct` | `(to − from) / from` when both counts exist; **`None`** if either snapshot lacks downloads, or **from = 0** with **to &gt; 0** (undefined); **0.0** if both zero. |
| `flags` / `safe_to_auto_merge` | `safe_to_auto_merge ⇔ len(flags)==0`. |

### Cadence anomaly — three-condition rule

Anomaly is **`True`** only if **all** of the following hold:

1. **Ratio:** Let `new_gap` = whole days between **from** publish time and **to** publish time. Let `prior` = the up to **10** consecutive inter-release gaps immediately preceding **`from_version`** in the sorted `time` map (same ordering as `_published_events`). Let `med = median(prior)`. Then **`new_gap < 0.3 × med`**.
   *Justification:* flags releases that are dramatically faster than this package’s recent rhythm, not normal weekly bumps.
2. **History:** At least **5** version publish events strictly **before** `to_version` in that timeline (`idx_to >= 5`). Otherwise **insufficient data** → no flag.
   *Justification:* avoid punishing young packages with no baseline.
3. **Absolute floor:** **`new_gap < 7`** days.
   *Justification:* legitimate weekly-ish cadences should not trip on ratio alone when the window is still a full week or more.

Implemented in **`_is_cadence_anomaly`** using **`_published_events`** only (no duplicate time parsing).

### Trust lens aggregation (`TrustLens.scan`)

- For each **`Dependency`**, call **`fetch_snapshot(cache, name, version)`**.
- **Resilience:** **`TrustClientError`** on a dependency → **`logger.warning`**, skip that dep, continue.
- **Score:** Sort successful **`subscore`** values descending; take the **top N = 10** (or all if fewer than 10); **lens score = arithmetic mean** of that slice (0 if no successful snapshots).
- **Findings:** One **`Finding`** per successful snapshot (severity bands from subscore; **`score`** = subscore as float).
- **Logging:** Summary line **`trust lens: N deps scored, M failed.`** (`warning` if **M > 0**; `info` if all succeeded).

### Graceful degradation policy

Failed snapshots **do not** fail the scan. The trust lens score reflects **only** dependencies that returned a snapshot. If **all** fail, score **0** and findings empty, with a log line that still includes **`trust lens:`** for operator grep.

## Open questions (Week 6 — fix-confidence)

- How **`TrustDelta`** combines with CVE severity and pipeline posture for a **graded** auto-merge confidence (replacing or refining the boolean `safe_to_auto_merge`).
- Whether **`NEW_MAINTAINER`** should be suppressed when **`OWNERSHIP_TRANSFER`** already fires (noise vs signal).
- Cadence: same-calendar-day **`timedelta.days == 0`** vs hour-granularity for hotfix paths.
- **`@types/*`** and similar namespaces: namespace allowlist for maintainer heuristics (deferred; see known limitations below).

---

## Branch 1 — `TrustSnapshot` (reference)

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

## References

- Model: `arguss/core/models.py` — `TrustSnapshot`, `TrustDelta`, `TrustFlag`
- Lens / delta: `arguss/lenses/trust.py` — `fetch_snapshot`, `fetch_delta`, `TrustLens`, `_is_cadence_anomaly`
- HTTP client: `arguss/lenses/_trust_client.py` — `TrustRegistryClient`
- Tests: `tests/test_trust_snapshot.py`, `tests/test_trust_delta.py`, `tests/test_trust_lens.py`
- Data: `data/README.md`
