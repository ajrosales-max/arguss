# `arguss.scoring` — Project Risk Score (PRS)

Project-level score for the dashboard. Separate from per-fix **fix-confidence**.

## Files

| File | Purpose |
|------|---------|
| [`unified.py`](unified.py) | `compute_project_score()` — 40% CVE + 30% trust + 30% pipeline; `epss_urgency_tier()` for UI |
| [`__init__.py`](__init__.py) | Re-exports `compute_project_score` |
