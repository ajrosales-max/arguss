# Maintenance scripts

Not imported at runtime. Run manually from the repo root with `uv run` where noted.

| File | Purpose |
|------|---------|
| [`refresh-top-1000.py`](refresh-top-1000.py) | Regenerate `data/npm-top-1000-YYYY-MM.txt` from npm-high-impact (fallback npm-rank) |
| [`bootstrap-github-project.sh`](bootstrap-github-project.sh) | Create GitHub Project board (one-time) |
| [`bootstrap-github-project-tasks.sh`](bootstrap-github-project-tasks.sh) | Seed project tasks |
| [`sync-github-project-tasks.sh`](sync-github-project-tasks.sh) | Sync task status with repo |
| [`sync-github-project-roadmap.sh`](sync-github-project-roadmap.sh) | Sync roadmap fields |

See [`../data/README.md`](../data/README.md) for top-1000 refresh cadence.
