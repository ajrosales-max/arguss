# Arguss application package

Python package imported as `arguss`. Entry points: [`api.py`](api.py) (FastAPI), [`cli.py`](cli.py) (Typer), [`settings.py`](settings.py) (environment config).

## Modules

| Path | Role |
|------|------|
| [`api.py`](api.py) | FastAPI app: mounts static files, dashboard + scan routers, `/health` |
| [`cli.py`](cli.py) | Typer CLI: `scan`, `propose-fixes`, `sbom`, trust helpers, zizmor |
| [`settings.py`](settings.py) | Env-based settings (DB, API bases, demo auth, kill switch) |
| [`core/`](core/README.md) | Shared models, parser, cache, SBOM, serialization |
| [`lenses/`](lenses/README.md) | Vulnerability, trust, and pipeline analyses |
| [`scoring/`](scoring/README.md) | Project Risk Score (PRS) aggregation |
| [`engine/`](engine/README.md) | Fix discovery, fix-confidence, proposal orchestration |
| [`explanations/`](explanations/README.md) | Claude-powered summaries and chat (optional) |
| [`web/`](web/README.md) | HTTP routes, GitHub integration, Jinja templates |

## Data flow

```
Input (lockfile ± repo/workflows)
  → core.parser
  → lenses (parallel)
  → engine.propose (candidates + fix-confidence)
  → scoring.unified (PRS for UI)
  → web / CLI / API output
```
