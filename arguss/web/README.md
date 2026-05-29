# `arguss.web` — HTTP surfaces

Dashboard (Jinja2 + HTMX) and JSON scan API share `engine.propose`.

## Python modules

| File | Purpose |
|------|---------|
| [`routes.py`](routes.py) | `POST /scan/url`, `/scan/upload`, `/scan/with-action` |
| [`dashboard.py`](dashboard.py) | HTML + HTMX routes |
| [`results_context.py`](results_context.py) | Results template context, glossary |
| [`error_cards.py`](error_cards.py) | Error card copy for HTMX responses |
| [`github_fetch.py`](github_fetch.py) | GitHub Contents API (Mode A) |
| [`github_action.py`](github_action.py) | Open PRs (Mode C) |
| [`github_url.py`](github_url.py) | URL parsing |
| [`git_clone.py`](git_clone.py) | Shallow clone fallback |
| [`lockfile_fix.py`](lockfile_fix.py) | Lockfile edits for PRs |
| [`zip_safe.py`](zip_safe.py) | Safe workflow zip extraction |
| [`auth.py`](auth.py) | Demo HTTP Basic Auth |
| [`__init__.py`](__init__.py) | Package marker |

## Subfolders

- [`templates/`](templates/README.md) — Jinja pages and partials
- [`static/`](static/README.md) — CSS and assets
