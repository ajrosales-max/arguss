# Jinja2 templates

Rendered by `dashboard.py` via `Jinja2Templates`. HTMX swaps partials without full page reloads.

## Top-level pages

| Template | Route / use |
|----------|-------------|
| [`base.html`](base.html) | Layout shell (nav, footer, CSS) |
| [`index.html`](index.html) | Home |
| [`how_it_works.html`](how_it_works.html) | Product explanation |
| [`about.html`](about.html) | Team / about |
| [`scan.html`](scan.html) | Mode A - GitHub URL |
| [`upload.html`](upload.html) | Mode B - file upload |
| [`results.html`](results.html) | Full results page |
| [`results_not_found.html`](results_not_found.html) | Unknown `scan_hash` |
| [`error.html`](error.html) | Generic error page |

## Partials

See [`partials/README.md`](partials/README.md) for HTMX fragments (`_summary_banner.html`, `_finding_card.html`, `_chat_panel.html`, etc.).
