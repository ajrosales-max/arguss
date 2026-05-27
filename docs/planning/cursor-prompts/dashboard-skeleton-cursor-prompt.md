# Cursor prompt — `feature/dashboard-skeleton`

This PR builds the structural skeleton of the Arguss web dashboard: HTML routes that serve Jinja templates, HTMX wiring for form submission and partial rendering, helper functions for grouping scan results by package, and minimal vanilla JS for tier filtering. **The visual design is explicitly out of scope.** Templates will use unstyled HTML with semantic class names and clear `<!-- TODO: design -->` markers so Sherbano can fill in Tailwind classes, color choices, and layout details in a follow-up.

**Branch name:** `feature/dashboard-skeleton`

**Estimated time:** 3–4 hours.

**Scope discipline:** New HTML routes, new templates, new dashboard helper module. Do NOT touch the JSON endpoints (`/scan/url`, `/scan/upload`, `/scan/with-action`), the engine, the lenses, the CLI, or `arguss/api.py` except to mount the new templates. Do NOT write production CSS — the only styles are placeholder structure (e.g., a single inline `<style>` block in base.html with minimal layout, no colors, no typography choices).

---

## Before pasting into Cursor

```bash
git checkout main
git pull
git log --oneline -3                      # confirm osv-batch-chunking is at top
uv run pytest                              # baseline: should be 320 passed
```

```bash
git checkout -b feature/dashboard-skeleton
```

---

## The prompt to paste into Cursor

I'm building the structural skeleton of the Arguss dashboard. The goal is to have a fully wired end-to-end flow — user submits a scan, results render, tier filtering works, package detail expansion works — with NO visual design. The actual design will be filled in by another contributor in a follow-up PR. My job here is to make sure all the plumbing is in place.

### Ground rules (non-negotiable)

1. **No visual design.** Templates are unstyled HTML with semantic class names (`summary-banner`, `package-row`, `tier-badge auto_merge`, `tier-badge review_required`, etc.). One inline `<style>` block in `base.html` with the absolute minimum for layout to not be broken (e.g., `display: none` for hidden details, basic spacing). No color choices, no typography, no Tailwind classes yet. Sherbano fills those in.

2. **JSON endpoints unchanged.** Do NOT modify `/scan/url`, `/scan/upload`, `/scan/with-action`, or any code in `arguss/web/routes.py` related to those handlers. The new dashboard routes call the same engine functions but render templates instead of JSON.

3. **Existing tests stay green.** The skeleton adds tests for the new routes; existing tests should pass unchanged.

4. **Native HTML where possible.** Use `<details>`/`<summary>` for expandable package rows rather than custom JS — browser-native, accessible, no extra code. Tier filtering uses minimal vanilla JS (toggle visibility based on `data-tier` attributes); no client-side framework.

5. **Tailwind via CDN in `base.html`.** Drop in `<script src="https://cdn.tailwindcss.com"></script>` so it's there for Sherbano's follow-up, but don't apply any Tailwind classes in this PR. Same for HTMX: `<script src="https://unpkg.com/htmx.org@1.9.10"></script>`.

### What to build

#### 1. New module: `arguss/web/dashboard.py`

Dashboard routes that render templates. Pattern follows the existing `routes.py` style but returns HTML.

```python
"""HTML routes for the Arguss dashboard.

Renders Jinja templates that consume the same engine output as the JSON
endpoints in routes.py. The JSON endpoints stay as the machine API; these
routes are the browser-facing surface.
"""

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import SecretStr

from arguss.engine.propose import propose_fixes, ProposalReport
# ... other imports as needed

router = APIRouter()
templates = Jinja2Templates(directory="arguss/web/templates")


@dataclass(frozen=True)
class PackageGroup:
    """One row in the grouped results view."""
    name: str
    finding_count: int
    summary_tier: str           # "auto_merge", "review_required", "decline", or "mixed"
    severity_range: str         # e.g. "low–high", "medium"
    entries: list                # the original ProposalEntry objects for this package


def group_by_package(report: ProposalReport) -> list[PackageGroup]:
    """Group entries by candidate.package, summarize tier and severity."""
    by_pkg: dict[str, list] = defaultdict(list)
    for entry in report.entries:
        by_pkg[entry.candidate.package].append(entry)

    groups = []
    for name, entries in by_pkg.items():
        tiers = {e.verdict.tier.value for e in entries}
        summary_tier = next(iter(tiers)) if len(tiers) == 1 else "mixed"
        severities = sorted({e.finding.severity for e in entries})
        severity_range = severities[0] if len(severities) == 1 else f"{severities[0]}–{severities[-1]}"
        groups.append(PackageGroup(
            name=name,
            finding_count=len(entries),
            summary_tier=summary_tier,
            severity_range=severity_range,
            entries=entries,
        ))

    return sorted(groups, key=lambda g: -g.finding_count)


@router.get("/", response_class=HTMLResponse)
async def landing(request: Request) -> HTMLResponse:
    """Landing page with input forms for all three scan modes."""
    return templates.TemplateResponse("index.html", {"request": request})


@router.post("/dashboard/scan", response_class=HTMLResponse)
async def dashboard_scan_url(
    request: Request,
    url: Annotated[str, Form()],
    ref: Annotated[str, Form()] = "HEAD",
) -> HTMLResponse:
    """Mode A from the dashboard. Returns the results fragment."""
    # Reuse the same logic as scan_url in routes.py: parse URL, fetch_repo_inputs,
    # propose_fixes. Wrap errors in template-rendered error fragments rather than
    # raising HTTPException — the dashboard wants graceful in-UI error display,
    # not a browser-default 4xx/5xx page.
    try:
        # ... call fetch_repo_inputs, propose_fixes ...
        report = ...
        groups = group_by_package(report)
        return templates.TemplateResponse(
            "results.html",
            {"request": request, "report": report, "groups": groups},
        )
    except Exception as exc:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": str(exc)},
            status_code=200,  # HTMX expects 200 for swap; error is rendered in-UI
        )


@router.post("/dashboard/upload", response_class=HTMLResponse)
async def dashboard_scan_upload(
    request: Request,
    lockfile: Annotated[UploadFile, File()],
    workflows_zip: Annotated[UploadFile | None, File()] = None,
    package_json: Annotated[UploadFile | None, File()] = None,
) -> HTMLResponse:
    """Mode B from the dashboard. Returns the results fragment."""
    # Mirror scan_upload in routes.py; render results.html on success.
    ...


@router.post("/dashboard/scan-with-action", response_class=HTMLResponse)
async def dashboard_scan_with_action(
    request: Request,
    url: Annotated[str, Form()],
    ref: Annotated[str, Form()] = "HEAD",
    pat: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Mode C from the dashboard. Returns results + actions section."""
    # Mirror scan_with_action; render results_with_actions.html on success.
    ...
```

Reuse as much logic as possible from `routes.py` — the error mapping, the temp directory handling, the call to `fetch_repo_inputs`. Extract common helpers into shared functions if duplication gets uncomfortable, but don't refactor the JSON routes themselves.

#### 2. Mount the dashboard router in `arguss/api.py`

Add the new router alongside the existing scan router:

```python
from arguss.web.dashboard import router as dashboard_router
app.include_router(dashboard_router)
```

Also: **remove the inline placeholder root HTML route** currently in `api.py`. The new dashboard router serves `GET /` from `index.html`. Don't leave both routes claiming `/`.

#### 3. Templates

Directory: `arguss/web/templates/`. Five files:

**`base.html`** — layout shell. Includes Tailwind CDN, HTMX CDN, one minimal inline `<style>` block for structural-only CSS (hiding details until expanded, basic spacing). Has `{% block content %}` for child templates.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{% block title %}Arguss{% endblock %}</title>
  <script src="https://unpkg.com/htmx.org@1.9.10"></script>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    /* Structural only. Visual design TODO: filled in by Sherbano */
    .htmx-indicator { display: none; }
    .htmx-request .htmx-indicator { display: inline; }
    .htmx-request.htmx-indicator { display: inline; }
  </style>
</head>
<body>
  {% block content %}{% endblock %}
</body>
</html>
```

**`index.html`** — landing page. Extends base. Has three forms (Mode A, B, C), each with `hx-post` to the corresponding dashboard endpoint, `hx-target="#results"`, `hx-swap="innerHTML"`, `hx-indicator="#spinner"`.

Mode tabs/sections can be in a simple structure (three `<div class="mode-section">` blocks, one per mode). Sherbano will decide whether they're tabs, accordion, or three stacked sections.

Each form must include the right fields:

- **Mode A:** `<input name="url">`, `<input name="ref" value="HEAD">`, submit.
- **Mode B:** `<input type="file" name="lockfile" required>`, `<input type="file" name="workflows_zip">`, `<input type="file" name="package_json">`, submit.
- **Mode C:** `<input name="url">`, `<input name="ref" value="HEAD">`, `<input name="pat" type="password">`, submit. Include a `<p class="consent-notice">` with placeholder consent text (`<!-- TODO: design final consent copy -->`).

Then:

```html
<div id="spinner" class="htmx-indicator">Analyzing… <!-- TODO: spinner design --></div>
<div id="results"></div>
```

Also include a small **"Try the demo target"** affordance — a button or link that prefills Mode A with `https://github.com/axios/axios` and `ref=v1.0.0` and submits. This is for the demo.

**`results.html`** — results fragment. NOT a full HTML page; it's the inner content swapped into `#results`.

```html
<!-- TODO: design summary banner -->
<div class="summary-banner">
  <span class="big-number">{{ report.summary.total_findings }}</span> findings ·
  <span class="big-number">{{ report.summary.auto_merge_count }}</span> auto-merge ·
  <span class="big-number">{{ report.summary.review_required_count }}</span> review ·
  <span class="big-number">{{ report.skipped_findings|length }}</span> skipped
</div>

<!-- TODO: design tier filter tabs -->
<div class="tier-filters">
  <button data-tier-filter="all" class="active">All</button>
  <button data-tier-filter="auto_merge">Auto-merge ({{ report.summary.auto_merge_count }})</button>
  <button data-tier-filter="review_required">Review ({{ report.summary.review_required_count }})</button>
  <button data-tier-filter="skipped">Skipped ({{ report.skipped_findings|length }})</button>
</div>

<div class="package-list">
  {% for group in groups %}
    <details class="package-row" data-tier="{{ group.summary_tier }}">
      <summary>
        <span class="package-name">{{ group.name }}</span>
        <span class="package-count">{{ group.finding_count }} findings</span>
        <span class="severity-range">{{ group.severity_range }}</span>
        <span class="tier-badge {{ group.summary_tier }}">{{ group.summary_tier }}</span>
      </summary>
      <div class="package-detail">
        {% for entry in group.entries %}
          {% include "partials/_finding_card.html" %}
        {% endfor %}
      </div>
    </details>
  {% endfor %}
</div>

{% if report.skipped_findings %}
  {% include "partials/_skipped.html" %}
{% endif %}

<script>
  // Tier filtering — vanilla JS, no framework
  (function() {
    const buttons = document.querySelectorAll('[data-tier-filter]');
    const rows = document.querySelectorAll('[data-tier]');
    buttons.forEach(btn => {
      btn.addEventListener('click', () => {
        buttons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const filter = btn.dataset.tierFilter;
        rows.forEach(row => {
          row.style.display = (filter === 'all' || row.dataset.tier === filter || (filter === 'skipped' && row.dataset.tier === 'mixed'))
            ? '' : 'none';
        });
      });
    });
  })();
</script>
```

**`partials/_finding_card.html`** — one per-finding card.

```html
<!-- TODO: design finding card -->
<div class="finding-card" data-tier="{{ entry.verdict.tier.value }}">
  <div class="version-delta">
    {{ entry.candidate.from_version }} → {{ entry.candidate.to_version }}
    <span class="fix-kind {{ entry.candidate.fix_kind.value }}">{{ entry.candidate.fix_kind.value }}</span>
  </div>
  <div class="tier-and-score">
    <span class="tier-badge {{ entry.verdict.tier.value }}">{{ entry.verdict.tier.value }}</span>
    <span class="score">Score: {{ entry.verdict.score }}</span>
  </div>
  <div class="veto-chips">
    {% for signal in entry.verdict.veto_signals %}
      <span class="veto-chip">{{ signal }}</span>
    {% endfor %}
  </div>
  <ul class="reasons">
    {% for reason in entry.verdict.reasons %}
      <li>{{ reason }}</li>
    {% endfor %}
  </ul>
  <div class="advisory">
    <strong>{{ entry.finding.title }}</strong>
    <p>{{ entry.finding.remediation }}</p>
    <a href="{{ entry.finding.source_url }}" target="_blank">View advisory</a>
  </div>
  <div class="transitive-path">
    {% for step in entry.finding.dependency.path %}
      {{ step }}{% if not loop.last %} → {% endif %}
    {% endfor %}
  </div>
</div>
```

**`partials/_skipped.html`** — skipped findings warning.

```html
<!-- TODO: design skipped findings section -->
<div class="skipped-section">
  <h3>Skipped findings ({{ report.skipped_findings|length }})</h3>
  {% for item in report.skipped_findings %}
    {% if item is string %}
      <span class="skipped-advisory">{{ item }}</span>
    {% else %}
      <div class="skipped-error">
        <strong>{{ item.reason }}</strong>: {{ item.detail }}
        <em>(lens: {{ item.lens }})</em>
      </div>
    {% endif %}
  {% endfor %}
</div>
```

**`error.html`** — in-UI error display (HTMX swaps this into `#results` when a scan fails).

```html
<!-- TODO: design error display -->
<div class="error">
  <strong>Scan failed:</strong> {{ message }}
</div>
```

### Tests

`tests/test_dashboard_routes.py` (new file):

- `test_landing_page_returns_html` — GET `/` returns 200 with content-type `text/html` and contains the three mode form action targets.
- `test_dashboard_scan_renders_results` — POST `/dashboard/scan` with a mocked `fetch_repo_inputs` and `propose_fixes` returns 200 with results.html content (search for `summary-banner`, `package-row`).
- `test_dashboard_scan_error_renders_error_template` — force `fetch_repo_inputs` to raise; verify response is 200 with `error.html` content rather than a 4xx/5xx.
- `test_dashboard_upload_renders_results` — similar for Mode B.
- `test_dashboard_scan_with_action_renders_results_with_actions` — similar for Mode C.
- `test_group_by_package_summary_tier_logic` — unit test for the grouping helper: all same tier → that tier; mixed → "mixed".

Existing tests stay green.

### Acceptance criteria

1. `uv run pytest` passes. New tests pass; existing 320 tests continue to pass.
2. `uv run uvicorn arguss.api:app --reload` then visit `http://localhost:8000` — see the three-mode landing page (unstyled but functional).
3. Click the "Try the demo target" button → see results render below the form. Summary banner shows real numbers, package rows expand on click, tier filter buttons hide/show rows.
4. Mode B form accepts the express fixture (`tests/fixtures/lockfiles/real-world.json`) and renders 12 findings.
5. The visual presentation is intentionally rough — that's correct for this PR. Sherbano fills in styling next.

### What NOT to do

- Don't write Tailwind classes or production CSS. Inline structural CSS only, marked with `<!-- TODO: design -->`.
- Don't modify any JSON endpoint or its tests.
- Don't refactor the engine, lenses, or parser.
- Don't add WebSockets, SSE, or polling — synchronous request/response is fine for 2-4s scans.
- Don't add user state, sessions, or any persistence.
- Don't write client-side templating. All rendering is server-side Jinja.
- Don't add a SPA framework (React, Vue, Alpine, etc.).

---

## After Cursor finishes

1. `uv run pytest` — all green.
2. Start uvicorn: `uv run uvicorn arguss.api:app --reload --port 8000`
3. Visit `http://localhost:8000` in a browser. Click "Try the demo target." Confirm 177 findings render, tier filters work, package rows expand.
4. Try Mode B by uploading the express fixture — confirm 12 findings.
5. Try Mode A with a bogus URL → confirm the error renders in-UI, not as a browser error page.

Once the structure works end-to-end, send Sherbano:

- A link to this PR (or merged branch)
- A note: "Templates are at `arguss/web/templates/`. All structure is in place; styling is yours. Search for `TODO: design` markers — those are the places to fill in. Tailwind is already loaded in `base.html`."

Then she can iterate on visual design without touching routes or template logic, and you can keep moving on demo polish (Mode C recording, talking-points script, fallback inputs cached).
