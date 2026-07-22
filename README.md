# Arguss

**Autonomous npm supply chain remediation**

> Three lenses on supply chain risk. Autonomous remediation that knows when not to merge.

Arguss combines vulnerability intelligence (OSV.dev), package trust signals (npm registry, deps.dev, OpenSSF Scorecard), and CI/CD pipeline analysis (GitHub Actions via zizmor) into a per-remediation **fix-confidence verdict**. Low-risk dependency upgrades auto-merge within a defensible safety envelope; higher-risk cases escalate to human review with structured reasoning. Unlike detection-only scanners (Snyk, OSV-Scanner), Arguss proposes and acts on fixes. Unlike auto-PR tools (Dependabot, Renovate), Arguss refuses to act when trust signals, blast radius, or CI reality suggest a fix isn't safe.

**Context:** MICS Capstone (Summer 2026), active development. Demo target on Fly.io: https://arguss.fly.dev (verify URL is current).

Broader product direction: [`docs/planning/project-overview-v2.md`](docs/planning/project-overview-v2.md), [`docs/planning/use-cases-and-delivery-plan.md`](docs/planning/use-cases-and-delivery-plan.md), and [`docs/planning/pivot-rationale.md`](docs/planning/pivot-rationale.md).

## What works today

| Area | Status |
|------|--------|
| **Vulnerability lens** | Live. OSV.dev (cached), batch queries ≤500/request, CVSS v3 parsing, EPSS exploit likelihood, CISA KEV known-exploited flag. |
| **Trust lens** | Live. npm registry + deps.dev clients, Levenshtein typosquat detection against top-1000 list, TrustDelta with four veto flags (ownership transfer, new maintainer, cadence anomaly, download collapse). |
| **Pipeline lens** | Live. zizmor wrapper for GitHub Actions analysis, four-condition test-reality check, severity-weighted-sum subscore. |
| **Fix-confidence engine** | Live. Per-remediation verdict with tier (AUTO_MERGE / REVIEW_REQUIRED / DECLINE), score (0–100), structured reasons, and machine-readable veto signals. |
| **Mode A: scan by URL** | Live. `POST /scan/url` fetches lockfile + workflows + test metadata via GitHub Contents API (no clone), supports any tag/branch/commit via optional `ref`. |
| **Mode B: scan from upload** | Live. `POST /scan/upload` accepts package-lock.json + optional workflows zip + optional package.json. |
| **Mode C: scan and act** | Live. `POST /scan/with-action` opens pull requests for AUTO_MERGE candidates via a user-supplied GitHub PAT. |
| **AI explanations** | Live. Claude generates natural-language explanations for escalations; failure mode degrades gracefully to deterministic templates. |
| **SBOM** | Live. CycloneDX 1.7 JSON export. |
| **Web dashboard** | Live. Jinja2 + HTMX UI: scan/upload/action flows, results with tier filters, glossary, chat Q&A on cached scans. |
| **Deployment** | Live on Fly.io; deploys from `main` via CI. SQLite cache on Fly volume. |

## Repository layout

| Folder | README |
|--------|--------|
| `arguss/` (Python package) | [`arguss/README.md`](arguss/README.md) |
| `data/` | [`data/README.md`](data/README.md) |
| `docs/` | [`docs/README.md`](docs/README.md) |
| `tests/` | [`tests/README.md`](tests/README.md) |
| `scripts/` | [`scripts/README.md`](scripts/README.md) |
| `.github/` | [`.github/README.md`](.github/README.md) |

Team overview: [`docs/repo-breakdown.md`](docs/repo-breakdown.md).

## Quick start

```bash
# Runtime deps + dev tools
uv sync --group dev

# Optional: Anthropic key for AI-generated PR explanations (Mode C, escalations)
cp .env.example .env
# Optional: ANTHROPIC_API_KEY, ARGUSS_GITHUB_TOKEN; auth: ARGUSS_REQUIRE_AUTH + ARGUSS_DEMO_PASSWORD
# Never commit .env or secrets

# Run the web service locally
uv run uvicorn arguss.api:app --reload --port 8000
```

The service is then at `http://localhost:8000`.

## Web UI routes

| Route | Purpose |
|-------|---------|
| `GET /` | Home |
| `GET /how-it-works`, `/about` | Product and team pages |
| `GET /scan`, `/upload`, `/action` | Mode A / B / C forms |
| `GET /results/{scan_hash}` | Results (tier filters, lens tiles, chat) |
| `POST /dashboard/scan`, `/dashboard/upload`, `/dashboard/scan-with-action` | HTMX scan handlers |
| `POST /dashboard/chat` | HTMX Q&A on cached scan |
| `GET /health` | Health check (no auth) |

Auth is controlled by `ARGUSS_REQUIRE_AUTH` (default locked when unset; set `false` to open the read surface for the public showcase). When auth is on, `ARGUSS_DEMO_PASSWORD` is required or the web app fails to boot; dashboard and scan API use HTTP Basic Auth and OpenAPI (`/docs`) is disabled. Unrecognized `ARGUSS_REQUIRE_AUTH` values stay locked (fail-closed). Mode C enact stays gated by GitHub App install/session ownership regardless of this flag.

## Web service / API

Three POST endpoints, all returning the same JSON proposal report shape.

| Endpoint | Mode | Input | Action |
|----------|------|-------|--------|
| `POST /scan/url` | A | `{"url": "...", "ref": "main"}` | Read-only analysis |
| `POST /scan/upload` | B | Multipart: lockfile + optional workflows zip + optional package.json | Read-only analysis |
| `POST /scan/with-action` | C | `{"url": "...", "pat": "ghp_..."}` | Analyze + open PRs for AUTO_MERGE candidates |

Interactive docs (auto-generated by FastAPI) live at:
- `http://localhost:8000/docs` — Swagger UI with "Try it out"
- `http://localhost:8000/redoc` — cleaner read-only reference
- `http://localhost:8000/openapi.json` — raw OpenAPI spec

### Worked example

Scan axios at the v1.0.0 tag (a known-vulnerable historical release):

```bash
curl -s -X POST http://localhost:8000/scan/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://github.com/axios/axios","ref":"v1.0.0"}' \
  | jq '.summary'
```

Returns:

```json
{
  "total_findings": 177,
  "total_candidates": 173,
  "auto_merge_count": 90,
  "review_required_count": 83,
  "decline_count": 0
}
```

Each entry in the `entries` array contains three things:

- `finding` — the vulnerability (OSV advisory, severity, dependency path through the transitive graph)
- `candidate` — the proposed remediation (package, from_version, to_version, fix_kind)
- `verdict` — the fix-confidence decision (tier, score 0–100, human-readable reasons, machine-readable veto signal IDs)

The full response shape is documented at `/docs`.

## CLI

The CLI shares the engine with the web service and is useful for local development and CI integration.

| Command | Purpose |
|---------|---------|
| `arguss scan <path>` | Lockfile → three lenses → unified `ProjectScore` JSON. |
| `arguss propose-fixes <lockfile> [--repo-path <dir>]` | Lockfile → fix candidates with fix-confidence verdicts. |
| `arguss sbom <path>` | CycloneDX 1.7 SBOM export. |
| `arguss trust-snapshot <package> <version>` | One coordinate → full TrustSnapshot JSON. |
| `arguss trust-delta <package> <from> <to>` | Between two versions → TrustDelta JSON with veto flags. |
| `arguss zizmor-scan <repo-path>` | Pipeline lens output for a repo's GitHub Actions workflows. |
| `arguss pipeline-snapshot <repo-path>` | Full pipeline lens evaluation including test-reality check. |

Use `arguss --help` and `arguss <command> --help` for full options.

## Development

```bash
uv sync --group dev
uv run pre-commit install

# Default test run excludes @pytest.mark.integration (no live OSV/npm/GitHub)
uv run pytest

# Include integration tests (network required)
uv run pytest -m integration

uv run ruff check .
uv run ruff format .
uv run mypy arguss
```

## Analytics (GTM → GA4)

The web UI pushes funnel events to the GTM `dataLayer` from `/static/js/analytics.js`
(`scan_url`, `scan_upload`, `remediation_start`, `wizard_select`, `wizard_authorize`,
`github_install`, plus HTMX `*_result` variants). In GTM, add a Custom Event trigger
per event name and a GA4 Event tag that forwards the event and parameters
(`repo`, `ref`, `source`, `status`, etc.). Repo identity is sent as `owner/repo`, not the raw URL.

## Deployment

Pushes to `main` deploy to **Fly.io** via CI. Manual deploy:

```bash
flyctl deploy
```

## License

TBD
