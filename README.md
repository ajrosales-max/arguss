# Arguss

**Secure CI/CD & Software Supply Chain Risk Analyzer**

> Three lenses. One risk score.

Arguss combines supply chain signals—**known vulnerabilities** (OSV.dev), **package trust** (npm registry; rolling out), and **CI/CD pipeline configuration** (GitHub Actions via zizmor)—into a single explainable project risk score. It is meant to catch risks that CVE-only scanners miss (unpinned actions, maintainer and typosquat signals, and similar).

## What works today

| Area | Status |
|------|--------|
| **`arguss scan`** | Parses npm lockfiles, runs the **vulnerability** lens against OSV, **pipeline** lens (zizmor), and **unified scoring** (40% CVE / 30% trust / 30% pipeline). |
| **Trust in `scan`** | **Placeholder** lens only (skeleton findings). Real npm-backed trust is not yet wired into the score; that is **Week 4 Branch 2** work. |
| **`arguss trust-snapshot`** | **Live**: fetches a [`TrustSnapshot`](arguss/core/models.py) for a single `package` + `version` (packument, downloads, typosquat vs bundled top-1000, v1 subscore). Uses the same SQLite cache as OSV. |
| **`arguss sbom`** | **Live**: CycloneDX **1.7** JSON from the lockfile for the project root. |
| **API / dashboard** | FastAPI app for local or hosted UI; production deploy on Fly.io. |

Design detail for trust snapshots: [`docs/planning/trust-signal-lens.md`](docs/planning/trust-signal-lens.md).

**Context:** MICS capstone, active development (Summer 2026). Broader product direction: [`docs/planning/project-overview.md`](docs/planning/project-overview.md) and [`docs/planning/pivot-rationale.md`](docs/planning/pivot-rationale.md).

**Demo:** https://arguss.fly.dev (evolving with milestones)

## Quick start

```bash
# Runtime deps + dev tools (pytest, ruff, mypy, …)
uv sync --group dev

# Optional: Anthropic key for future AI-assisted explanations on scan
cp .env.example .env
# edit .env — not required for scan --no-ai or trust-snapshot

# Unified scan (JSON default; use -f pretty for terminal-friendly output)
uv run arguss scan ./path/to/project
uv run arguss scan ./path/to/project --no-ai

# Trust snapshot for one npm coordinate (JSON to stdout)
uv run arguss trust-snapshot lodash 4.17.21
uv run arguss trust-snapshot "@types/node" 20.10.0

# CycloneDX SBOM
uv run arguss sbom ./path/to/project -o bom.json

# Web dashboard (local)
uv run uvicorn arguss.api:app --reload
```

## CLI overview

| Command | Purpose |
|---------|---------|
| `arguss scan <path>` | Lockfile → three lenses → `ProjectScore` JSON (or pretty). |
| `arguss trust-snapshot <package> <version>` | Real npm **TrustSnapshot** (inspection / debugging until Branch 2). |
| `arguss sbom <path>` | CycloneDX 1.7 SBOM (`-o` file or stdout). |

Use `arguss --help` and `arguss <command> --help` for options.

## Development

```bash
uv sync --group dev
uv run pre-commit install

# Default test run excludes @pytest.mark.integration (no live OSV/npm)
uv run pytest

# Include integration tests (network)
uv run pytest -m integration

uv run ruff check .
uv run ruff format .
uv run mypy arguss
```

## Deployment

Pushes to `main` deploy to **Fly.io** via CI. Manual deploy:

```bash
flyctl deploy
```

## License

TBD
