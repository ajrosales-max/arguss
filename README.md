# Arguss

**Secure CI/CD & Software Supply Chain Risk Analyzer**

> Three lenses. One risk score.

Arguss combines supply chain signals—**known vulnerabilities** (OSV.dev), **package trust** (npm registry; rolling out), and **CI/CD pipeline configuration** (GitHub Actions via zizmor)—into a single explainable project risk score. It is meant to catch risks that CVE-only scanners miss (unpinned actions, maintainer and typosquat signals, and similar).

## What works today

| Area | Status |
|------|--------|
| **`arguss scan`** | Parses npm lockfiles, runs the **vulnerability** lens (OSV), **trust** lens (per-dependency npm snapshots, top-10 mean subscore), **pipeline** lens (zizmor), and **unified scoring** (40% CVE / 30% trust / 30% pipeline). |
| **Trust in `scan`** | **Live**: `TrustLens` aggregates `TrustSnapshot.subscore` across dependencies (failed fetches skipped; see logs). |
| **`arguss trust-snapshot`** | **Live**: one coordinate → full **TrustSnapshot** JSON (debug / tooling). |
| **`arguss trust-delta`** | **Live**: `from` → `to` version → **TrustDelta** JSON (veto flags for future fix-confidence; not consumed by `scan` yet). |
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
# edit .env — not required for scan --no-ai or trust-snapshot / trust-delta

# Unified scan (JSON default; use -f pretty for terminal-friendly output)
uv run arguss scan ./path/to/project
uv run arguss scan ./path/to/project --no-ai

# Trust snapshot for one npm coordinate (JSON to stdout)
uv run arguss trust-snapshot lodash 4.17.21
uv run arguss trust-snapshot "@types/node" 20.10.0

# Trust delta between two versions (veto signal JSON; Week 6 consumer)
uv run arguss trust-delta lodash 4.17.20 4.17.21

# CycloneDX SBOM
uv run arguss sbom ./path/to/project -o bom.json

# Web dashboard (local)
uv run uvicorn arguss.api:app --reload
```

## CLI overview

| Command | Purpose |
|---------|---------|
| `arguss scan <path>` | Lockfile → three lenses → `ProjectScore` JSON (or pretty). |
| `arguss trust-snapshot <package> <version>` | One coordinate → **TrustSnapshot** JSON. |
| `arguss trust-delta <package> <from> <to>` | **TrustDelta** JSON (`safe_to_auto_merge`, flags). |
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
