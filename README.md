# Arguss

**Secure CI/CD & Software Supply Chain Risk Analyzer**

> Three lenses. One risk score.

Arguss unifies three supply chain risk lenses — known vulnerabilities, package trust signals, and CI/CD pipeline configuration — into a single explainable risk score. It catches the kinds of attacks (xz-utils-style maintainer takeovers, unpinned action exploits) that CVE-only scanners miss.

## Status

🚧 Under active development as a MICS Capstone project (Summer 2026).

**Live demo:** https://arguss.fly.dev (coming Week 7)

## Quick start

```bash
# Install dependencies
uv sync --all-extras

# Copy env template and add your Anthropic key
cp .env.example .env

# Run a scan
uv run arguss scan ./path/to/project

# Run the web dashboard locally
uv run uvicorn arguss.api:app --reload
```

## Development

```bash
# Install pre-commit hooks
uv run pre-commit install

# Run tests
uv run pytest

# Lint and format
uv run ruff check .
uv run ruff format .

# Type check
uv run mypy arguss
```

## Deployment

Production deploys to Fly.io automatically on merge to `main`. To deploy manually:

```bash
flyctl deploy
```

## License

TBD
