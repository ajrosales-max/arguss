# Arguss — Day 1 Setup Guide

This document is a step-by-step scaffolding guide for setting up the Arguss repo. It's structured so each section can be handed to Cursor as a task, in order. Each step includes the full file contents to create, the rationale, and a verification step.

**Goal of Day 1:** A working fake-data skeleton locally + a hello-world Fly.io deployment live at a stable URL. `arguss scan ./test-dir` prints a JSON ProjectScore on your laptop. The same command runs green in CI on a PR. The FastAPI app responds at `https://arguss-<your-suffix>.fly.dev/`.

---

## Working with Cursor

For each step below:
1. Open Cursor in the project root
2. Use Cmd/Ctrl+K and paste the step's instruction (or use Cursor chat with the file contents)
3. Review the generated code against the spec
4. Run the verification command before moving to the next step

**Tip:** Don't let Cursor invent files or features beyond what's in each step. If it suggests adding something, defer it — the skeleton's value is that everything has a clear contract before any real implementation lands.

---

## Prerequisites

Verify these are installed before starting:

```bash
python3 --version       # 3.11 or higher
git --version
gh --version            # GitHub CLI (optional but useful)
docker --version        # Needed for Fly deploys
```

Install `uv` (the package manager we'll use):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Install `flyctl` (Fly.io CLI):

```bash
curl -L https://fly.io/install.sh | sh
```

Verify both:

```bash
uv --version
flyctl version
```

Sign up for Fly.io at https://fly.io and log in:

```bash
flyctl auth signup        # or: flyctl auth login if you already have an account
```

Credit card required for signup (anti-abuse), but you won't be charged on the free tier.

---

## Step 1: Initialize the repo and `pyproject.toml`

**What:** Set up the project root with `pyproject.toml` defining all dependencies.

**Cursor prompt:**

> Create a `pyproject.toml` at the project root for a Python 3.11+ project named "arguss" using uv. Use the exact contents below.

**File: `pyproject.toml`**

```toml
[project]
name = "arguss"
version = "0.1.0"
description = "Secure CI/CD & Software Supply Chain Risk Analyzer"
readme = "README.md"
requires-python = ">=3.11"
authors = [
    { name = "Arguss Team" },
]
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "pydantic>=2.9.0",
    "typer>=0.12.0",
    "python-dotenv>=1.0.0",
    "anthropic>=0.39.0",
    "httpx>=0.27.0",
    "jinja2>=3.1.0",
    "rich>=13.9.0",
]

[project.scripts]
arguss = "arguss.cli:app"

[dependency-groups]
dev = [
    "pytest>=8.3.0",
    "pytest-cov>=5.0.0",
    "pytest-asyncio>=0.24.0",
    "ruff>=0.7.0",
    "mypy>=1.13.0",
    "pre-commit>=4.0.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["arguss"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = [
    "E",    # pycodestyle errors
    "W",    # pycodestyle warnings
    "F",    # pyflakes
    "I",    # isort
    "B",    # flake8-bugbear
    "UP",   # pyupgrade
    "SIM",  # flake8-simplify
]
ignore = ["E501"]  # line length handled by formatter

[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[[tool.mypy.overrides]]
module = ["tests.*"]
disallow_untyped_defs = false

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
addopts = "-v --tb=short"
```

**Verification:**

```bash
uv sync --all-extras
```

Should install all dependencies cleanly into `.venv/`.

---

## Step 2: `.gitignore`, `.env.example`, `README.md`

**Cursor prompt:**

> Create the standard Python `.gitignore`, an `.env.example` template, and a minimal `README.md` for the Arguss project.

**File: `.gitignore`**

```
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
*.egg-info/
.installed.cfg
*.egg
build/
dist/

# Virtual environments
.venv/
venv/
env/

# Testing
.pytest_cache/
.coverage
.coverage.*
htmlcov/
.mypy_cache/
.ruff_cache/

# IDE
.vscode/
.idea/
*.swp
*.swo
.cursor/

# Project-specific
.env
.env.*
!.env.example
*.db
*.sqlite
*.sqlite3
*.db-shm
*.db-wal
arguss/web/static/css/output.css

# OS
.DS_Store
Thumbs.db
```

**File: `.env.example`**

```
# Anthropic API for AI-assisted remediation explanations
ANTHROPIC_API_KEY=sk-ant-your-key-here
ANTHROPIC_EXPLANATION_MODEL=claude-sonnet-4-6

# External APIs
OSV_API_BASE=https://api.osv.dev
NPM_REGISTRY_BASE=https://registry.npmjs.org
DEPSDEV_API_BASE=https://api.deps.dev/v3

# Database
ARGUSS_DB_PATH=./arguss.db
CACHE_TTL_HOURS=24
AI_EXPLANATION_TTL_DAYS=7

# Logging
LOG_LEVEL=INFO
```

**File: `README.md`**

```markdown
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
```

**Verification:**

```bash
git status
```

`.env` should NOT appear; `.env.example` SHOULD appear as untracked.

---

## Step 3: Create the package structure

**Cursor prompt:**

> Create the Arguss package directory structure with empty `__init__.py` files in each module.

Run these commands manually (don't let Cursor invent the structure):

```bash
mkdir -p arguss/core/migrations arguss/lenses arguss/scoring arguss/ai arguss/web/templates arguss/web/static
mkdir -p tests/fixtures
mkdir -p docs
mkdir -p .github/workflows .github/ISSUE_TEMPLATE

touch arguss/__init__.py
touch arguss/core/__init__.py
touch arguss/lenses/__init__.py
touch arguss/scoring/__init__.py
touch arguss/ai/__init__.py
touch tests/__init__.py
```

---

## Step 4: Settings module (env-aware config)

**File: `arguss/settings.py`**

**Cursor prompt:**

> Create `arguss/settings.py` that loads environment variables from `.env`, validates the Anthropic API key shape, and provides an env-aware database path. The DB path defaults to `/data/arguss.db` when running on Fly (detected via `FLY_APP_NAME` env var) and `./arguss.db` locally.

```python
"""Environment-aware configuration for Arguss.

Loads from .env in development, environment in production (Fly.io).
Validates required settings at startup so problems surface immediately.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _default_db_path() -> str:
    """Pick the database path based on runtime environment."""
    if os.environ.get("FLY_APP_NAME"):
        # Running on Fly: use the mounted persistent volume
        return "/data/arguss.db"
    return "./arguss.db"


class Settings:
    """Centralized application settings.

    Reads from environment variables (populated from .env in dev).
    """

    # Anthropic (explanation generation for human-facing PR prose; not on the decision path)
    _anthropic_key_raw: str = os.environ.get("ANTHROPIC_API_KEY", "")
    anthropic_api_key: str | None = _anthropic_key_raw if _anthropic_key_raw else None
    anthropic_explanation_model: str = os.environ.get(
        "ANTHROPIC_EXPLANATION_MODEL", "claude-sonnet-4-6"
    )

    # External APIs
    osv_api_base: str = os.environ.get("OSV_API_BASE", "https://api.osv.dev")
    npm_registry_base: str = os.environ.get("NPM_REGISTRY_BASE", "https://registry.npmjs.org")
    depsdev_api_base: str = os.environ.get("DEPSDEV_API_BASE", "https://api.deps.dev/v3")

    # Database
    db_path: Path = Path(os.environ.get("ARGUSS_DB_PATH", _default_db_path()))
    cache_ttl_hours: int = int(os.environ.get("CACHE_TTL_HOURS", "24"))
    ai_explanation_ttl_days: int = int(os.environ.get("AI_EXPLANATION_TTL_DAYS", "7"))

    # Logging
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")

    # Deployment detection
    is_production: bool = bool(os.environ.get("FLY_APP_NAME"))


def validate_settings(require_ai: bool = False) -> None:
    """Fail fast at startup if required settings are missing or malformed.

    Args:
        require_ai: If True, the Anthropic API key must be present. Used by
            the AI explainer module; not required for basic CLI scans.
    """
    if require_ai:
        key = Settings.anthropic_api_key
        if not key:
            sys.exit(
                "ANTHROPIC_API_KEY not set. "
                "Copy .env.example to .env and fill in your key, "
                "or run with --no-ai to skip AI features."
            )
        if not key.startswith("sk-ant-"):
            sys.exit(
                "ANTHROPIC_API_KEY doesn't look right "
                "(should start with sk-ant-). Check your .env file."
            )

    # Ensure DB directory exists
    Settings.db_path.parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
```

**Verification:**

```bash
uv run python -c "from arguss.settings import settings; print('DB path:', settings.db_path); print('Is prod:', settings.is_production)"
```

Should print local DB path and `Is prod: False`.

---

## Step 5: Pydantic data models

**File: `arguss/core/models.py`**

**Cursor prompt:**

> Create `arguss/core/models.py` with the Pydantic v2 data models below. These are the data contracts every component will use. Don't add fields or methods beyond what's specified.

```python
"""Core data models for Arguss.

These Pydantic models define the contracts between components.
All lenses, scoring, AI, and serialization layers consume and produce these types.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low"]
LensName = Literal["cve", "trust", "pipeline"]
MigrationRisk = Literal["low", "medium", "high", "unknown"]
Confidence = Literal["low", "medium", "high"]


class Dependency(BaseModel):
    """A single package in the dependency graph."""

    name: str
    version: str
    ecosystem: str = "npm"
    direct: bool = Field(
        description="True if listed in the manifest directly; False if pulled in transitively."
    )
    path: list[str] = Field(
        default_factory=list,
        description="Chain of package names from project root to this dependency.",
    )
    parents: list[str] = Field(
        default_factory=list,
        description="Direct parents (packages that depend on this one).",
    )


class Finding(BaseModel):
    """A single risk finding from one of the three lenses."""

    dependency: Dependency
    lens: LensName
    severity: Severity
    score: float = Field(ge=0, le=100, description="Normalized severity score 0-100.")
    title: str
    description: str
    remediation: str | None = None
    source_url: str | None = None


class LensScore(BaseModel):
    """Aggregated output of a single lens scan."""

    lens: LensName
    score: float = Field(ge=0, le=100)
    findings: list[Finding] = Field(default_factory=list)


class Explanation(BaseModel):
    """AI-generated explanation of a remediation."""

    summary: str
    why_it_matters: str
    migration_risk: MigrationRisk
    migration_notes: str
    suggested_steps: list[str]
    confidence: Confidence
    generated_at: datetime
    model: str = Field(description="Which Anthropic model produced this.")
    prompt_version: str = Field(description="Version tag of the prompt template used.")


class Remediation(BaseModel):
    """A proposed change that reduces project risk."""

    change: str = Field(description="Human-readable change, e.g., 'upgrade foo from 1.2 to 1.4'.")
    package_name: str
    from_version: str
    to_version: str
    findings_eliminated: list[Finding] = Field(default_factory=list)
    score_reduction: float = Field(
        ge=0,
        description="Estimated reduction in overall project score if applied.",
    )
    explanation: Explanation | None = None


class ProjectScore(BaseModel):
    """The unified result of an Arguss scan."""

    overall: float = Field(ge=0, le=100)
    lens_scores: dict[LensName, LensScore]
    top_remediations: list[Remediation] = Field(default_factory=list)
    scanned_at: datetime
    project_path: str
```

**Verification:**

```bash
uv run python -c "from arguss.core.models import ProjectScore; print('models OK')"
```

---

## Step 6: SQLite cache module + migrations

**File: `arguss/core/migrations/001_initial.sql`**

**Cursor prompt:**

> Create the initial SQL migration with three tables: api_cache, ai_explanations, and scan_history. Use the schema below exactly.

```sql
-- Initial schema: API response cache, AI explanation cache, scan history.

CREATE TABLE IF NOT EXISTS api_cache (
    key TEXT PRIMARY KEY,
    response_json TEXT NOT NULL,
    source TEXT NOT NULL,           -- 'osv', 'npm', 'deps_dev', 'scorecard', 'epss', 'kev'
    cached_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_cache_expires ON api_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_cache_source ON api_cache(source);

CREATE TABLE IF NOT EXISTS ai_explanations (
    cache_key TEXT PRIMARY KEY,     -- hash of (package, from_v, to_v, findings_hash, prompt_v)
    package_name TEXT NOT NULL,
    from_version TEXT NOT NULL,
    to_version TEXT NOT NULL,
    findings_hash TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    explanation_json TEXT NOT NULL,
    model TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_explanations_expires ON ai_explanations(expires_at);

CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,            -- UUID
    project_identifier TEXT,        -- repo URL or filename hash
    overall_score REAL NOT NULL,
    lens_scores_json TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending'  -- 'pending', 'complete', 'failed'
);

CREATE INDEX IF NOT EXISTS idx_scan_history_scanned ON scan_history(scanned_at DESC);
```

**File: `arguss/core/cache.py`**

**Cursor prompt:**

> Create `arguss/core/cache.py` with SQLite connection management (WAL mode), a migration runner that applies numbered SQL files from `migrations/`, and a `Cache` class with methods for the API response cache. Use the contents below exactly.

```python
"""SQLite cache and migrations for Arguss.

WAL mode is enabled for better concurrent read performance.
Migrations are numbered SQL files in arguss/core/migrations/; they're applied
automatically at startup based on the schema_version table.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def get_connection(db_path: Path | str) -> sqlite3.Connection:
    """Open a SQLite connection with sensible defaults for this project."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Apply any pending schema migrations.

    Tracks applied migrations in the schema_version table. Migration files
    are SQL files in MIGRATIONS_DIR named like '001_initial.sql'.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )
    conn.commit()

    current_row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    current = current_row[0] if current_row and current_row[0] is not None else 0

    for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = int(sql_file.stem.split("_")[0])
        if version > current:
            conn.executescript(sql_file.read_text())
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, datetime.now(UTC).isoformat()),
            )
            conn.commit()


class Cache:
    """Cache layer wrapping the SQLite database.

    Handles API response caching with TTL eviction. AI explanation caching
    lands in Week 10 as separate methods.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def get_api_response(self, source: str, key: str) -> dict[str, Any] | None:
        """Retrieve a cached API response, or None if missing/expired."""
        row = self.conn.execute(
            """
            SELECT response_json FROM api_cache
            WHERE key = ? AND source = ? AND expires_at > ?
            """,
            (key, source, datetime.now(UTC).isoformat()),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["response_json"])  # type: ignore[no-any-return]

    def set_api_response(
        self,
        source: str,
        key: str,
        response: dict[str, Any],
        ttl_hours: int = 24,
    ) -> None:
        """Store an API response with a TTL."""
        now = datetime.now(UTC)
        expires = now + timedelta(hours=ttl_hours)
        self.conn.execute(
            """
            INSERT OR REPLACE INTO api_cache
                (key, response_json, source, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (key, json.dumps(response), source, now.isoformat(), expires.isoformat()),
        )
        self.conn.commit()

    def cleanup_expired(self) -> int:
        """Remove expired entries from all caches. Returns count removed."""
        now = datetime.now(UTC).isoformat()
        cur1 = self.conn.execute("DELETE FROM api_cache WHERE expires_at <= ?", (now,))
        cur2 = self.conn.execute("DELETE FROM ai_explanations WHERE expires_at <= ?", (now,))
        self.conn.commit()
        return (cur1.rowcount or 0) + (cur2.rowcount or 0)
```

**Verification:**

```bash
uv run python -c "
from arguss.core.cache import get_connection, init_db, Cache
from arguss.settings import settings, validate_settings
validate_settings()
conn = get_connection(settings.db_path)
init_db(conn)
cache = Cache(conn)
cache.set_api_response('test', 'key1', {'hello': 'world'})
print('Cache get:', cache.get_api_response('test', 'key1'))
print('Schema OK')
"
```

Should print `Cache get: {'hello': 'world'}` and `Schema OK`. A `arguss.db` file appears in the project root.

---

## Step 7: Fake-data lens stubs

**Cursor prompt:**

> Create three lens modules under `arguss/lenses/`, each with a class that returns hardcoded fake data. The class signatures are contracts — they must not change when real implementations replace them later.

**File: `arguss/lenses/__init__.py`**

```python
"""Risk analysis lenses for Arguss."""

from arguss.lenses.pipeline import PipelineLens
from arguss.lenses.trust import TrustLens
from arguss.lenses.vulnerability import VulnerabilityLens

__all__ = ["VulnerabilityLens", "TrustLens", "PipelineLens"]
```

**File: `arguss/lenses/vulnerability.py`**

```python
"""Vulnerability lens — known CVEs from OSV.dev, enriched with EPSS and CISA KEV.

WEEK 3: Replace fake data with real OSV.dev integration.
WEEK 10: Add EPSS and CISA KEV enrichment.
"""

from arguss.core.models import Dependency, Finding, LensScore


class VulnerabilityLens:
    """Scans dependencies for known vulnerabilities."""

    def scan(self, deps: list[Dependency]) -> LensScore:
        """Return a LensScore for the given dependencies.

        Currently returns hardcoded fake data for skeleton testing.
        """
        if not deps:
            return LensScore(lens="cve", score=0.0, findings=[])

        fake_finding = Finding(
            dependency=deps[0],
            lens="cve",
            severity="high",
            score=75.0,
            title="CVE-2024-FAKE: Prototype pollution in fake-package",
            description=(
                "A fake high-severity CVE for skeleton testing. "
                "Will be replaced with real OSV.dev data in Week 3."
            ),
            remediation=f"Upgrade {deps[0].name} to a patched version",
            source_url="https://osv.dev/vulnerability/FAKE-2024-0001",
        )

        return LensScore(lens="cve", score=75.0, findings=[fake_finding])
```

**File: `arguss/lenses/trust.py`**

```python
"""Trust signal lens — maintainer health, typosquatting, OpenSSF Scorecard.

WEEK 4: Replace fake data with npm registry + typosquat + Scorecard integration.
"""

from arguss.core.models import Dependency, Finding, LensScore


class TrustLens:
    """Scans dependencies for package trust signals."""

    def scan(self, deps: list[Dependency]) -> LensScore:
        """Return a LensScore for the given dependencies.

        Currently returns hardcoded fake data for skeleton testing.
        """
        if not deps:
            return LensScore(lens="trust", score=0.0, findings=[])

        fake_finding = Finding(
            dependency=deps[0],
            lens="trust",
            severity="medium",
            score=40.0,
            title=f"Single-maintainer package: {deps[0].name}",
            description=(
                "Fake trust signal for skeleton testing. "
                "Will be replaced with real npm registry data in Week 4."
            ),
            remediation="Review maintainer history before upgrading",
            source_url=f"https://www.npmjs.com/package/{deps[0].name}",
        )

        return LensScore(lens="trust", score=40.0, findings=[fake_finding])
```

**File: `arguss/lenses/pipeline.py`**

```python
"""Pipeline configuration lens — GitHub Actions workflow analysis via zizmor.

WEEK 5: Replace fake data with real zizmor subprocess wrapper.
"""

from pathlib import Path

from arguss.core.models import Dependency, Finding, LensScore


class PipelineLens:
    """Scans GitHub Actions workflows for configuration risks."""

    def scan(self, project_path: str | Path) -> LensScore:
        """Return a LensScore for the project's .github/workflows directory.

        Currently returns hardcoded fake data for skeleton testing.
        """
        fake_dep = Dependency(
            name=".github/workflows/ci.yml",
            version="N/A",
            ecosystem="github-actions",
            direct=True,
        )

        fake_finding = Finding(
            dependency=fake_dep,
            lens="pipeline",
            severity="medium",
            score=50.0,
            title="Unpinned action reference",
            description=(
                "Fake pipeline finding for skeleton testing. "
                "Will be replaced with real zizmor output in Week 5."
            ),
            remediation="Pin actions to a specific SHA",
            source_url=None,
        )

        return LensScore(lens="pipeline", score=50.0, findings=[fake_finding])
```

---

## Step 8: Unified scoring (real, not fake)

**Cursor prompt:**

> Create `arguss/scoring/unified.py` with the real weighted scoring math. This is NOT a stub — implement the actual 40/30/30 formula. Include the remediation ranker stub for now.

**File: `arguss/scoring/__init__.py`**

```python
"""Unified scoring engine for Arguss."""

from arguss.scoring.unified import compute_project_score

__all__ = ["compute_project_score"]
```

**File: `arguss/scoring/unified.py`**

```python
"""Unified scoring engine.

Combines the three lens sub-scores into a single project risk score.
The math is real and stable from day one; only the inputs change.
"""

from datetime import UTC, datetime

from arguss.core.models import LensScore, ProjectScore, Remediation

# Default weights. Configurable via env or CLI in future.
DEFAULT_WEIGHTS = {
    "cve": 0.40,
    "trust": 0.30,
    "pipeline": 0.30,
}


def compute_project_score(
    cve: LensScore,
    trust: LensScore,
    pipeline: LensScore,
    project_path: str = ".",
    weights: dict[str, float] | None = None,
) -> ProjectScore:
    """Combine three lens scores into a unified ProjectScore.

    Args:
        cve: Vulnerability lens output.
        trust: Trust signal lens output.
        pipeline: Pipeline configuration lens output.
        project_path: Path to the project being scanned (for the report).
        weights: Optional override for lens weights. Must sum to 1.0.

    Returns:
        ProjectScore with overall risk, per-lens breakdown, and ranked remediations.
    """
    w = weights or DEFAULT_WEIGHTS
    _validate_weights(w)

    overall = (
        cve.score * w["cve"]
        + trust.score * w["trust"]
        + pipeline.score * w["pipeline"]
    )

    return ProjectScore(
        overall=round(overall, 2),
        lens_scores={
            "cve": cve,
            "trust": trust,
            "pipeline": pipeline,
        },
        top_remediations=_rank_remediations(cve, trust, pipeline),
        scanned_at=datetime.now(UTC),
        project_path=project_path,
    )


def _validate_weights(weights: dict[str, float]) -> None:
    """Ensure weights sum to 1.0 within floating-point tolerance."""
    total = sum(weights.values())
    if abs(total - 1.0) > 0.01:
        raise ValueError(f"Lens weights must sum to 1.0, got {total}")


def _rank_remediations(
    cve: LensScore,
    trust: LensScore,
    pipeline: LensScore,
) -> list[Remediation]:
    """Generate ranked list of top remediations.

    WEEK 6: Replace stub with real ranker that computes score reduction
    per proposed upgrade.
    """
    # Stub: return empty list for now. Real ranker lands Week 6.
    return []
```

---

## Step 9: CLI wired end-to-end

**File: `arguss/cli.py`**

**Cursor prompt:**

> Create `arguss/cli.py` using Typer. It should expose a single `scan` command that wires the parser, all three lenses, and the scoring engine together, then prints the JSON ProjectScore. Include a `--no-ai` flag (stubbed for now; will be respected by the AI explainer in Week 10).

```python
"""Arguss CLI entry point.

Usage:
    arguss scan ./path/to/project
"""

import json
import sys
from pathlib import Path

import typer
from rich.console import Console

from arguss.core.models import Dependency
from arguss.lenses import PipelineLens, TrustLens, VulnerabilityLens
from arguss.scoring import compute_project_score

app = typer.Typer(
    name="arguss",
    help="Secure CI/CD & Software Supply Chain Risk Analyzer",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to project root or package-lock.json"),
    no_ai: bool = typer.Option(  # noqa: ARG001
        False,
        "--no-ai",
        help="Skip AI-assisted remediation explanations (offline-safe mode).",
    ),
    output_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format: json or pretty.",
    ),
) -> None:
    """Scan a project for supply chain risks."""
    project_path = Path(path).resolve()
    if not project_path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {project_path}")
        sys.exit(1)

    # WEEK 3: Replace with real parser.parse_lockfile(project_path)
    deps = _fake_deps()

    cve = VulnerabilityLens().scan(deps)
    trust = TrustLens().scan(deps)
    pipeline = PipelineLens().scan(project_path)

    score = compute_project_score(
        cve=cve,
        trust=trust,
        pipeline=pipeline,
        project_path=str(project_path),
    )

    if output_format == "pretty":
        _print_pretty(score)
    else:
        print(score.model_dump_json(indent=2))


def _fake_deps() -> list[Dependency]:
    """Return hardcoded dependency list for skeleton testing.

    WEEK 3: Delete this. Replace with real parser.
    """
    return [
        Dependency(
            name="fake-package",
            version="1.0.0",
            ecosystem="npm",
            direct=True,
            path=["root", "fake-package"],
            parents=["root"],
        ),
        Dependency(
            name="fake-transitive",
            version="2.3.1",
            ecosystem="npm",
            direct=False,
            path=["root", "fake-package", "fake-transitive"],
            parents=["fake-package"],
        ),
    ]


def _print_pretty(score) -> None:  # type: ignore[no-untyped-def]
    """Pretty-print a ProjectScore to the terminal."""
    console.print(f"\n[bold]Arguss Scan Result[/bold] — {score.project_path}")
    console.print(f"Overall risk: [bold]{score.overall:.1f}[/bold] / 100\n")
    for lens_name, lens in score.lens_scores.items():
        console.print(f"  [cyan]{lens_name}[/cyan]: {lens.score:.1f} ({len(lens.findings)} findings)")


if __name__ == "__main__":
    app()
```

**Verification:**

```bash
uv run arguss scan .
```

Should print a JSON ProjectScore with overall risk ~55.

```bash
uv run arguss scan . --format pretty
```

---

## Step 10: Minimal FastAPI app for the hello-world deploy

This isn't the real dashboard — that comes Week 7. This is enough to prove the Fly deployment pipeline works.

**File: `arguss/api.py`**

**Cursor prompt:**

> Create `arguss/api.py` with a minimal FastAPI app. One route returns a JSON health check; the root returns simple HTML. This is the Week 1 hello-world to verify the Fly.io deployment pipeline.

```python
"""FastAPI application entry point.

WEEK 1: Minimal hello-world for deployment verification.
WEEK 7: Real dashboard with HTMX + Tailwind lands here.
"""

from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from arguss.settings import settings

app = FastAPI(
    title="Arguss",
    description="Secure CI/CD & Software Supply Chain Risk Analyzer",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    """Health check endpoint for Fly.io monitoring."""
    return {
        "status": "ok",
        "service": "arguss",
        "timestamp": datetime.now(UTC).isoformat(),
        "environment": "production" if settings.is_production else "development",
    }


@app.get("/", response_class=HTMLResponse)
def root() -> str:
    """Landing page placeholder."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Arguss</title>
        <style>
            body { font-family: system-ui, sans-serif; max-width: 640px; margin: 4em auto; padding: 0 1em; color: #222; }
            h1 { font-size: 2.5em; margin-bottom: 0.2em; }
            p { font-size: 1.1em; line-height: 1.5; }
            code { background: #f4f4f4; padding: 0.1em 0.4em; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>Arguss</h1>
        <p><strong>Three lenses. One risk score.</strong></p>
        <p>Secure CI/CD &amp; Software Supply Chain Risk Analyzer.</p>
        <p>🚧 Under active development as a MICS Capstone project (Summer 2026).</p>
        <p>Health check: <code><a href="/health">/health</a></code></p>
    </body>
    </html>
    """
```

**Verification:**

```bash
uv run uvicorn arguss.api:app --reload
```

Open http://localhost:8000 in a browser. Should see the Arguss landing page. Visit http://localhost:8000/health for the JSON response.

---

## Step 11: Canary integration tests

**File: `tests/test_skeleton.py`**

**Cursor prompt:**

> Create `tests/test_skeleton.py` with the canary integration test plus a few model-level tests. These tests must stay green for the whole semester — they're the contract.

```python
"""Skeleton tests — canary suite that stays green for the whole project."""

import json
from pathlib import Path

from typer.testing import CliRunner

from arguss.cli import app
from arguss.core.models import LensScore, ProjectScore
from arguss.lenses import PipelineLens, TrustLens, VulnerabilityLens
from arguss.scoring import compute_project_score

runner = CliRunner()


def test_cli_runs_end_to_end(tmp_path: Path) -> None:
    """The CLI accepts a path and prints a valid ProjectScore JSON."""
    fake_lockfile = tmp_path / "package-lock.json"
    fake_lockfile.write_text('{"lockfileVersion": 3, "packages": {}}')

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0, f"CLI failed: {result.output}"
    output = json.loads(result.stdout)
    assert "overall" in output
    assert 0 <= output["overall"] <= 100
    assert "lens_scores" in output
    assert set(output["lens_scores"].keys()) == {"cve", "trust", "pipeline"}


def test_unified_scoring_math() -> None:
    """The unified score is a weighted average of the three lenses."""
    cve = LensScore(lens="cve", score=100.0, findings=[])
    trust = LensScore(lens="trust", score=0.0, findings=[])
    pipeline = LensScore(lens="pipeline", score=0.0, findings=[])

    score = compute_project_score(cve, trust, pipeline)

    # 100 * 0.4 + 0 * 0.3 + 0 * 0.3 = 40
    assert score.overall == 40.0


def test_unified_scoring_all_max() -> None:
    """When all lenses max out, overall is 100."""
    cve = LensScore(lens="cve", score=100.0, findings=[])
    trust = LensScore(lens="trust", score=100.0, findings=[])
    pipeline = LensScore(lens="pipeline", score=100.0, findings=[])

    score = compute_project_score(cve, trust, pipeline)
    assert score.overall == 100.0


def test_unified_scoring_all_zero() -> None:
    """When all lenses are clean, overall is 0."""
    cve = LensScore(lens="cve", score=0.0, findings=[])
    trust = LensScore(lens="trust", score=0.0, findings=[])
    pipeline = LensScore(lens="pipeline", score=0.0, findings=[])

    score = compute_project_score(cve, trust, pipeline)
    assert score.overall == 0.0


def test_lenses_return_valid_lens_scores() -> None:
    """Each lens returns a LensScore matching its declared name."""
    from arguss.core.models import Dependency

    deps = [Dependency(name="x", version="1.0.0", direct=True)]

    cve = VulnerabilityLens().scan(deps)
    trust = TrustLens().scan(deps)
    pipeline = PipelineLens().scan(".")

    assert cve.lens == "cve"
    assert trust.lens == "trust"
    assert pipeline.lens == "pipeline"
    assert all(0 <= s.score <= 100 for s in [cve, trust, pipeline])


def test_project_score_serializes_to_json() -> None:
    """A ProjectScore round-trips through JSON cleanly."""
    cve = LensScore(lens="cve", score=50.0, findings=[])
    trust = LensScore(lens="trust", score=30.0, findings=[])
    pipeline = LensScore(lens="pipeline", score=20.0, findings=[])

    score = compute_project_score(cve, trust, pipeline)
    serialized = score.model_dump_json()
    restored = ProjectScore.model_validate_json(serialized)

    assert restored.overall == score.overall


def test_health_endpoint() -> None:
    """The FastAPI health endpoint responds correctly."""
    from fastapi.testclient import TestClient

    from arguss.api import app as api_app

    client = TestClient(api_app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "arguss"


def test_cache_round_trip(tmp_path: Path) -> None:
    """The SQLite cache writes and reads back values correctly."""
    from arguss.core.cache import Cache, get_connection, init_db

    db_path = tmp_path / "test.db"
    conn = get_connection(db_path)
    init_db(conn)
    cache = Cache(conn)

    cache.set_api_response("osv", "test-key", {"vulns": ["CVE-1"]})
    assert cache.get_api_response("osv", "test-key") == {"vulns": ["CVE-1"]}
    assert cache.get_api_response("osv", "nonexistent") is None
```

**Verification:**

```bash
uv run pytest
```

All tests should pass.

---

## Step 12: Dockerfile for Fly deployment

**File: `Dockerfile`**

**Cursor prompt:**

> Create a multi-stage Dockerfile for the Arguss FastAPI app using uv as the package manager. The image should be slim, use a non-root user, and run uvicorn on port 8080 (Fly's default).

```dockerfile
# syntax=docker/dockerfile:1.7

# ---- Build stage ----
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Install dependencies (cached layer when pyproject.toml unchanged)
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-install-project

# Copy source and install the project itself
COPY arguss ./arguss
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev

# ---- Runtime stage ----
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# Create non-root user
RUN groupadd -r arguss && useradd -r -g arguss arguss

WORKDIR /app

# Copy the virtualenv and source from the builder
COPY --from=builder --chown=arguss:arguss /app/.venv /app/.venv
COPY --from=builder --chown=arguss:arguss /app/arguss /app/arguss

# Create data directory for SQLite volume mount
RUN mkdir -p /data && chown arguss:arguss /data

USER arguss

EXPOSE 8080

# Health check for Fly
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health').read()" || exit 1

CMD ["uvicorn", "arguss.api:app", "--host", "0.0.0.0", "--port", "8080"]
```

**File: `.dockerignore`**

```
.git
.github
.venv
__pycache__
*.pyc
.pytest_cache
.mypy_cache
.ruff_cache
.env
.env.*
!.env.example
*.db
*.sqlite*
*.db-shm
*.db-wal
docs/
tests/
README.md
*.md
```

**Verification (optional, requires Docker locally):**

```bash
docker build -t arguss:dev .
docker run --rm -p 8080:8080 arguss:dev
```

Visit http://localhost:8080 — should see the same landing page as the local uvicorn run.

---

## Step 13: Fly.io configuration

**File: `fly.toml`**

**Cursor prompt:**

> Create the Fly.io app configuration with a persistent volume for SQLite, auto-stop disabled (to avoid cold starts during demos), and a health check pointing at /health.

```toml
# Fly.io app configuration for Arguss.
# https://fly.io/docs/reference/configuration/

app = "arguss"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile"

[env]
  PORT = "8080"
  LOG_LEVEL = "INFO"
  ARGUSS_DB_PATH = "/data/arguss.db"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = false   # Keep warm for capstone demos
  auto_start_machines = true
  min_machines_running = 1

  [http_service.concurrency]
    type = "requests"
    hard_limit = 50
    soft_limit = 25

[[http_service.checks]]
  interval = "30s"
  timeout = "5s"
  grace_period = "10s"
  method = "GET"
  path = "/health"

[mounts]
  source = "arguss_data"
  destination = "/data"
  initial_size = "1gb"

[[vm]]
  size = "shared-cpu-1x"
  memory = "256mb"
  cpu_kind = "shared"
  cpus = 1
```

### Initialize the Fly app

Run these commands once (don't put them in Cursor):

```bash
# Launch the app (creates it on Fly but doesn't deploy yet)
flyctl launch --no-deploy --copy-config --name arguss

# If "arguss" is taken (likely), use a suffix like arguss-mics2026
# Update the `app = ` line in fly.toml to match

# Create the persistent volume
flyctl volumes create arguss_data --region iad --size 1

# Set the Anthropic API key as a Fly secret (not committed)
flyctl secrets set ANTHROPIC_API_KEY=sk-ant-your-key-here

# Deploy
flyctl deploy
```

**Verification:**

```bash
flyctl status
flyctl logs
```

Open `https://arguss-<your-suffix>.fly.dev/` in a browser. Should see the landing page. Visit `/health` for JSON.

**Set Anthropic spending cap:** Log into the Anthropic console (https://console.anthropic.com), navigate to Settings → Usage limits, set a $20/month cap. Do this now, not later.

---

## Step 14: GitHub Actions CI workflows

**File: `.github/workflows/ci.yml`**

**Cursor prompt:**

> Create the main CI workflow that runs on every push and PR. It should lint, format-check, type-check, and test.

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3
        with:
          enable-cache: true

      - name: Set up Python
        run: uv python install 3.11

      - name: Install dependencies
        run: uv sync --all-extras

      - name: Lint
        run: uv run ruff check .

      - name: Format check
        run: uv run ruff format --check .

      - name: Type check
        run: uv run mypy arguss

      - name: Test
        run: uv run pytest --cov=arguss --cov-report=term-missing
```

**File: `.github/workflows/secret-scan.yml`**

```yaml
name: Secret scan

on:
  push:
  pull_request:

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**File: `.github/workflows/deploy.yml`**

```yaml
name: Deploy

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    name: Deploy to Fly.io
    runs-on: ubuntu-latest
    concurrency:
      group: deploy-${{ github.ref }}
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@v4

      - name: Set up flyctl
        uses: superfly/flyctl-actions/setup-flyctl@master

      - name: Deploy
        run: flyctl deploy --remote-only
        env:
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
```

### Get a Fly deploy token for GitHub Actions

```bash
flyctl tokens create deploy -x 8760h
```

Copy the output. In the GitHub repo: Settings → Secrets and variables → Actions → New repository secret. Name: `FLY_API_TOKEN`. Value: paste the token.

---

## Step 15: Pre-commit hooks

**File: `.pre-commit-config.yaml`**

**Cursor prompt:**

> Create the pre-commit configuration with ruff, gitleaks, and standard hygiene hooks.

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.7.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-added-large-files
      - id: check-merge-conflict
      - id: check-yaml
      - id: check-toml
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: detect-private-key
```

**Verification:**

```bash
uv run pre-commit install
uv run pre-commit run --all-files
```

First run will fix formatting. Run again — should be clean.

---

## Step 16: Issue templates

**File: `.github/ISSUE_TEMPLATE/feature.md`**

```markdown
---
name: Feature
about: A new capability or improvement
labels: feature
---

## Context

What is this and why does it matter?

## Acceptance criteria

- [ ] ...
- [ ] ...

## Out of scope

What this issue is explicitly NOT doing. Things that might be tempting to expand into but belong in a separate issue or a future sprint.

## Notes

Any technical detail, links, or dependencies on other issues.
```

**File: `.github/ISSUE_TEMPLATE/bug.md`**

```markdown
---
name: Bug
about: Something is broken
labels: bug
---

## What happened

## What you expected

## How to reproduce

1. ...
2. ...

## Environment

- OS:
- Python version:
- Branch / commit:
```

---

## Step 17: Final verification

Run through this checklist before considering Day 1 done:

```bash
# Skeleton runs locally
uv run arguss scan .

# JSON output is valid
uv run arguss scan . | python -c "import json, sys; json.load(sys.stdin); print('OK')"

# Local FastAPI starts
uv run uvicorn arguss.api:app --reload &
sleep 2 && curl -s http://localhost:8000/health | python -m json.tool
kill %1

# All tests pass
uv run pytest

# Lint clean
uv run ruff check .

# Format clean
uv run ruff format --check .

# Types clean
uv run mypy arguss

# Pre-commit clean
uv run pre-commit run --all-files
```

Then push to GitHub:

```bash
git add .
git commit -m "Initial skeleton: fake-data wiring, SQLite cache, hello-world deploy"
git push -u origin main
```

Watch the CI run on GitHub. `ci.yml`, `secret-scan.yml`, and `deploy.yml` should all pass.

After the deploy workflow finishes, verify the live URL:

```bash
curl -s https://arguss-<your-suffix>.fly.dev/health | python -m json.tool
```

---

## Step 18: GitHub Project board

This part can't be done by Cursor — it's manual UI work on GitHub.

1. Go to the repo on GitHub → Projects → New project → "Board"
2. Name it "Arguss capstone"
3. Add custom fields:
   - **Week** (single-select): Week 1, Week 2, ..., Week 14
   - **Owner** (single-select): one entry per team member
   - **Lens** (single-select): Vulnerability, Trust, Pipeline, Scoring, AI, Frontend, Infra, Eval
   - **Size** (single-select): S, M, L
4. Add views:
   - "Board by status" — default board view, columns Backlog/This Week/In Progress/In Review/Done
   - "Roadmap by week" — timeline view grouped by Week field
5. Create a few starter issues for Week 2 work

---

## Step 19: Branch protection

Also manual GitHub UI:

1. Repo → Settings → Branches → Add rule for `main`
2. Enable:
   - Require a pull request before merging
   - Require approvals: 1
   - Require status checks to pass: select `test` and `gitleaks`
   - Require conversation resolution before merging
   - Do not allow bypassing the above settings

---

## What you should have at the end of Day 1

A repo where:

1. `uv run arguss scan .` prints a JSON ProjectScore with overall ~55
2. `uv run uvicorn arguss.api:app` starts the FastAPI app locally
3. `uv run pytest` passes with 8 tests green
4. `uv run pre-commit run --all-files` clean
5. CI passes on `main` and on PRs
6. Secret scanning runs on every push
7. **The hello-world FastAPI app is live at `https://arguss-<suffix>.fly.dev`**
8. **CI auto-deploys to Fly on every merge to main**
9. Branch protection blocks direct pushes to `main`
10. Project board exists with custom fields and views
11. `.env.example` committed, `.env` ignored
12. Anthropic spending cap set to $20/month
13. SQLite cache module working with WAL mode and migrations

From here, Week 3 onward is replacing one fake-data stub at a time. The contract (the data models, the lens interfaces, the scoring math, the deployment pipeline) doesn't change.

---

## Troubleshooting

**`uv` not found:** Add `~/.local/bin` (or wherever `uv` installed) to your PATH.

**`flyctl` not found:** Add `~/.fly/bin` to your PATH.

**Pydantic v1 vs v2 errors:** Make sure `pyproject.toml` pins `pydantic>=2.9.0`. The model syntax is v2-specific.

**`mypy` complains about untyped imports:** Add the package to `[[tool.mypy.overrides]]` with `ignore_missing_imports = true` if it's a known issue with the upstream package.

**Pre-commit fails on first run with formatting changes:** This is normal. Pre-commit auto-fixes; just re-add and re-commit.

**CI fails but local passes:** Almost always a missing dependency in `pyproject.toml` or a hardcoded path. Check the CI log for the specific step that failed.

**Fly deploy fails with "app not found":** Run `flyctl apps list` to confirm the app name; update `fly.toml` if needed.

**Fly deploy fails with "no machines":** Run `flyctl scale count 1` to spin up your free machine.

**Fly health check failing:** Check `flyctl logs` — usually the app crashed at startup. Common cause: missing required env var. Set with `flyctl secrets set KEY=value`.

**Volume mount fails:** Volumes are region-specific. The volume in `fly.toml` must be in the same region as `primary_region`. Confirm with `flyctl volumes list`.

---

## Next steps (after Day 1)

- Hand the [main project plan](./arguss-project-plan.md) to the team
- Schedule the Monday team sync rhythm
- Create Week 2 issues on the project board for the 5W1H submission and demo scenario research
- Get every team member running `arguss scan .` locally and pushing a trivial PR to verify the workflow end-to-end
- Verify the Fly URL is in the README and pinned in the team Slack channel
