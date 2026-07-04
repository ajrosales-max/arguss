"""Environment-aware configuration for Arguss.

Loads from .env in development, environment in production (Fly.io).
Validates required settings at startup so problems surface immediately.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _parse_bool_env(key: str, default: bool) -> bool:
    """Parse a boolean environment variable."""
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


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
    """Anthropic API key for explanation generation. If unset, the explainer is disabled
    and callers fall back to deterministic output."""

    anthropic_explanation_model: str = os.environ.get(
        "ANTHROPIC_EXPLANATION_MODEL", "claude-sonnet-4-6"
    )
    """Claude model for explanation generation (Sonnet default; haiku faster/cheaper)."""

    # External APIs
    osv_api_base: str = os.environ.get("OSV_API_BASE", "https://api.osv.dev")
    npm_registry_base: str = os.environ.get("NPM_REGISTRY_BASE", "https://registry.npmjs.org")
    depsdev_api_base: str = os.environ.get("DEPSDEV_API_BASE", "https://api.deps.dev/v3")
    scorecard_api_base: str = os.environ.get(
        "SCORECARD_API_BASE",
        "https://api.securityscorecards.dev/projects/github.com",
    )

    # Database
    db_path: Path = Path(os.environ.get("ARGUSS_DB_PATH", _default_db_path()))
    cache_ttl_hours: int = int(os.environ.get("CACHE_TTL_HOURS", "24"))
    ai_explanation_ttl_days: int = int(os.environ.get("AI_EXPLANATION_TTL_DAYS", "7"))

    # Logging
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")

    # Deployment detection
    is_production: bool = bool(os.environ.get("FLY_APP_NAME"))

    # Mode C: max concurrent PR-open tasks per scan (thread-pool backed)
    mode_c_concurrency: int = int(os.environ.get("MODE_C_CONCURRENCY", "5"))

    # Mode C wait-and-merge: CI polling and merge timeout
    mode_c_ci_poll_interval_seconds: int = int(
        os.environ.get("MODE_C_CI_POLL_INTERVAL_SECONDS", "15")
    )
    mode_c_ci_grace_period_seconds: int = int(
        os.environ.get("MODE_C_CI_GRACE_PERIOD_SECONDS", "90")
    )
    mode_c_merge_wait_cap_seconds: int = int(
        os.environ.get("MODE_C_MERGE_WAIT_CAP_SECONDS", "1200")
    )

    # Mode A: optional service-level GitHub token for Contents API rate limits (read-only)
    _github_token_raw: str = os.environ.get("ARGUSS_GITHUB_TOKEN", "")
    github_token: str | None = _github_token_raw if _github_token_raw else None
    """Optional GitHub token for Mode A crawls. Never used on the action/write path."""

    # Demo-period HTTP Basic Auth (web service only; unset = disabled)
    demo_username: str = os.environ.get("ARGUSS_DEMO_USERNAME", "demo")
    _demo_password_raw: str = os.environ.get("ARGUSS_DEMO_PASSWORD", "")
    demo_password: str | None = _demo_password_raw if _demo_password_raw else None

    # Wizard: allow users to override DECLINE-tier candidates on /select (default on for demo)
    allow_decline_override: bool = _parse_bool_env("ARGUSS_ALLOW_DECLINE_OVERRIDE", True)

    # Background scheduler (top-1000 nightly sweep; web process only)
    enable_scheduler: bool = _parse_bool_env("ARGUSS_ENABLE_SCHEDULER", True)
    top_1000_sweep_cron_hour: int = int(os.environ.get("ARGUSS_TOP_1000_SWEEP_CRON_HOUR", "3"))


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
