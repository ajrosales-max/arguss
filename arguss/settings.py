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
