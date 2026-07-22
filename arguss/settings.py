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


def _parse_require_auth_env(key: str = "ARGUSS_REQUIRE_AUTH") -> bool:
    """Parse ARGUSS_REQUIRE_AUTH with fail-closed (locked) semantics.

    Unlike ``_parse_bool_env``, unrecognized values never open the surface:

    - unset / empty → True (auth required)
    - explicit false allowlist (false / 0 / no / off) → False (open)
    - anything else (true, typos, garbage) → True (auth required)
    """
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return True
    token = raw.strip().lower()
    # False only for the explicit open allowlist; everything else stays locked.
    return token not in ("false", "0", "no", "off")


def _parse_int_env(key: str, default: int) -> int:
    """Parse a non-negative integer env var, falling back to the default.

    Fail-safe: a missing, empty, malformed, or negative value yields the
    conservative default — never an unlimited/disabled state.
    """
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        return default
    if value < 0:
        return default
    return value


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

    # GitHub App credentials (Mode C App auth primitives; unset = App path disabled)
    _github_app_id_raw: str = os.environ.get("ARGUSS_GITHUB_APP_ID", "")
    github_app_id: str | None = _github_app_id_raw if _github_app_id_raw else None
    """GitHub App ID. Optional; absence does not affect boot or the PAT path."""

    _github_app_private_key_b64_raw: str = os.environ.get("ARGUSS_GITHUB_APP_PRIVATE_KEY_B64", "")
    github_app_private_key_b64: str | None = (
        _github_app_private_key_b64_raw if _github_app_private_key_b64_raw else None
    )
    """Base64-encoded PEM private key for the GitHub App. Decoded lazily on use."""

    # GitHub App OAuth (install+authorize flow; unset = install routes fail on use)
    _github_app_client_id_raw: str = os.environ.get("ARGUSS_GITHUB_APP_CLIENT_ID", "")
    github_app_client_id: str | None = (
        _github_app_client_id_raw if _github_app_client_id_raw else None
    )
    """OAuth client ID for the GitHub App. Optional; absence does not affect boot."""

    _github_app_client_secret_raw: str = os.environ.get("ARGUSS_GITHUB_APP_CLIENT_SECRET", "")
    github_app_client_secret: str | None = (
        _github_app_client_secret_raw if _github_app_client_secret_raw else None
    )
    """OAuth client secret for the GitHub App. Optional; absence does not affect boot."""

    _github_app_slug_raw: str = os.environ.get("ARGUSS_GITHUB_APP_SLUG", "")
    github_app_slug: str | None = _github_app_slug_raw if _github_app_slug_raw else None
    """GitHub App slug used in install URLs (github.com/apps/{slug}/...)."""

    _session_secret_raw: str = os.environ.get("ARGUSS_SESSION_SECRET", "")
    session_secret: str | None = _session_secret_raw if _session_secret_raw else None
    """Secret for signing the Starlette session cookie. Optional; middleware skipped if unset."""

    # HTTP Basic Auth for the read/dashboard surface. require_auth is the
    # single on/off switch (default locked). demo_password is the credential
    # only — its presence no longer decides whether auth is enforced.
    require_auth: bool = _parse_require_auth_env()
    """When True, dashboard/scan routers require Basic auth. Unset = locked."""

    demo_username: str = os.environ.get("ARGUSS_DEMO_USERNAME", "demo")
    _demo_password_raw: str = os.environ.get("ARGUSS_DEMO_PASSWORD", "")
    demo_password: str | None = _demo_password_raw if _demo_password_raw else None

    # Wizard: allow users to override DECLINE-tier candidates on /select (default on for demo)
    allow_decline_override: bool = _parse_bool_env("ARGUSS_ALLOW_DECLINE_OVERRIDE", True)

    # Background scheduler (top-1000 nightly sweep; web process only)
    enable_scheduler: bool = _parse_bool_env("ARGUSS_ENABLE_SCHEDULER", True)
    top_1000_sweep_cron_hour: int = int(os.environ.get("ARGUSS_TOP_1000_SWEEP_CRON_HOUR", "3"))

    # Ingress rate limiting. Fail-safe: missing/invalid values fall back to
    # the conservative defaults below, never to unlimited. Unset kill switch
    # means ENABLED (the safe state is protected).
    rate_limit_enabled: bool = _parse_bool_env("ARGUSS_RATE_LIMIT_ENABLED", True)
    """Master kill switch for ingress rate limiting. Default on."""

    rate_limit_ip_per_minute: int = _parse_int_env("ARGUSS_RATE_LIMIT_IP_PER_MINUTE", 60)
    """Per-IP request-rate backstop (requests per minute)."""

    rate_limit_scans_per_session: int = _parse_int_env("ARGUSS_RATE_LIMIT_SCANS_PER_SESSION", 10)
    """Max scans per wizard session."""

    rate_limit_scans_per_ip_per_hour: int = _parse_int_env(
        "ARGUSS_RATE_LIMIT_SCANS_PER_IP_PER_HOUR", 20
    )
    """Max scan-triggering requests per client IP per hour."""

    anthropic_daily_ceiling: int = _parse_int_env("ARGUSS_ANTHROPIC_DAILY_CEILING", 200)
    """Global Anthropic CALL-COUNT ceiling per UTC day (durable in SQLite).
    Not a token/dollar cap; each call_claude invocation counts as one."""


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


_WEB_AUTH_BOOT_ERROR = (
    "ARGUSS_REQUIRE_AUTH is enabled but ARGUSS_DEMO_PASSWORD is unset "
    "— set a password or set ARGUSS_REQUIRE_AUTH=false"
)


def validate_web_auth_settings() -> None:
    """Fail fast on web boot when auth is required without a credential.

    Called from ``create_app`` only (not CLI). Locked-with-no-password would
    401 every request with no operable way in — refuse to start instead.
    """
    if settings.require_auth and not settings.demo_password:
        sys.exit(_WEB_AUTH_BOOT_ERROR)
