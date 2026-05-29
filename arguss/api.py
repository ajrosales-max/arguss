"""FastAPI application entry point."""

from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles

from arguss.logging_config import configure_logging
from arguss.settings import settings
from arguss.web.auth import require_demo_auth
from arguss.web.dashboard import router as dashboard_router
from arguss.web.routes import router as scan_router

_STATIC_DIR = Path(__file__).parent / "web" / "static"


def create_app() -> FastAPI:
    """Build the FastAPI app (reads settings at call time for docs/auth wiring)."""
    configure_logging(settings.log_level)
    auth_on = bool(settings.demo_password)
    app = FastAPI(
        title="Arguss",
        description="Secure CI/CD & Software Supply Chain Risk Analyzer",
        version="0.1.0",
        docs_url=None if auth_on else "/docs",
        redoc_url=None if auth_on else "/redoc",
        openapi_url=None if auth_on else "/openapi.json",
    )

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    app.include_router(dashboard_router, dependencies=[Depends(require_demo_auth)])
    app.include_router(scan_router, dependencies=[Depends(require_demo_auth)])

    @app.get("/health")
    def health() -> dict[str, str]:
        """Health check endpoint for Fly.io monitoring."""
        return {
            "status": "ok",
            "service": "arguss",
            "timestamp": datetime.now(UTC).isoformat(),
            "environment": "production" if settings.is_production else "development",
        }

    return app


app = create_app()
