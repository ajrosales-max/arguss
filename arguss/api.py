"""FastAPI application entry point."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles

from arguss.jobs.top_1000_sweep import run_sweep
from arguss.logging_config import configure_logging
from arguss.settings import settings
from arguss.web.auth import require_demo_auth
from arguss.web.dashboard import router as dashboard_router
from arguss.web.dashboard import templates
from arguss.web.error_handlers import register_error_handlers
from arguss.web.routes import router as scan_router

_STATIC_DIR = Path(__file__).parent / "web" / "static"


@asynccontextmanager
async def _app_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start background jobs on startup and tear them down on shutdown."""
    scheduler = None
    if settings.enable_scheduler:
        from apscheduler.schedulers.background import BackgroundScheduler

        # Assumes a single worker process; multiple workers would each start a scheduler.
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            run_sweep,
            "cron",
            hour=settings.top_1000_sweep_cron_hour,
            args=[settings.db_path],
            kwargs={"latest": True},
            id="top_1000_sweep",
        )
        scheduler.start()
    app.state.scheduler = scheduler

    try:
        yield
    finally:
        if scheduler is not None:
            scheduler.shutdown(wait=False)
        app.state.scheduler = None


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
        lifespan=_app_lifespan,
    )

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    app.include_router(dashboard_router, dependencies=[Depends(require_demo_auth)])
    app.include_router(scan_router, dependencies=[Depends(require_demo_auth)])

    register_error_handlers(app, templates)

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
