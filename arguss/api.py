"""FastAPI application entry point."""

from datetime import UTC, datetime

from fastapi import FastAPI

from arguss.settings import settings
from arguss.web.dashboard import router as dashboard_router
from arguss.web.routes import router as scan_router

app = FastAPI(
    title="Arguss",
    description="Secure CI/CD & Software Supply Chain Risk Analyzer",
    version="0.1.0",
)

app.include_router(dashboard_router)
app.include_router(scan_router)


@app.get("/health")
def health() -> dict[str, str]:
    """Health check endpoint for Fly.io monitoring."""
    return {
        "status": "ok",
        "service": "arguss",
        "timestamp": datetime.now(UTC).isoformat(),
        "environment": "production" if settings.is_production else "development",
    }
