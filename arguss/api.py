"""FastAPI application entry point.

WEEK 1: Minimal hello-world for deployment verification.
WEEK 7: Real dashboard with HTMX + Tailwind lands here.
"""

from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from arguss.settings import settings
from arguss.web.routes import router as scan_router

app = FastAPI(
    title="Arguss",
    description="Secure CI/CD & Software Supply Chain Risk Analyzer",
    version="0.1.0",
)

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
