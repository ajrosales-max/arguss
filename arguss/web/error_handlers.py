"""Global HTTP error handlers for HTML vs JSON responses."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

_API_PATH_PREFIXES = (
    "/scan/url",
    "/scan/upload",
    "/scan/with-action",
    "/dashboard/scan-with-action/start",
)


def is_api_request(request: Request) -> bool:
    """Return True when the client expects a JSON API response, not HTML."""
    path = request.url.path
    if path == "/health":
        return True
    if any(path == prefix or path.startswith(prefix + "/") for prefix in _API_PATH_PREFIXES):
        return True
    accept = (request.headers.get("accept") or "").lower()
    return "application/json" in accept and "text/html" not in accept


def register_error_handlers(app: FastAPI, templates: Jinja2Templates) -> None:
    """Register app-wide handlers (404 HTML for browser navigation)."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request,
        exc: StarletteHTTPException,
    ) -> Response:
        if exc.status_code == 404 and not is_api_request(request):
            return templates.TemplateResponse(
                request,
                "not_found.html",
                {"path": request.url.path},
                status_code=404,
            )
        headers = dict(exc.headers) if exc.headers else None
        return JSONResponse(
            {"detail": exc.detail},
            status_code=exc.status_code,
            headers=headers,
        )
