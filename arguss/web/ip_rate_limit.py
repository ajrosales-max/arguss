"""In-memory per-IP per-minute request-rate backstop.

A coarse abuse layer, independent of the scan-frequency limits and the
Anthropic daily ceiling. Loss on process restart is acceptable; only the
Anthropic counter needs durable SQLite storage.

Keyed by client_ip() (Fly-Client-IP when present). Old timestamps are pruned
on every check so the per-IP deques stay bounded.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from arguss.settings import settings
from arguss.web.client_ip import client_ip

IP_WINDOW_SECONDS = 60

IP_REQUEST_LIMIT_DETAIL = (
    "Request rate limit reached for your network address. Please wait before trying again."
)

_SSE_STREAM_PREFIXES = (
    "/scan/with-action/stream/",
    "/dashboard/scan-with-action/stream/",
)


@dataclass(frozen=True)
class IpRateLimitDenial:
    retry_after_seconds: int
    detail: str = IP_REQUEST_LIMIT_DETAIL


def is_ip_rate_limit_exempt(path: str) -> bool:
    """Paths that must never consume or hit the per-minute IP backstop."""
    if path == "/health":
        return True
    if path == "/static" or path.startswith("/static/"):
        return True
    if path == "/github/callback":
        return True
    return any(path.startswith(prefix) for prefix in _SSE_STREAM_PREFIXES)


class _IpRateLimitState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ip_events: dict[str, deque[float]] = {}

    def tracked_ip_count(self) -> int:
        with self._lock:
            return len(self._ip_events)

    def check_and_count(
        self,
        *,
        ip: str,
        limit: int,
        now: float | None = None,
    ) -> IpRateLimitDenial | None:
        """Atomically prune, check, and (if allowed) record one request.

        A denied request consumes no budget. Empty IP deques are dropped so
        the map stays bounded as windows slide.
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            if limit <= 0:
                return IpRateLimitDenial(IP_WINDOW_SECONDS)

            cutoff = now - IP_WINDOW_SECONDS
            # Drop fully-expired IPs so the map cannot grow without bound.
            stale = [
                key for key, events in self._ip_events.items() if not events or events[-1] <= cutoff
            ]
            for key in stale:
                del self._ip_events[key]

            events = self._ip_events.setdefault(ip, deque())
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(events[0] + IP_WINDOW_SECONDS - now) + 1)
                return IpRateLimitDenial(retry_after)
            events.append(now)
            return None


_state = _IpRateLimitState()


def check_ip_rate_limit(request: Request) -> IpRateLimitDenial | None:
    """Check-and-count one request against the per-minute IP backstop.

    Returns None when the request may proceed, or a denial. No-op when the
    kill switch is off or the path is exempt.
    """
    if not settings.rate_limit_enabled:
        return None
    if is_ip_rate_limit_exempt(request.url.path):
        return None
    return _state.check_and_count(
        ip=client_ip(request),
        limit=settings.rate_limit_ip_per_minute,
    )


def reset_ip_rate_limit_state() -> None:
    """Drop all in-memory counters (test isolation)."""
    global _state
    _state = _IpRateLimitState()


class IpRateLimitMiddleware(BaseHTTPMiddleware):
    """ASGI middleware enforcing the general per-IP per-minute backstop.

    Runs before route handlers, so a backstop denial never reaches the
    scan-frequency limiter (Step 3). Scan requests that pass still count
    against both layers — intentional.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        html_response_factory: Callable[[Request, IpRateLimitDenial], Response] | None = None,
    ) -> None:
        super().__init__(app)
        self._html_response_factory = html_response_factory

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        denial = check_ip_rate_limit(request)
        if denial is None:
            return await call_next(request)

        headers = {"Retry-After": str(denial.retry_after_seconds)}
        from arguss.web.error_handlers import is_api_request

        if is_api_request(request) or self._html_response_factory is None:
            return JSONResponse(
                {"detail": denial.detail},
                status_code=429,
                headers=headers,
            )
        return self._html_response_factory(request, denial)
