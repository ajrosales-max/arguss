"""In-memory scan-frequency limits (per-IP hourly + per-wizard-session).

These are short-window/rolling counts where loss on process restart is
acceptable, so they live in memory (single uvicorn process on one Fly
machine). Only the Anthropic daily ceiling needs durable SQLite storage.

Per-IP counts key off client_ip() (Fly-Client-IP, trusted). Per-session
counts key off the arguss_wizard_session cookie — NOT arguss_session, which
is OAuth-only. Requests that carry a wizard session are subject to BOTH
limits; pre-wizard scans (JSON API, first browser scan) only have the IP
lever because the wizard cookie does not exist yet.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass

from fastapi import HTTPException, status
from starlette.requests import Request

from arguss.settings import settings
from arguss.web.client_ip import client_ip
from arguss.web.wizard_session import WIZARD_SESSION_COOKIE

IP_WINDOW_SECONDS = 3600

SCAN_IP_LIMIT_DETAIL = (
    "Scan rate limit reached for your network address. Please wait before scanning again."
)
SCAN_SESSION_LIMIT_DETAIL = (
    "Scan limit reached for this session. Please wait before running more scans."
)


@dataclass(frozen=True)
class ScanRateLimitDenial:
    scope: str  # "ip" | "session"
    retry_after_seconds: int
    detail: str


class _ScanRateLimitState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ip_events: dict[str, deque[float]] = {}
        self._session_counts: dict[str, int] = {}

    def check_and_count(
        self,
        *,
        ip: str,
        session_token: str | None,
        ip_limit: int,
        session_limit: int,
        now: float | None = None,
    ) -> ScanRateLimitDenial | None:
        """Atomically check both limits; count against both only when allowed.

        A denied request consumes no budget on either counter.
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            if ip_limit <= 0:
                return ScanRateLimitDenial("ip", IP_WINDOW_SECONDS, SCAN_IP_LIMIT_DETAIL)
            events = self._ip_events.setdefault(ip, deque())
            cutoff = now - IP_WINDOW_SECONDS
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= ip_limit:
                retry_after = max(1, int(events[0] + IP_WINDOW_SECONDS - now) + 1)
                return ScanRateLimitDenial("ip", retry_after, SCAN_IP_LIMIT_DETAIL)
            if session_token is not None and (
                session_limit <= 0 or self._session_counts.get(session_token, 0) >= session_limit
            ):
                return ScanRateLimitDenial(
                    "session",
                    IP_WINDOW_SECONDS,
                    SCAN_SESSION_LIMIT_DETAIL,
                )
            events.append(now)
            if session_token is not None:
                self._session_counts[session_token] = self._session_counts.get(session_token, 0) + 1
            return None


_state = _ScanRateLimitState()


def check_scan_rate_limit(request: Request) -> ScanRateLimitDenial | None:
    """Check-and-count one scan trigger for this request.

    Returns None when the scan may proceed (budget consumed), or a denial
    describing which limit was hit. No-op when the kill switch is off.
    """
    if not settings.rate_limit_enabled:
        return None
    session_token = request.cookies.get(WIZARD_SESSION_COOKIE) or None
    return _state.check_and_count(
        ip=client_ip(request),
        session_token=session_token,
        ip_limit=settings.rate_limit_scans_per_ip_per_hour,
        session_limit=settings.rate_limit_scans_per_session,
    )


def scan_rate_limit_http_exception(denial: ScanRateLimitDenial) -> HTTPException:
    """429 with Retry-After for the JSON API endpoints."""
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=denial.detail,
        headers={"Retry-After": str(denial.retry_after_seconds)},
    )


def reset_scan_rate_limit_state() -> None:
    """Drop all in-memory counters (test isolation)."""
    global _state
    _state = _ScanRateLimitState()
