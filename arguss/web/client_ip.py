"""Trusted client-IP extraction for rate limiting.

Behind Fly.io (no other CDN/proxy in front), Fly Proxy sets the
``Fly-Client-IP`` header to the address it accepted the connection from,
overwriting any client-supplied value — that makes it the trusted source.

``X-Forwarded-For`` is deliberately NOT consulted: its leftmost entries are
client-controlled and trivially spoofable, so using it for rate limiting
would let an attacker rotate identities per request.
"""

from __future__ import annotations

from starlette.requests import Request

FLY_CLIENT_IP_HEADER = "Fly-Client-IP"

_UNKNOWN_CLIENT = "unknown"


def client_ip(request: Request) -> str:
    """Return the trusted client IP for this request.

    Prefers ``Fly-Client-IP`` (set by Fly Proxy in production). Falls back to
    the direct socket peer (``request.client.host``) for local/dev where no
    proxy is in front. Never reads ``X-Forwarded-For``.
    """
    header_value = request.headers.get(FLY_CLIENT_IP_HEADER, "").strip()
    if header_value:
        return header_value
    if request.client is not None and request.client.host:
        return request.client.host
    return _UNKNOWN_CLIENT
