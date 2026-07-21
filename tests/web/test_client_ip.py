"""Trusted client-IP extraction (Fly-Client-IP; never X-Forwarded-For)."""

from __future__ import annotations

from starlette.requests import Request

from arguss.web.client_ip import client_ip


def _request(
    headers: dict[str, str] | None = None,
    client_host: str | None = "127.0.0.1",
) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (name.lower().encode("latin-1"), value.encode("latin-1"))
            for name, value in (headers or {}).items()
        ],
        "client": (client_host, 51234) if client_host is not None else None,
    }
    return Request(scope)


def test_returns_fly_client_ip_when_present() -> None:
    request = _request({"Fly-Client-IP": "203.0.113.7"})
    assert client_ip(request) == "203.0.113.7"


def test_falls_back_to_socket_peer_without_fly_header() -> None:
    request = _request(client_host="192.0.2.10")
    assert client_ip(request) == "192.0.2.10"


def test_ignores_spoofed_x_forwarded_for() -> None:
    request = _request(
        {"X-Forwarded-For": "6.6.6.6, 7.7.7.7"},
        client_host="192.0.2.10",
    )
    assert client_ip(request) == "192.0.2.10"


def test_fly_header_wins_over_x_forwarded_for() -> None:
    request = _request(
        {
            "Fly-Client-IP": "203.0.113.7",
            "X-Forwarded-For": "6.6.6.6",
        },
        client_host="192.0.2.10",
    )
    assert client_ip(request) == "203.0.113.7"


def test_blank_fly_header_falls_back() -> None:
    request = _request({"Fly-Client-IP": "   "}, client_host="192.0.2.10")
    assert client_ip(request) == "192.0.2.10"


def test_unknown_when_no_header_and_no_peer() -> None:
    request = _request(client_host=None)
    assert client_ip(request) == "unknown"
