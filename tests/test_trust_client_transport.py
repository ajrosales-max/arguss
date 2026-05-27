"""Trust client maps httpx transport errors to TrustClientError."""

from __future__ import annotations

from unittest import mock

import httpx
import pytest

from arguss.lenses._trust_client import TrustClientError, _request_with_retries


def test_connect_timeout_raises_trust_client_error() -> None:
    client = mock.MagicMock()
    client.request.side_effect = httpx.ConnectTimeout("handshake timed out")

    with pytest.raises(TrustClientError, match="network error"):
        _request_with_retries(
            client,
            "GET",
            "https://api.npmjs.org/downloads/point/last-week/lodash",
            timeout=httpx.Timeout(5.0),
            context="downloads",
            package="lodash",
        )
