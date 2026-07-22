"""ARGUSS_REQUIRE_AUTH fail-closed parsing (auth flag must never open on typo)."""

from __future__ import annotations

import pytest

from arguss.settings import Settings, _parse_require_auth_env


def test_require_auth_unset_is_locked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUSS_REQUIRE_AUTH", raising=False)
    assert _parse_require_auth_env() is True


def test_require_auth_empty_is_locked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUSS_REQUIRE_AUTH", "")
    assert _parse_require_auth_env() is True
    monkeypatch.setenv("ARGUSS_REQUIRE_AUTH", "   ")
    assert _parse_require_auth_env() is True


@pytest.mark.parametrize("value", ["false", "False", "FALSE", "0", "no", "No", "off", "OFF"])
def test_require_auth_explicit_false_opens(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("ARGUSS_REQUIRE_AUTH", value)
    assert _parse_require_auth_env() is False


@pytest.mark.parametrize("value", ["true", "True", "1", "yes", "on"])
def test_require_auth_truthy_stays_locked(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("ARGUSS_REQUIRE_AUTH", value)
    assert _parse_require_auth_env() is True


@pytest.mark.parametrize("value", ["ture", "maybe", "yesplease", "enabled", "2", "null"])
def test_require_auth_garbage_stays_locked(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """Unrecognized values must lock — never fail open like _parse_bool_env."""
    monkeypatch.setenv("ARGUSS_REQUIRE_AUTH", value)
    assert _parse_require_auth_env() is True


def test_settings_exposes_require_auth_attribute() -> None:
    assert isinstance(Settings.require_auth, bool)
