"""Operator kill switch for the fix-confidence engine."""

from __future__ import annotations

import os
from pathlib import Path

_ENV_KILL_SWITCH = "ARGUSS_KILL_SWITCH"
_ENV_KILL_SWITCH_FILE_PATH = "ARGUSS_KILL_SWITCH_FILE_PATH"
_DEFAULT_KILL_SWITCH_FILE = "/tmp/arguss_kill_switch"

_ACTIVE_ENV_VALUES = frozenset({"1", "true", "yes"})


def _env_kill_switch_active() -> bool:
    raw = os.environ.get(_ENV_KILL_SWITCH)
    if raw is None:
        return False
    return raw.strip().lower() in _ACTIVE_ENV_VALUES


def _file_kill_switch_active() -> bool:
    path_str = os.environ.get(_ENV_KILL_SWITCH_FILE_PATH, _DEFAULT_KILL_SWITCH_FILE)
    try:
        return Path(path_str).exists()
    except OSError:
        return False


def is_kill_switch_active() -> bool:
    """Check if the engine is administratively disabled.

    Two ways to activate the kill switch:
    1. Environment variable ARGUSS_KILL_SWITCH set to '1', 'true', 'yes' (case-insensitive)
    2. A file exists at ARGUSS_KILL_SWITCH_FILE_PATH (default: /tmp/arguss_kill_switch)

    When the kill switch is active, compute_fix_confidence returns DECLINE for
    every candidate with veto_signal 'kill_switch' and reason 'engine
    administratively disabled via kill switch'.

    Returns True if active, False otherwise. Never raises.
    """
    return _env_kill_switch_active() or _file_kill_switch_active()
