"""Logging filters that redact secrets before records are emitted."""

from __future__ import annotations

import logging
import re

_GITHUB_PAT_PATTERN = re.compile(
    r"\b(ghp_|github_pat_|ghs_|ghu_|gho_|ghr_)[A-Za-z0-9_]{16,}\b",
)
_GENERIC_BEARER_PATTERN = re.compile(
    r"(Bearer\s+|token\s+|authorization:\s*)[A-Za-z0-9_\-\.~+/=]{20,}",
    re.IGNORECASE,
)
_ANTHROPIC_KEY_PATTERN = re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")

_REDACTED_PAT = "<REDACTED_PAT>"


class SecretFilter(logging.Filter):
    """Redact PAT-like tokens from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._scrub(str(record.msg))
        if record.args:
            record.args = tuple(
                self._scrub(arg) if isinstance(arg, str) else arg for arg in record.args
            )
        skip_keys = frozenset(
            {
                "name",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
                "msg",
                "args",
                "exc_info",
                "exc_text",
                "stack_info",
                "taskName",
            }
        )
        for key, value in list(record.__dict__.items()):
            if key in skip_keys:
                continue
            if isinstance(value, str):
                record.__dict__[key] = self._scrub(value)
        return True

    @staticmethod
    def _scrub(text: str) -> str:
        s = _GITHUB_PAT_PATTERN.sub(_REDACTED_PAT, text)
        s = _ANTHROPIC_KEY_PATTERN.sub(_REDACTED_PAT, s)
        s = _GENERIC_BEARER_PATTERN.sub(r"\1<REDACTED>", s)
        return s
