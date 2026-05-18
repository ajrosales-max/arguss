"""Subprocess wrapper around the zizmor CLI for GitHub Actions workflow analysis.

zizmor is distributed as a Rust binary (the ``zizmor`` PyPI package installs that
binary on PATH). Arguss does **not** import zizmor as a Python library; the only
IPC is ``subprocess.run`` with ``--no-exit-codes --format json``.

**Timeout:** ``ZIZMOR_DEFAULT_TIMEOUT_SECONDS`` (30s). On expiry,
:class:`ZizmorClientError` is raised with a clear message; the subprocess is
terminated by the stdlib timeout handler.

**Exit codes:** we pass ``--no-exit-codes`` to zizmor so it always returns ``0`` on
successful execution. Findings are detected purely from the JSON output (an empty
array means no findings). Any non-zero exit code indicates a tool failure and
raises :class:`ZizmorClientError` (stderr is included in the error).

**Severity / confidence:** zizmor 1.25.2 nests title-case strings under
``determinations`` (e.g. ``"High"``, ``"Medium"``). We map them to lowercase
literals on :class:`~arguss.core.models.ZizmorFinding` via
``_ZIZMOR_SEVERITY_MAP`` and ``_ZIZMOR_CONFIDENCE_MAP``. Unknown values log a
warning and default to ``medium`` / ``unknown``.

**Locations:** Prefer the first location whose ``symbolic.kind`` is
``"Primary"``; if none, use the first location in the array. Row/column in JSON
are 0-indexed; the model stores 1-indexed values for human display.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from arguss.core.models import ZizmorConfidence, ZizmorFinding, ZizmorSeverity

_LOG = logging.getLogger(__name__)

ZIZMOR_DEFAULT_TIMEOUT_SECONDS = 30

_ZIZMOR_SEVERITY_MAP: dict[str, ZizmorSeverity] = {
    "Informational": "informational",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
}

_ZIZMOR_CONFIDENCE_MAP: dict[str, ZizmorConfidence] = {
    "Low": "low",
    "Medium": "medium",
    "High": "high",
    "Unknown": "unknown",
}


class ZizmorClientError(Exception):
    """Raised when the zizmor subprocess fails in an unrecoverable way."""


def _normalize_severity(raw: str, ident: str) -> ZizmorSeverity:
    mapped = _ZIZMOR_SEVERITY_MAP.get(raw)
    if mapped is not None:
        return mapped
    _LOG.warning("zizmor: unknown severity %r for %s; defaulting to medium", raw, ident)
    return "medium"


def _normalize_confidence(raw: str, ident: str) -> ZizmorConfidence:
    mapped = _ZIZMOR_CONFIDENCE_MAP.get(raw)
    if mapped is not None:
        return mapped
    _LOG.warning("zizmor: unknown confidence %r for %s; defaulting to unknown", raw, ident)
    return "unknown"


def _pick_location(locations: list[Any]) -> dict[str, Any] | None:
    if not locations:
        return None
    for loc in locations:
        if not isinstance(loc, dict):
            continue
        symbolic = loc.get("symbolic")
        if isinstance(symbolic, dict) and symbolic.get("kind") == "Primary":
            return loc
    first = locations[0]
    return first if isinstance(first, dict) else None


def _extract_file_path(symbolic: dict[str, Any]) -> str | None:
    key = symbolic.get("key")
    if not isinstance(key, dict):
        return None
    local = key.get("Local")
    if not isinstance(local, dict):
        return None
    given = local.get("given_path")
    if isinstance(given, str) and given:
        return Path(given).name
    return None


def _parse_zizmor_output(stdout: str) -> list[ZizmorFinding]:
    """Parse zizmor JSON stdout (top-level array) into normalized findings."""
    try:
        parsed: Any = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise ZizmorClientError(f"zizmor returned invalid JSON: {e}") from e

    if not isinstance(parsed, list):
        raise ZizmorClientError(f"zizmor JSON root must be a list, got {type(parsed).__name__}")

    out: list[ZizmorFinding] = []
    for item in parsed:
        if not isinstance(item, dict):
            _LOG.warning("zizmor: skipping non-object finding entry")
            continue

        if item.get("ignored") is True:
            continue

        ident = item.get("ident")
        desc = item.get("desc")
        url = item.get("url")
        if not isinstance(ident, str) or not isinstance(desc, str) or not isinstance(url, str):
            _LOG.warning("zizmor: skipping finding with missing ident/desc/url")
            continue

        determinations = item.get("determinations")
        if not isinstance(determinations, dict):
            _LOG.warning("zizmor: skipping %s — missing determinations", ident)
            continue

        raw_sev = determinations.get("severity")
        raw_conf = determinations.get("confidence")
        if not isinstance(raw_sev, str) or not isinstance(raw_conf, str):
            _LOG.warning("zizmor: skipping %s — missing severity/confidence", ident)
            continue

        severity = _normalize_severity(raw_sev, ident)
        confidence = _normalize_confidence(raw_conf, ident)

        locations_raw = item.get("locations")
        if not isinstance(locations_raw, list):
            _LOG.warning("zizmor: skipping %s — no locations array", ident)
            continue

        loc = _pick_location(locations_raw)
        if loc is None:
            _LOG.warning("zizmor: skipping %s — no usable location", ident)
            continue

        symbolic = loc.get("symbolic")
        concrete = loc.get("concrete")
        if not isinstance(symbolic, dict) or not isinstance(concrete, dict):
            _LOG.warning("zizmor: skipping %s — malformed location", ident)
            continue

        file_name = _extract_file_path(symbolic)
        if not file_name:
            _LOG.warning("zizmor: skipping %s — could not resolve file path", ident)
            continue

        annotation = symbolic.get("annotation")
        if not isinstance(annotation, str):
            annotation = ""

        feature = concrete.get("feature")
        if not isinstance(feature, str):
            feature = ""

        location = concrete.get("location")
        if not isinstance(location, dict):
            _LOG.warning("zizmor: skipping %s — missing concrete.location", ident)
            continue

        start = location.get("start_point")
        if not isinstance(start, dict):
            _LOG.warning("zizmor: skipping %s — missing start_point", ident)
            continue

        row = start.get("row")
        column = start.get("column")
        if not isinstance(row, int) or not isinstance(column, int):
            _LOG.warning("zizmor: skipping %s — invalid row/column", ident)
            continue

        out.append(
            ZizmorFinding(
                ident=ident,
                severity=severity,
                confidence=confidence,
                description=desc,
                file=file_name,
                line=row + 1,
                column=column + 1,
                feature=feature,
                annotation=annotation,
                audit_url=url,
            )
        )

    return out


class ZizmorClient:
    """Subprocess wrapper around the zizmor CLI."""

    def __init__(
        self,
        binary: str | None = None,
        timeout_seconds: int = ZIZMOR_DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        resolved = binary or shutil.which("zizmor")
        if not resolved:
            raise ZizmorClientError(
                "zizmor not found on PATH; install with `uv add zizmor` or set binary="
            )
        self._binary = resolved
        self._timeout = timeout_seconds

    def version(self) -> str:
        """Return zizmor's version string."""
        try:
            result = subprocess.run(
                [self._binary, "--version"],
                capture_output=True,
                text=True,
                timeout=min(self._timeout, 10),
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise ZizmorClientError("zizmor --version timed out") from e

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            raise ZizmorClientError(f"zizmor --version failed (exit {result.returncode}): {err}")

        return (result.stdout or result.stderr or "").strip().splitlines()[0].strip()

    def scan_workflows(self, workflows_dir: Path) -> list[ZizmorFinding]:
        """Run zizmor against a workflows directory or a single workflow file."""
        path = workflows_dir.resolve()
        if not path.exists():
            return []

        if path.is_dir():
            yaml_files = [*path.glob("*.yml"), *path.glob("*.yaml")]
            if not yaml_files:
                return []
        elif path.suffix not in (".yml", ".yaml"):
            return []

        cmd = [self._binary, "--no-exit-codes", "--format", "json", str(path)]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise ZizmorClientError(
                f"zizmor timed out after {self._timeout}s scanning {path}"
            ) from e

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout_snip = (result.stdout or "")[:500].strip()
            raise ZizmorClientError(
                f"zizmor exited {result.returncode} scanning {path}: "
                f"stderr={stderr!r} stdout={stdout_snip!r}"
            )

        stdout = result.stdout or ""
        if not stdout.strip():
            return []

        return _parse_zizmor_output(stdout)
