"""Apply a single fix candidate to a package-lock.json.

v1 supports direct dependencies and simple top-level ``node_modules/{package}``
entries. Complex nested transitive layouts return ``None`` — the caller treats
that as ``skipped`` rather than producing an inaccurate diff.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from arguss.core.models import FixCandidate

_LOG = logging.getLogger(__name__)

_LOCKFILE_VERSION = 3
_PACKAGE_KEY_PREFIX = "node_modules/"


class LockfileModificationError(Exception):
    """The lockfile could not be parsed or is not a supported lockfile v3."""


def _reject(message: str) -> None:
    raise LockfileModificationError(message)


def _package_lockfile_key(package: str) -> str:
    return f"{_PACKAGE_KEY_PREFIX}{package}"


def _update_resolved_url(resolved: str, from_version: str, to_version: str) -> str:
    """Rewrite an npm ``resolved`` tarball URL for the target version."""
    if from_version not in resolved:
        _reject(f"resolved URL does not contain from_version {from_version!r}: {resolved!r}")
    return resolved.replace(from_version, to_version, 1)


def _find_simple_package_key(packages: dict[str, Any], package: str) -> str | None:
    """Return the sole matching packages key, or None if the layout is not simple."""
    target = _package_lockfile_key(package)
    if target not in packages:
        return None

    nested_prefix = f"{target}/"
    for key in packages:
        if key.startswith(nested_prefix):
            _LOG.warning(
                "lockfile fix skipped for %s: nested entry %s",
                package,
                key,
            )
            return None

    duplicate_keys = [
        key
        for key in packages
        if key != target and key.endswith(f"/{package}") and not key.endswith("/")
    ]
    if duplicate_keys:
        _LOG.warning(
            "lockfile fix skipped for %s: multiple entries (%s)",
            package,
            ", ".join(sorted({target, *duplicate_keys})),
        )
        return None

    return target


def apply_fix_to_lockfile(
    lockfile_bytes: bytes,
    candidate: FixCandidate,
) -> bytes | None:
    """Apply a single fix candidate to a lockfile.

    Returns the modified lockfile bytes, or ``None`` if the modifier cannot
    cleanly apply this candidate (complex layout, version mismatch, etc.).

    Raises ``LockfileModificationError`` only for malformed or unsupported
    lockfiles.
    """
    try:
        data = json.loads(lockfile_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockfileModificationError("lockfile is not valid JSON") from exc

    if not isinstance(data, dict):
        _reject("lockfile root must be a JSON object")

    if data.get("lockfileVersion") != _LOCKFILE_VERSION:
        _reject(
            f"lockfile version {data.get('lockfileVersion')!r} is not supported "
            f"(expected {_LOCKFILE_VERSION})",
        )

    packages = data.get("packages")
    if not isinstance(packages, dict):
        _reject("lockfile packages field must be an object")

    package_key = _find_simple_package_key(packages, candidate.package)
    if package_key is None:
        _LOG.warning(
            "lockfile fix skipped for %s: no simple node_modules entry",
            candidate.package,
        )
        return None

    entry = packages.get(package_key)
    if not isinstance(entry, dict):
        _LOG.warning(
            "lockfile fix skipped for %s: packages[%s] is not an object",
            candidate.package,
            package_key,
        )
        return None

    if entry.get("version") != candidate.from_version:
        _LOG.warning(
            "lockfile fix skipped for %s: expected version %s, found %s",
            candidate.package,
            candidate.from_version,
            entry.get("version"),
        )
        return None

    resolved = entry.get("resolved")
    if isinstance(resolved, str):
        if not re.search(re.escape(candidate.from_version), resolved):
            _LOG.warning(
                "lockfile fix skipped for %s: resolved URL does not reference from_version",
                candidate.package,
            )
            return None
        try:
            entry["resolved"] = _update_resolved_url(
                resolved,
                candidate.from_version,
                candidate.to_version,
            )
        except LockfileModificationError:
            _LOG.warning(
                "lockfile fix skipped for %s: could not update resolved URL",
                candidate.package,
            )
            return None
    elif resolved is not None:
        _LOG.warning(
            "lockfile fix skipped for %s: unexpected resolved field type",
            candidate.package,
        )
        return None

    entry["version"] = candidate.to_version
    entry.pop("integrity", None)

    root = packages.get("")
    if isinstance(root, dict):
        root_deps = root.get("dependencies")
        if isinstance(root_deps, dict) and candidate.package in root_deps:
            pinned = root_deps[candidate.package]
            if pinned == candidate.from_version:
                root_deps[candidate.package] = candidate.to_version

    encoded = json.dumps(data, indent=2) + "\n"
    return encoded.encode("utf-8")
