"""Apply a single fix candidate to package.json and/or package-lock.json.

Direct dependencies update both manifests; transitive dependencies update
lockfile entries only (npm honors lockfile pins on install).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from arguss.core.models import FixCandidate
from arguss.lenses._trust_client import TrustClientError

_LOG = logging.getLogger(__name__)

_LOCKFILE_VERSION = 3
_DIRECT_DEP_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


class LockfileModificationError(Exception):
    """The lockfile could not be parsed or is not a supported lockfile v3."""


class NpmRegistryClient(Protocol):
    """Minimal npm registry surface used by lockfile fix."""

    def fetch_version_metadata(self, package: str, version: str) -> dict[str, Any]:
        """Return version document including ``dist.tarball`` and ``dist.integrity``."""
        ...


@dataclass(frozen=True)
class FixApplicationResult:
    """Outcome of attempting to apply one fix candidate in memory."""

    applied: bool
    skipped_reason: str | None = None
    entries_updated: tuple[str, ...] = ()
    files_modified: tuple[str, ...] = ()


def classify_dep_position(
    package: str,
    package_json: dict[str, Any],
) -> Literal["direct", "transitive"]:
    """Return ``direct`` if ``package`` is declared in any direct-dep section."""
    for section in _DIRECT_DEP_SECTIONS:
        deps = package_json.get(section)
        if isinstance(deps, dict) and package in deps:
            return "direct"
    return "transitive"


def _entry_key_matches_package(entry_key: str, package: str) -> bool:
    """True when the last ``/node_modules/<name>`` segment equals ``package``."""
    if not entry_key.startswith("node_modules/"):
        return False
    remainder = entry_key[len("node_modules/") :]
    parts = remainder.split("/node_modules/")
    return parts[-1] == package


def find_lockfile_entries(
    lockfile: dict[str, Any],
    package: str,
    from_version: str,
) -> list[str]:
    """Return all lockfile entry keys for ``package`` at exactly ``from_version``."""
    packages = lockfile.get("packages")
    if not isinstance(packages, dict):
        return []

    matching: list[str] = []
    for entry_key, entry_data in packages.items():
        if not entry_key:
            continue
        if not isinstance(entry_data, dict):
            continue
        if not _entry_key_matches_package(entry_key, package):
            continue
        if entry_data.get("version") == from_version:
            matching.append(entry_key)
    return matching


def _bump_range(current_range: str, to_version: str) -> str:
    """Preserve range prefix if recognized; otherwise pin exactly."""
    for prefix in ("^", "~", ">=", ">"):
        if current_range.startswith(prefix):
            return f"{prefix}{to_version}"
    return to_version


def _update_package_json_version(
    package_json: dict[str, Any],
    package: str,
    to_version: str,
) -> None:
    """Update the version range for ``package`` in whichever direct-dep section holds it."""
    for section in _DIRECT_DEP_SECTIONS:
        deps = package_json.get(section)
        if not isinstance(deps, dict) or package not in deps:
            continue
        current_range = deps[package]
        if not isinstance(current_range, str):
            deps[package] = to_version
        else:
            deps[package] = _bump_range(current_range, to_version)
        return
    raise ValueError(f"package {package} not found in any direct-dep section")


def _validate_lockfile(lockfile: dict[str, Any]) -> dict[str, Any]:
    if lockfile.get("lockfileVersion") != _LOCKFILE_VERSION:
        raise LockfileModificationError(
            f"lockfile version {lockfile.get('lockfileVersion')!r} is not supported "
            f"(expected {_LOCKFILE_VERSION})",
        )
    packages = lockfile.get("packages")
    if not isinstance(packages, dict):
        raise LockfileModificationError("lockfile packages field must be an object")
    return packages


def _update_root_lockfile_dep(
    packages: dict[str, Any],
    package: str,
    from_version: str,
    to_version: str,
) -> None:
    """Sync exact root dependency pins when present in the lockfile root entry."""
    root = packages.get("")
    if not isinstance(root, dict):
        return
    root_deps = root.get("dependencies")
    if not isinstance(root_deps, dict) or package not in root_deps:
        return
    pinned = root_deps[package]
    if pinned == from_version:
        root_deps[package] = to_version


def apply_fix_to_lockfile(
    lockfile: dict[str, Any],
    package_json: dict[str, Any],
    candidate: FixCandidate,
    npm_client: NpmRegistryClient,
) -> FixApplicationResult:
    """Apply a single fix candidate to ``lockfile`` and ``package_json`` in memory."""
    packages = _validate_lockfile(lockfile)

    position = classify_dep_position(candidate.package, package_json)

    entries = find_lockfile_entries(lockfile, candidate.package, candidate.from_version)
    if not entries:
        return FixApplicationResult(
            applied=False,
            skipped_reason=(
                f"no lockfile entry found for {candidate.package}@{candidate.from_version}; "
                f"lockfile may be out of sync"
            ),
        )

    try:
        new_pkg_meta = npm_client.fetch_version_metadata(
            candidate.package,
            candidate.to_version,
        )
    except TrustClientError as exc:
        return FixApplicationResult(
            applied=False,
            skipped_reason=(
                f"could not fetch {candidate.package}@{candidate.to_version} "
                f"from npm registry: {exc}"
            ),
        )

    dist = new_pkg_meta.get("dist")
    if not isinstance(dist, dict):
        return FixApplicationResult(
            applied=False,
            skipped_reason=(
                f"could not fetch {candidate.package}@{candidate.to_version} "
                f"from npm registry: missing dist metadata"
            ),
        )
    new_resolved = dist.get("tarball")
    new_integrity = dist.get("integrity")
    if not isinstance(new_resolved, str) or not isinstance(new_integrity, str):
        return FixApplicationResult(
            applied=False,
            skipped_reason=(
                f"could not fetch {candidate.package}@{candidate.to_version} "
                f"from npm registry: incomplete dist metadata"
            ),
        )

    try:
        if position == "direct":
            _update_package_json_version(package_json, candidate.package, candidate.to_version)
    except ValueError as exc:
        return FixApplicationResult(
            applied=False,
            skipped_reason=str(exc),
        )

    for entry_key in entries:
        entry = packages[entry_key]
        if not isinstance(entry, dict):
            return FixApplicationResult(
                applied=False,
                skipped_reason=(
                    f"lockfile packages[{entry_key!r}] is not an object; lockfile may be corrupt"
                ),
            )
        entry["version"] = candidate.to_version
        entry["resolved"] = new_resolved
        entry["integrity"] = new_integrity

    _update_root_lockfile_dep(
        packages,
        candidate.package,
        candidate.from_version,
        candidate.to_version,
    )

    _LOG.info(
        "lockfile fix applied",
        extra={
            "package": candidate.package,
            "from_version": candidate.from_version,
            "to_version": candidate.to_version,
            "entries_updated": len(entries),
            "entry_keys": entries,
        },
    )

    files_modified: tuple[str, ...]
    if position == "direct":
        files_modified = ("package.json", "package-lock.json")
    else:
        files_modified = ("package-lock.json",)

    return FixApplicationResult(
        applied=True,
        entries_updated=tuple(entries),
        files_modified=files_modified,
    )


def detect_json_indent(source: str | bytes) -> int | str:
    """Detect the indent style used by a JSON file.

    Returns an int (space count), ``'\t'`` for tabs, or ``2`` as default.
    """
    if isinstance(source, bytes):
        source = source.lstrip(b"\xef\xbb\xbf").decode("utf-8", errors="replace")

    for line in source.splitlines():
        if not line:
            continue
        if line[0] == "\t":
            return "\t"
        stripped = line.lstrip(" ")
        if line == stripped:
            continue
        return len(line) - len(stripped)

    return 2


def _encode_json(data: dict[str, Any], original_bytes: bytes) -> bytes:
    indent = detect_json_indent(original_bytes)
    trailing_newline = b"\n" if original_bytes.endswith(b"\n") else b""
    return json.dumps(data, indent=indent, ensure_ascii=False).encode("utf-8") + trailing_newline


def encode_lockfile(lockfile: dict[str, Any], original_bytes: bytes) -> bytes:
    """Serialize a lockfile dict, preserving source indent and trailing newline."""
    return _encode_json(lockfile, original_bytes)


def encode_package_json(package_json: dict[str, Any], original_bytes: bytes) -> bytes:
    """Serialize package.json, preserving source indent and trailing newline."""
    return _encode_json(package_json, original_bytes)


def parse_lockfile_bytes(lockfile_bytes: bytes) -> dict[str, Any]:
    """Parse lockfile bytes; raise ``LockfileModificationError`` on failure."""
    try:
        data = json.loads(lockfile_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockfileModificationError("lockfile is not valid JSON") from exc
    if not isinstance(data, dict):
        raise LockfileModificationError("lockfile root must be a JSON object")
    return data
