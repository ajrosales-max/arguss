"""Parser for npm package-lock.json files.

Supports lockfile versions 2 and 3. v1 is not supported (no ``packages`` section).
npm workspaces are out of scope; workspace entries are skipped silently.

The parser produces Dependency objects in two passes: physical placement from
lockfile paths (including ``install_key``), then per-physical-install logical
resolution (``parents``, display ``path``) via npm nearest-ancestor rules.

Output feeds the vulnerability lens (for blast radius analysis) and the
CycloneDX SBOM generator.
"""

from __future__ import annotations

import json
import logging
from collections import deque
from pathlib import Path
from typing import Any, cast

from arguss.core.models import Dependency

logger = logging.getLogger(__name__)

SUPPORTED_LOCKFILE_VERSIONS = (2, 3)


class ParserError(Exception):
    """Raised when a lockfile is missing, unreadable, or unsupported."""


def parse_lockfile(path: str | Path) -> list[Dependency]:
    """Parse an npm package-lock.json (v2 or v3) into Dependency objects.

    Args:
        path: Path to a package-lock.json file, OR a directory containing one.

    Returns:
        A list of Dependency objects, sorted by (name, version). The root
        package itself is excluded. Each row carries a non-empty ``install_key``
        (the raw lockfile ``packages`` key). After pass 2, ``parents`` is the
        full set of logical declarers whose nearest-ancestor resolution lands on
        that physical install; ``path`` is a single canonical display route.

    Raises:
        ParserError: If the file is missing, unreadable, unsupported, or produces
            a dependency without a valid ``install_key``.
    """
    lockfile_path = _resolve_lockfile_path(path)
    data = _load_lockfile(lockfile_path)
    _validate_lockfile_version(data, lockfile_path)

    direct_dep_names = _extract_direct_dep_names(data)
    packages = data.get("packages", {})

    by_install_key: dict[str, Dependency] = {}
    for pkg_path, pkg_data in packages.items():
        if pkg_path == "":
            continue  # root package
        if not pkg_path.startswith("node_modules/"):
            continue  # workspace or other non-standard entry
        if pkg_data.get("link") or pkg_data.get("extraneous"):
            continue

        dep = _build_dependency(pkg_path, pkg_data, direct_dep_names)
        if dep is not None:
            by_install_key[pkg_path] = dep

    _resolve_logical_relationships_per_install(by_install_key, packages)

    deps = list(by_install_key.values())
    _assert_parser_install_keys(deps)
    deps.sort(key=lambda d: (d.name, d.version))
    return deps


def _resolve_lockfile_path(path: str | Path) -> Path:
    """Accept either a file path or a directory; return the lockfile path."""
    p = Path(path).resolve()
    if p.is_dir():
        candidate = p / "package-lock.json"
        if not candidate.exists():
            raise ParserError(f"No package-lock.json found in {p}")
        return candidate
    if not p.exists():
        raise ParserError(f"Lockfile not found: {p}")
    return p


def _load_lockfile(path: Path) -> dict[str, Any]:
    """Load and JSON-parse the lockfile, raising ParserError on any issue."""
    try:
        return cast(dict[str, Any], json.loads(path.read_text()))
    except json.JSONDecodeError as e:
        raise ParserError(f"Invalid JSON in {path}: {e}") from e
    except OSError as e:
        raise ParserError(f"Cannot read {path}: {e}") from e


def _validate_lockfile_version(data: dict[str, Any], path: Path) -> None:
    """Ensure the lockfile is v2 or v3. v1 has no ``packages`` section and is rejected."""
    lockfile_version = data.get("lockfileVersion")
    if lockfile_version not in SUPPORTED_LOCKFILE_VERSIONS:
        supported = " or ".join(str(v) for v in SUPPORTED_LOCKFILE_VERSIONS)
        raise ParserError(
            f"{path}: lockfile version {lockfile_version} is not supported. "
            f"Arguss supports lockfileVersion {supported}. "
            "Run `npm install` with npm 7+ to generate a supported lockfile."
        )


def _extract_direct_dep_names(data: dict[str, Any]) -> set[str]:
    """Get the set of direct dep names from the root package entry."""
    root = data.get("packages", {}).get("", {})
    names: set[str] = set()
    for key in ("dependencies", "devDependencies"):
        names.update((root.get(key) or {}).keys())
    return names


def _build_dependency(
    pkg_path: str,
    pkg_data: dict[str, Any],
    direct_dep_names: set[str],
) -> Dependency | None:
    """Build a Dependency from a packages-entry path and its data."""
    version = pkg_data.get("version")
    if not version:
        return None  # weird entry, skip

    chain = _parse_package_path(pkg_path)
    if not chain:
        return None

    name = chain[-1]
    _assert_install_key_is_lockfile_relative(pkg_path)
    return Dependency(
        name=name,
        version=version,
        ecosystem="npm",
        direct=(name in direct_dep_names),
        install_key=pkg_path,
        path=["root", *chain],
        parents=[chain[-2]] if len(chain) > 1 else ["root"],
    )


def _assert_install_key_is_lockfile_relative(install_key: str) -> None:
    """Guardrail: install_key must be the raw lockfile key, never a filesystem path."""
    if not install_key:
        raise ParserError("install_key must be non-empty for parser-produced dependencies")
    if install_key.startswith("/") or install_key.startswith("\\"):
        raise ParserError(f"install_key must not be absolute: {install_key!r}")
    if "://" in install_key:
        raise ParserError(f"install_key must not be a URL: {install_key!r}")
    lowered = install_key.lower()
    for fragment in ("/tmp/", "/var/folders/", "/private/var/folders/", "\\temp\\"):
        if fragment in lowered:
            raise ParserError(f"install_key must not contain temp path fragment: {install_key!r}")
    if not install_key.startswith("node_modules/"):
        raise ParserError(f"install_key must be a lockfile node_modules key, got: {install_key!r}")


def _assert_parser_install_keys(deps: list[Dependency]) -> None:
    """Every parser-produced dependency must have a unique non-empty install_key."""
    seen: set[str] = set()
    for dep in deps:
        key = dep.install_key
        if not key:
            raise ParserError(
                f"parser produced dependency {dep.name}@{dep.version} without install_key"
            )
        if key in seen:
            raise ParserError(f"duplicate install_key from parser: {key!r}")
        seen.add(key)


def _logical_parent_name_for_pkg_path(pkg_path: str) -> str | None:
    """Label of the package that declares edges from this ``packages`` entry.

    For the root key (empty string), returns ``root`` (edges from the project).
    For ``node_modules/...`` keys, returns that package's logical name (last
    segment of the path chain). Returns None for non-``node_modules`` paths
    (e.g. workspaces), which we skip.
    """
    if pkg_path == "":
        return "root"
    if not pkg_path.startswith("node_modules/"):
        return None
    chain = _parse_package_path(pkg_path)
    return chain[-1] if chain else None


def _child_dep_keys_for_packages_entry(pkg_path: str, pkg_data: dict[str, Any]) -> list[str]:
    """Dependency names declared by this package entry (for logical edges)."""
    if pkg_path == "":
        keys: list[str] = []
        keys.extend((pkg_data.get("dependencies") or {}).keys())
        keys.extend((pkg_data.get("devDependencies") or {}).keys())
        return keys
    return list((pkg_data.get("dependencies") or {}).keys())


def _ancestor_node_modules_prefixes(declarer_key: str) -> list[str]:
    """Walk from declarer outward: nearest node_modules scope first, then root."""
    prefixes: list[str] = []
    cur = declarer_key
    while True:
        prefixes.append(cur)
        if cur == "":
            break
        if "/node_modules/" in cur:
            cur = cur.rsplit("/node_modules/", 1)[0]
        elif cur.startswith("node_modules/"):
            cur = ""
        else:
            break
    return prefixes


def _resolve_physical_install_key(
    declarer_key: str,
    child_name: str,
    packages: dict[str, Any],
) -> str | None:
    """Nearest-ancestor npm resolution: which physical ``packages`` key serves ``child_name``."""
    for prefix in _ancestor_node_modules_prefixes(declarer_key):
        candidate = (
            f"{prefix}/node_modules/{child_name}" if prefix else f"node_modules/{child_name}"
        )
        pkg_data = packages.get(candidate)
        if not isinstance(pkg_data, dict):
            continue
        if pkg_data.get("link") or pkg_data.get("extraneous"):
            continue
        if not pkg_data.get("version"):
            continue
        return candidate
    return None


def _build_install_parents_map(
    packages: dict[str, Any],
    install_keys: frozenset[str],
) -> dict[str, set[str]]:
    """install_key -> logical parent names whose resolution lands on that install."""
    install_parents: dict[str, set[str]] = {}

    for pkg_path, pkg_data in packages.items():
        parent_name = _logical_parent_name_for_pkg_path(pkg_path)
        if parent_name is None:
            continue

        for child_name in _child_dep_keys_for_packages_entry(pkg_path, pkg_data):
            target_key = _resolve_physical_install_key(pkg_path, child_name, packages)
            if target_key is None or target_key not in install_keys:
                continue
            install_parents.setdefault(target_key, set()).add(parent_name)

    return install_parents


def _build_name_level_parents_map(
    packages: dict[str, Any],
    by_name: frozenset[str],
) -> dict[str, set[str]]:
    """Name-level declarer graph for display-path BFS only (not identity)."""
    parents_map: dict[str, set[str]] = {}

    for pkg_path, pkg_data in packages.items():
        parent_name = _logical_parent_name_for_pkg_path(pkg_path)
        if parent_name is None:
            continue

        for child_name in _child_dep_keys_for_packages_entry(pkg_path, pkg_data):
            if child_name not in by_name:
                continue
            parents_map.setdefault(child_name, set()).add(parent_name)

    return parents_map


def _children_from_parents_map(parents_map: dict[str, set[str]]) -> dict[str, set[str]]:
    """Invert parents_map: parent -> set of children."""
    children_of: dict[str, set[str]] = {}
    for child, parents in parents_map.items():
        for p in parents:
            children_of.setdefault(p, set()).add(child)
    return children_of


def _bfs_shortest_pred(children_of: dict[str, set[str]]) -> dict[str, str]:
    """BFS from ``root``. Returns pred[name] = chosen predecessor on a shortest path.

    Tie-break for equal length: lexicographically smallest predecessor.
    Used for display ``path`` only.
    """
    dist: dict[str, int] = {"root": 0}
    pred: dict[str, str] = {}
    queue: deque[str] = deque(["root"])

    while queue:
        p = queue.popleft()
        d_p = dist[p]
        for child in sorted(children_of.get(p, ())):
            nd = d_p + 1
            if child not in dist or nd < dist[child]:
                dist[child] = nd
                pred[child] = p
                queue.append(child)
            elif nd == dist[child]:
                current_pred = pred.get(child)
                if current_pred is None or p < current_pred:
                    pred[child] = p

    return pred


def _logical_path_from_pred(name: str, pred: dict[str, str]) -> list[str]:
    """``['root', ..., name]`` following ``pred`` back to root (display only)."""
    if name not in pred and name != "root":
        return ["root", name]
    parts: list[str] = []
    cur = name
    while cur != "root":
        parts.append(cur)
        if cur not in pred:
            return ["root", name]
        cur = pred[cur]
    parts.append("root")
    parts.reverse()
    return parts


def _canonical_display_path(
    parents: list[str],
    child_name: str,
    pred: dict[str, str],
) -> list[str]:
    """Single representative route for display; lex-first parent, then name-level BFS."""
    if not parents:
        return ["root", child_name]
    canon_parent = sorted(parents)[0]
    base = _logical_path_from_pred(canon_parent, pred)
    if base[-1] == child_name:
        return base
    return base + [child_name]


def _resolve_logical_relationships_per_install(
    by_install_key: dict[str, Dependency],
    packages: dict[str, Any],
) -> None:
    """Second pass: per-physical-install ``parents`` and display ``path``.

    Mutates dependencies in place. ``install_key`` is set in pass 1 and unchanged.
    """
    install_keys = frozenset(by_install_key.keys())
    install_parents = _build_install_parents_map(packages, install_keys)

    by_name = frozenset(d.name for d in by_install_key.values())
    name_parents = _build_name_level_parents_map(packages, by_name)
    children_of = _children_from_parents_map(name_parents)
    pred = _bfs_shortest_pred(children_of)

    for install_key, dep in by_install_key.items():
        parents = sorted(install_parents.get(install_key, {"root"}))
        dep.parents = parents
        dep.path = _canonical_display_path(parents, dep.name, pred)


def _parse_package_path(pkg_path: str) -> list[str]:
    """Split a node_modules path into its package-name chain.

    'node_modules/foo' → ['foo']
    'node_modules/foo/node_modules/bar' → ['foo', 'bar']
    'node_modules/@scope/pkg' → ['@scope/pkg']
    'node_modules/foo/node_modules/@scope/bar' → ['foo', '@scope/bar']
    """
    if not pkg_path.startswith("node_modules/"):
        return []

    # Split on /node_modules/ to separate the chain
    parts = pkg_path.split("/node_modules/")
    # First part starts with "node_modules/" -strip it
    parts[0] = parts[0].removeprefix("node_modules/")
    return [p for p in parts if p]


def lockfile_project_for_sbom(
    path: str | Path,
    project_name_override: str | None = None,
) -> tuple[str, str]:
    """Resolve a lockfile path and return ``(project_name, project_version)`` for SBOM root metadata.

    ``project_name`` defaults to the directory containing ``package-lock.json``.
    ``project_version`` comes from the root ``packages[\"\"]`` entry, or
    ``\"0.0.0\"`` when missing.
    """
    lockfile_path = _resolve_lockfile_path(path)
    data = _load_lockfile(lockfile_path)
    root = (data.get("packages") or {}).get("") or {}
    version = str(root.get("version") or "0.0.0")
    name = project_name_override if project_name_override is not None else lockfile_path.parent.name
    return (name, version)
