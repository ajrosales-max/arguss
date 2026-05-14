"""CycloneDX JSON SBOM generation from parsed npm lockfile dependencies."""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import Any

from arguss.core.models import Dependency

CYCLONEDX_SPEC_VERSION = "1.7"


def _encode_npm_name_for_purl(name: str) -> str:
    """Encode an npm package name for the ``name`` segment of ``pkg:npm/...``.

    Scoped names (``@scope/pkg``) encode the leading ``@`` as ``%40`` per the
    Package URL spec for npm.
    """
    if name.startswith("@"):
        return "%40" + name[1:]
    return name


def _purl(name: str, version: str) -> str:
    """Full Package-URL for an npm dependency (also used as ``bom-ref``)."""
    return f"pkg:npm/{_encode_npm_name_for_purl(name)}@{version}"


def _project_bom_ref(project_name: str, project_version: str) -> str:
    """Stable ``bom-ref`` for the analyzed project (custom ``pkg:project`` scheme)."""
    return f"pkg:project/{_encode_npm_name_for_purl(project_name)}@{project_version}"


def _arguss_tool_version() -> str:
    try:
        return pkg_version("arguss")
    except PackageNotFoundError:
        return "0.1.0"


def _merge_dep_rows(deps: Iterable[Dependency]) -> dict[tuple[str, str], frozenset[str]]:
    """Key ``(name, version)`` -> merged logical ``parents`` (deduped rows share one component)."""
    merged: dict[tuple[str, str], set[str]] = {}
    for d in deps:
        key = (d.name, d.version)
        merged.setdefault(key, set()).update(d.parents)
    return {k: frozenset(v) for k, v in merged.items()}


def _deps_by_name(
    merged: dict[tuple[str, str], frozenset[str]],
) -> dict[str, list[tuple[str, str]]]:
    """Map bare package name -> sorted list of ``(name, version)`` keys with that name."""
    by_name: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for name, ver in merged:
        by_name[name].append((name, ver))
    for name in by_name:
        by_name[name].sort(key=lambda t: (t[0], t[1]))
    return dict(by_name)


def _build_dependency_graph(
    merged: dict[tuple[str, str], frozenset[str]],
    root_ref: str,
) -> dict[str, set[str]]:
    """Build ``dependsOn`` edges: each parent ``bom-ref`` -> set of child ``bom-ref``s.

    Uses ``Dependency.parents`` from the parser: ``root`` and package names are
    logical parents. If multiple installed versions share a bare ``name``, an edge
    is emitted from **each** matching parent ``bom-ref`` to the child (conservative
    when the lockfile model only records the parent name).
    """
    by_name = _deps_by_name(merged)
    edges: dict[str, set[str]] = defaultdict(set)

    for name, ver in sorted(merged.keys(), key=lambda t: (t[0], t[1])):
        child_ref = _purl(name, ver)
        for parent in sorted(merged[(name, ver)]):
            if parent == "root":
                edges[root_ref].add(child_ref)
                continue
            for pname, pver in by_name.get(parent, ()):
                edges[_purl(pname, pver)].add(child_ref)

    return edges


def generate_sbom(
    deps: list[Dependency], project_name: str, project_version: str
) -> dict[str, Any]:
    """Build a CycloneDX JSON-serializable dict from parsed dependencies.

    ``specVersion`` is :data:`CYCLONEDX_SPEC_VERSION` (ECMA-424 2nd Edition / CycloneDX 1.7).

    Components are deduplicated by ``(name, version)``. The ``dependencies`` graph
    follows logical ``parents`` edges (parser output). ``components`` and
    ``dependsOn`` lists are sorted for stable diffs; ``serialNumber`` and
    ``metadata.timestamp`` change each run.
    """
    root_ref = _project_bom_ref(project_name, project_version)
    merged = _merge_dep_rows(deps)
    edges = _build_dependency_graph(merged, root_ref)

    components: list[dict[str, Any]] = []
    for name, ver in sorted(merged.keys(), key=lambda t: (t[0], t[1])):
        pr = _purl(name, ver)
        components.append(
            {
                "type": "library",
                "bom-ref": pr,
                "name": name,
                "version": ver,
                "purl": pr,
                "scope": "required",
            }
        )

    component_refs = {c["bom-ref"] for c in components}
    root_entry: dict[str, Any] = {
        "ref": root_ref,
        "dependsOn": sorted(edges.get(root_ref, ())),
    }
    component_entries = [
        {"ref": ref, "dependsOn": sorted(edges.get(ref, set()))} for ref in sorted(component_refs)
    ]
    dep_entries = [root_entry, *component_entries]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "vendor": "Arguss",
                        "name": "arguss",
                        "version": _arguss_tool_version(),
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": project_name,
                "version": project_version,
            },
        },
        "components": components,
        "dependencies": dep_entries,
    }
