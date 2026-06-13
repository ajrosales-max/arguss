"""Cytoscape element builders for per-package blast-radius subgraphs."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_ROOT_ID = "root"


def _deps_graph_available(deps: list[dict[str, Any]]) -> bool:
    """True when deps carry enriched parent edges (post-enrichment cache payloads)."""
    if not deps:
        return False
    for raw in deps:
        if not isinstance(raw, dict):
            return False
        if not isinstance(raw.get("parents"), list):
            return False
    return True


def _deps_index(deps: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for raw in deps:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("package") or "").strip()
        if not name:
            continue
        parents_raw = raw.get("parents")
        parents = (
            [str(p).strip() for p in parents_raw if str(p).strip()]
            if isinstance(parents_raw, list)
            else None
        )
        version = str(raw.get("version") or "").strip()
        is_direct = bool(raw.get("is_direct"))
        if name not in index:
            index[name] = {
                "version": version,
                "is_direct": is_direct,
                "parents": set(parents or []),
            }
        else:
            entry = index[name]
            entry["parents"].update(parents or [])
            entry["is_direct"] = entry["is_direct"] or is_direct
            if version and not entry["version"]:
                entry["version"] = version
    merged: dict[str, dict[str, Any]] = {}
    for name, entry in index.items():
        merged[name] = {
            "version": entry["version"],
            "is_direct": entry["is_direct"],
            "parents": sorted(entry["parents"]),
        }
    return merged


def _target_dep_exists(
    deps: list[dict[str, Any]],
    target: str,
    target_version: str | None,
) -> bool:
    if target_version is None:
        return any(
            isinstance(raw, dict) and str(raw.get("package") or "").strip() == target
            for raw in deps
        )
    version = str(target_version).strip()
    if not version:
        return _target_dep_exists(deps, target, None)
    return any(
        isinstance(raw, dict)
        and str(raw.get("package") or "").strip() == target
        and str(raw.get("version") or "").strip() == version
        for raw in deps
    )


def _max_severity(severities: list[str]) -> str | None:
    ranked = [s for s in severities if s in _SEVERITY_ORDER]
    if not ranked:
        return None
    return min(ranked, key=lambda s: _SEVERITY_ORDER[s])


def _vuln_stats_by_package(
    findings: list[dict[str, Any]],
    index: dict[str, dict[str, Any]],
) -> dict[str, tuple[int, str | None]]:
    """Map package name -> (vuln_count, max_severity) using dep versions from index."""
    by_package: dict[str, list[str]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        dep = finding.get("dependency")
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name") or "").strip()
        version = str(dep.get("version") or "").strip()
        if not name:
            continue
        expected_version = index.get(name, {}).get("version")
        if expected_version and version and version != expected_version:
            continue
        severity = finding.get("severity")
        if isinstance(severity, str) and severity.strip():
            by_package.setdefault(name, []).append(severity.strip().lower())
    return {
        name: (len(severities), _max_severity(severities))
        for name, severities in by_package.items()
    }


def _collect_nodes_and_edges(
    target: str,
    index: dict[str, dict[str, Any]],
) -> tuple[set[str], set[tuple[str, str]]]:
    nodes: set[str] = set()
    edges: set[tuple[str, str]] = set()

    def walk(node: str, visiting: frozenset[str]) -> None:
        if node in visiting:
            return
        nodes.add(node)
        if node == _ROOT_ID:
            return
        meta = index.get(node)
        if meta is None:
            return
        parents = meta.get("parents")
        if not isinstance(parents, list):
            return
        for parent in parents:
            if not parent:
                continue
            edges.add((parent, node))
            walk(parent, visiting | {node})

    walk(target, frozenset())
    return nodes, edges


def _node_class(node_id: str, target: str, is_direct: bool) -> str:
    if node_id == target:
        return "target"
    if node_id == _ROOT_ID:
        return "root"
    if is_direct:
        return "direct"
    return "intermediate"


def _full_graph_node_class(node_id: str, is_direct: bool) -> str:
    if node_id == _ROOT_ID:
        return "root"
    if is_direct:
        return "direct"
    return "transitive"


def _all_graph_edges(index: dict[str, dict[str, Any]]) -> set[tuple[str, str]]:
    edges: set[tuple[str, str]] = set()
    for name, meta in index.items():
        parents = meta.get("parents")
        if not isinstance(parents, list):
            continue
        for parent in parents:
            parent_id = str(parent or "").strip()
            if parent_id:
                edges.add((parent_id, name))
    return edges


def _depth_by_package(
    deps: list[dict[str, Any]],
    edges: set[tuple[str, str]],
) -> dict[str, int]:
    """Shortest distance from root using path length on dep rows, then edge BFS."""
    depths: dict[str, int] = {_ROOT_ID: 0}
    for raw in deps:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("package") or "").strip()
        path = raw.get("path")
        if not name or not isinstance(path, list):
            continue
        path_parts = [str(part).strip() for part in path if str(part).strip()]
        if not path_parts:
            continue
        depth = len(path_parts) - 1 if path_parts[0] == _ROOT_ID else len(path_parts)
        if name not in depths or depth < depths[name]:
            depths[name] = depth

    adjacency: dict[str, list[str]] = defaultdict(list)
    for parent, child in edges:
        adjacency[parent].append(child)

    queue: deque[tuple[str, int]] = deque([(_ROOT_ID, 0)])
    while queue:
        node, depth = queue.popleft()
        if node not in depths or depth < depths[node]:
            depths[node] = depth
        for child in adjacency.get(node, []):
            child_depth = depth + 1
            if child not in depths or child_depth < depths[child]:
                queue.append((child, child_depth))

    return depths


def _node_element(data: dict[str, Any]) -> dict[str, Any]:
    return {"data": data}


def _edge_element(parent: str, child: str) -> dict[str, Any]:
    return {
        "data": {
            "id": f"{parent}->{child}",
            "source": parent,
            "target": child,
        },
    }


def build_trust_by_package_from_lens_explain(cached: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map direct-dep trust lens rows to graph node attrs (subscore only, no candidate fallback)."""
    packages = (cached.get("lens_explain") or {}).get("trust", {}).get("packages") or []
    out: dict[str, dict[str, Any]] = {}
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        sub = pkg.get("subscore")
        if not isinstance(sub, (int, float)):
            continue
        entry: dict[str, Any] = {"trust_score": int(sub)}
        concerns = pkg.get("scorecard_top_concerns")
        if isinstance(concerns, list) and concerns:
            first = concerns[0]
            if isinstance(first, str) and first.strip():
                entry["trust_concern"] = first.strip()
        out[name] = entry
    return out


def finding_dicts_from_cached(cached: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect finding dicts from cached scan entries for subgraph vuln metadata."""
    out: list[dict[str, Any]] = []
    for entry in cached.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        related = entry.get("related_findings")
        if isinstance(related, list):
            for item in related:
                if isinstance(item, dict):
                    out.append(item)
        finding = entry.get("finding")
        if isinstance(finding, dict):
            out.append(finding)
    return out


def explain_subgraph_miss(
    target_name: str,
    target_version: str | None,
    deps: list[dict[str, Any]],
) -> str | None:
    """Return a debug reason when enriched deps exist but no subgraph can be built.

    Returns None for legacy caches without parent edges (expected silence).
    """
    if not _deps_graph_available(deps):
        return None
    target = str(target_name or "").strip()
    if not target:
        return "empty_target_name"
    index = _deps_index(deps)
    if target not in index:
        return f"package_not_in_deps_index:{target}"
    if not _target_dep_exists(deps, target, target_version):
        card_version = str(target_version or "").strip() or "unknown"
        index_version = str(index.get(target, {}).get("version") or "").strip() or "unknown"
        return f"target_version_mismatch:card={card_version} deps_index={index_version}"
    nodes, _ = _collect_nodes_and_edges(target, index)
    if not nodes:
        return f"no_reachable_nodes:{target}"
    return "unknown_empty_subgraph"


def build_full_graph_elements(
    deps: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    trust_by_package: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build deduped Cytoscape nodes and edges for the full-project dependency graph."""
    if not _deps_graph_available(deps):
        return []

    index = _deps_index(deps)
    if not index:
        return []

    edges = _all_graph_edges(index)
    nodes: set[str] = set(index.keys())
    nodes.add(_ROOT_ID)
    for parent, child in edges:
        nodes.add(parent)
        nodes.add(child)

    vuln_stats = _vuln_stats_by_package(findings, index)
    depths = _depth_by_package(deps, edges)
    trust = trust_by_package or {}

    elements: list[dict[str, Any]] = []
    for node_id in sorted(nodes, key=str.lower):
        if node_id == _ROOT_ID:
            version = ""
            is_direct = False
            node_class = "root"
            depth = 0
        else:
            meta = index.get(node_id, {})
            version = str(meta.get("version") or "")
            is_direct = bool(meta.get("is_direct"))
            node_class = _full_graph_node_class(node_id, is_direct)
            depth = depths.get(node_id, 0)

        vuln_count, max_severity = vuln_stats.get(node_id, (0, None))
        data: dict[str, Any] = {
            "id": node_id,
            "label": node_id,
            "version": version,
            "node_class": node_class,
            "vuln_count": vuln_count,
            "max_severity": max_severity,
            "has_vuln": vuln_count > 0,
            "depth": depth,
        }
        trust_entry = trust.get(node_id)
        if isinstance(trust_entry, dict):
            trust_score = trust_entry.get("trust_score")
            if isinstance(trust_score, (int, float)):
                data["trust_score"] = int(trust_score)
            concern = trust_entry.get("trust_concern")
            if isinstance(concern, str) and concern.strip():
                data["trust_concern"] = concern.strip()

        elements.append(_node_element(data))

    for parent, child in sorted(edges, key=lambda pair: (pair[0].lower(), pair[1].lower())):
        elements.append(_edge_element(parent, child))

    return elements


def build_subgraph_elements(
    target_name: str,
    target_version: str | None,
    deps: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build deduped Cytoscape nodes and edges for one package blast-radius subgraph."""
    if not _deps_graph_available(deps):
        return []

    index = _deps_index(deps)
    target = str(target_name or "").strip()
    if not target or target not in index:
        return []

    if not _target_dep_exists(deps, target, target_version):
        return []

    target_version_label = (
        str(target_version).strip()
        if target_version is not None and str(target_version).strip()
        else index[target]["version"]
    )

    nodes, edges = _collect_nodes_and_edges(target, index)
    if not nodes:
        return []

    vuln_stats = _vuln_stats_by_package(findings, index)
    elements: list[dict[str, Any]] = []

    for node_id in sorted(nodes, key=str.lower):
        if node_id == target:
            version = target_version_label
            is_direct = bool(index.get(node_id, {}).get("is_direct"))
        elif node_id == _ROOT_ID:
            version = ""
            is_direct = False
        else:
            meta = index.get(node_id, {})
            version = str(meta.get("version") or "")
            is_direct = bool(meta.get("is_direct"))

        vuln_count, max_severity = vuln_stats.get(node_id, (0, None))
        elements.append(
            _node_element(
                {
                    "id": node_id,
                    "label": node_id,
                    "version": version,
                    "node_class": _node_class(node_id, target, is_direct),
                    "vuln_count": vuln_count,
                    "max_severity": max_severity,
                }
            )
        )

    for parent, child in sorted(edges, key=lambda pair: (pair[0].lower(), pair[1].lower())):
        elements.append(_edge_element(parent, child))

    return elements
