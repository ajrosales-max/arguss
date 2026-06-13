"""Tests for blast-radius subgraph element builders."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from arguss.web.graph_data import (
    build_full_graph_elements,
    build_subgraph_elements,
    build_trust_by_package_from_lens_explain,
    explain_subgraph_miss,
    finding_dicts_from_cached,
)
from arguss.web.url_scan import serialize_lockfile_deps

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles"
_REAL_WORLD = _FIXTURES / "real-world.json"


def _node_ids(elements: list[dict[str, Any]]) -> list[str]:
    return [el["data"]["id"] for el in elements if "source" not in el["data"]]


def _edge_pairs(elements: list[dict[str, Any]]) -> list[tuple[str, str]]:
    return [
        (el["data"]["source"], el["data"]["target"]) for el in elements if "source" in el["data"]
    ]


def _element_ids(elements: list[dict[str, Any]]) -> list[str]:
    return [el["data"]["id"] for el in elements]


@pytest.fixture
def real_world_deps() -> list[dict[str, Any]]:
    return serialize_lockfile_deps(_REAL_WORLD)


def test_build_subgraph_debug_multi_parent_routes(real_world_deps: list[dict[str, Any]]) -> None:
    elements = build_subgraph_elements("debug", "2.6.9", real_world_deps, [])

    assert "debug" in _node_ids(elements)
    assert ("express", "debug") in _edge_pairs(elements)
    assert ("body-parser", "debug") in _edge_pairs(elements)
    assert ("finalhandler", "debug") in _edge_pairs(elements)
    assert ("send", "debug") in _edge_pairs(elements)
    assert ("root", "express") in _edge_pairs(elements)

    debug_node = next(el for el in elements if el["data"].get("id") == "debug")
    assert debug_node["data"]["node_class"] == "target"
    assert debug_node["data"]["version"] == "2.6.9"


def test_build_subgraph_ms_parents_include_debug_and_send(
    real_world_deps: list[dict[str, Any]],
) -> None:
    elements = build_subgraph_elements("ms", "2.0.0", real_world_deps, [])

    assert ("debug", "ms") in _edge_pairs(elements)
    assert ("send", "ms") in _edge_pairs(elements)
    assert "debug" in _node_ids(elements)
    assert "send" in _node_ids(elements)


def test_build_subgraph_cyclic_deps_does_not_hang() -> None:
    cyclic_deps = [
        {
            "package": "pkg-a",
            "version": "1.0.0",
            "is_direct": False,
            "parents": ["pkg-b"],
            "path": ["root", "pkg-b", "pkg-a"],
        },
        {
            "package": "pkg-b",
            "version": "1.0.0",
            "is_direct": False,
            "parents": ["pkg-a", "root"],
            "path": ["root", "pkg-b"],
        },
    ]

    elements = build_subgraph_elements("pkg-a", "1.0.0", cyclic_deps, [])

    assert "pkg-a" in _node_ids(elements)
    assert "pkg-b" in _node_ids(elements)
    assert "root" in _node_ids(elements)
    assert ("pkg-b", "pkg-a") in _edge_pairs(elements)
    assert ("pkg-a", "pkg-b") in _edge_pairs(elements)
    assert ("root", "pkg-b") in _edge_pairs(elements)


def test_build_subgraph_missing_parents_returns_empty() -> None:
    legacy_deps = [
        {"package": "express", "version": "4.17.0", "is_direct": True},
        {"package": "debug", "version": "2.6.9", "is_direct": False},
    ]

    assert build_subgraph_elements("debug", "2.6.9", legacy_deps, []) == []
    assert build_subgraph_elements("debug", "2.6.9", [], []) == []


def test_build_subgraph_no_duplicate_element_ids(real_world_deps: list[dict[str, Any]]) -> None:
    elements = build_subgraph_elements("debug", "2.6.9", real_world_deps, [])
    ids = _element_ids(elements)
    assert len(ids) == len(set(ids))


def test_explain_subgraph_miss_legacy_deps_returns_none() -> None:
    legacy_deps = [
        {"package": "express", "version": "4.17.0", "is_direct": True},
        {"package": "debug", "version": "2.6.9", "is_direct": False},
    ]
    assert explain_subgraph_miss("debug", "2.6.9", legacy_deps) is None
    assert explain_subgraph_miss("debug", "2.6.9", []) is None


def test_explain_subgraph_miss_version_mismatch_returns_reason(
    real_world_deps: list[dict[str, Any]],
) -> None:
    reason = explain_subgraph_miss("debug", "9.9.9", real_world_deps)
    assert reason is not None
    assert reason.startswith("target_version_mismatch:")


def test_build_subgraph_version_mismatch_returns_empty(
    real_world_deps: list[dict[str, Any]],
) -> None:
    assert build_subgraph_elements("debug", "9.9.9", real_world_deps, []) == []


def test_build_subgraph_aggregates_vuln_stats_from_findings(
    real_world_deps: list[dict[str, Any]],
) -> None:
    findings = [
        {
            "severity": "high",
            "dependency": {"name": "debug", "version": "2.6.9"},
        },
        {
            "severity": "medium",
            "dependency": {"name": "express", "version": "4.17.0"},
        },
        {
            "severity": "low",
            "dependency": {"name": "express", "version": "4.17.0"},
        },
        {
            "severity": "critical",
            "dependency": {"name": "send", "version": "0.17.1"},
        },
    ]

    elements = build_subgraph_elements("debug", "2.6.9", real_world_deps, findings)

    debug = next(el for el in elements if el["data"].get("id") == "debug")
    express = next(el for el in elements if el["data"].get("id") == "express")
    send = next(el for el in elements if el["data"].get("id") == "send")

    assert debug["data"]["vuln_count"] == 1
    assert debug["data"]["max_severity"] == "high"
    assert express["data"]["vuln_count"] == 2
    assert express["data"]["max_severity"] == "medium"
    assert send["data"]["vuln_count"] == 1
    assert send["data"]["max_severity"] == "critical"


def test_finding_dicts_from_cached_collects_entry_and_related() -> None:
    cached = {
        "entries": [
            {
                "finding": {"severity": "high", "dependency": {"name": "a"}},
                "related_findings": [
                    {"severity": "low", "dependency": {"name": "b"}},
                ],
            },
            {
                "related_findings": [{"severity": "medium", "dependency": {"name": "c"}}],
            },
        ],
    }

    findings = finding_dicts_from_cached(cached)
    names = {f["dependency"]["name"] for f in findings}
    assert names == {"a", "b", "c"}


def test_build_packages_attaches_subgraph_elements() -> None:
    from pathlib import Path

    from arguss.web.results_context import build_packages
    from arguss.web.url_scan import serialize_lockfile_deps
    from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts
    from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

    lockfile = Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles" / "real-world.json"
    deps = serialize_lockfile_deps(lockfile)
    entry = _cached_entry(package="debug")
    entry["finding"]["dependency"]["version"] = "2.6.9"
    entry["candidate"]["from_version"] = "2.6.9"
    scan = _cached_scan_dict(entries=[entry])
    scan["deps"] = deps
    scan = attach_minimal_scan_counts(scan)
    packages = build_packages(scan, scan_hash="graph-test")
    debug_pkg = next(p for p in packages if p.name == "debug")
    assert debug_pkg.subgraph_elements
    assert any(el["data"].get("id") == "debug" for el in debug_pkg.subgraph_elements)


def test_build_packages_from_clean_deps_attaches_subgraph_elements() -> None:
    from pathlib import Path

    from arguss.web.results_context import build_packages
    from arguss.web.url_scan import serialize_lockfile_deps
    from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts
    from tests.test_candidate_selection_ui import _cached_scan_dict

    lockfile = Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles" / "real-world.json"
    deps = serialize_lockfile_deps(lockfile)
    scan = _cached_scan_dict(entries=[])
    scan["deps"] = deps
    scan = attach_minimal_scan_counts(scan, total_findings=0)
    packages = build_packages(scan, scan_hash="clean-graph-test")
    assert packages
    debug_pkg = next((pkg for pkg in packages if pkg.name == "debug"), None)
    assert debug_pkg is not None
    assert debug_pkg.total_count == 0
    assert debug_pkg.summary_tier == "clean"
    assert debug_pkg.subgraph_elements


def test_build_full_graph_express_node_and_edge_counts(
    real_world_deps: list[dict[str, Any]],
) -> None:
    from arguss.web.graph_data import _deps_index

    index = _deps_index(real_world_deps)
    elements = build_full_graph_elements(real_world_deps, [])
    node_ids = _node_ids(elements)
    edge_pairs = _edge_pairs(elements)

    assert len(node_ids) == len(index) + 1
    assert "root" in node_ids
    root = next(el for el in elements if el["data"].get("id") == "root")
    assert root["data"]["node_class"] == "root"

    for name, meta in index.items():
        for parent in meta["parents"]:
            assert (parent, name) in edge_pairs


def test_build_full_graph_vuln_flags(real_world_deps: list[dict[str, Any]]) -> None:
    findings = [
        {"severity": "high", "dependency": {"name": "debug", "version": "2.6.9"}},
        {"severity": "critical", "dependency": {"name": "send", "version": "0.17.1"}},
    ]
    elements = build_full_graph_elements(real_world_deps, findings)

    debug = next(el for el in elements if el["data"].get("id") == "debug")
    send = next(el for el in elements if el["data"].get("id") == "send")
    express = next(el for el in elements if el["data"].get("id") == "express")

    assert debug["data"]["has_vuln"] is True
    assert debug["data"]["max_severity"] == "high"
    assert send["data"]["has_vuln"] is True
    assert send["data"]["max_severity"] == "critical"
    assert express["data"]["has_vuln"] is False
    assert express["data"]["max_severity"] is None


def test_build_full_graph_trust_only_on_scored_subset(
    real_world_deps: list[dict[str, Any]],
) -> None:
    trust_by_package = {
        "express": {"trust_score": 72, "trust_concern": "Branch-Protection (3)"},
    }
    elements = build_full_graph_elements(real_world_deps, [], trust_by_package=trust_by_package)

    express = next(el for el in elements if el["data"].get("id") == "express")
    debug = next(el for el in elements if el["data"].get("id") == "debug")

    assert express["data"]["trust_score"] == 72
    assert express["data"]["trust_concern"] == "Branch-Protection (3)"
    assert "trust_score" not in debug["data"]
    assert "trust_concern" not in debug["data"]


def test_build_full_graph_no_duplicate_element_ids(real_world_deps: list[dict[str, Any]]) -> None:
    elements = build_full_graph_elements(real_world_deps, [])
    ids = _element_ids(elements)
    assert len(ids) == len(set(ids))


def test_build_full_graph_cyclic_deps_finite() -> None:
    cyclic_deps = [
        {
            "package": "pkg-a",
            "version": "1.0.0",
            "is_direct": False,
            "parents": ["pkg-b"],
            "path": ["root", "pkg-b", "pkg-a"],
        },
        {
            "package": "pkg-b",
            "version": "1.0.0",
            "is_direct": False,
            "parents": ["pkg-a", "root"],
            "path": ["root", "pkg-b"],
        },
    ]
    elements = build_full_graph_elements(cyclic_deps, [])
    assert elements
    assert len(_element_ids(elements)) == len(set(_element_ids(elements)))


def test_build_full_graph_legacy_deps_returns_empty() -> None:
    legacy_deps = [
        {"package": "express", "version": "4.17.0", "is_direct": True},
    ]
    assert build_full_graph_elements(legacy_deps, []) == []


def test_build_trust_by_package_from_lens_explain_maps_subscore_and_concern() -> None:
    cached: dict[str, Any] = {
        "lens_explain": {
            "trust": {
                "packages": [
                    {
                        "name": "left-pad",
                        "subscore": 50,
                        "scorecard_top_concerns": ["low maintainability", "other"],
                    },
                    {"name": "no-subscore", "scorecard_top_concerns": ["ignored"]},
                    {"name": "", "subscore": 10},
                ]
            }
        }
    }
    assert build_trust_by_package_from_lens_explain(cached) == {
        "left-pad": {"trust_score": 50, "trust_concern": "low maintainability"},
    }


def test_build_results_context_includes_nonempty_full_graph_elements() -> None:
    from arguss.web.results_context import build_results_context
    from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts

    cached = attach_minimal_scan_counts(
        {
            "entries": [],
            "project_scores": {},
            "summary": {
                "total_findings": 0,
                "auto_merge_count": 0,
                "review_required_count": 0,
                "decline_count": 0,
            },
            "skipped_findings": [],
            "lens_explain": {},
            "deps": [
                {
                    "package": "left-pad",
                    "version": "1.0.0",
                    "is_direct": True,
                    "parents": ["root"],
                    "path": ["root", "left-pad"],
                },
            ],
        }
    )
    context = build_results_context(cached, "hash-full-graph")
    assert context["full_graph_elements"]
