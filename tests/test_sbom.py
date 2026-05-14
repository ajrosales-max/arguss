"""Tests for CycloneDX SBOM generation."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from arguss.core.models import Dependency
from arguss.core.parser import parse_lockfile
from arguss.core.sbom import CYCLONEDX_SPEC_VERSION, generate_sbom

FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"


def _strip_volatile(sbom: dict) -> dict:
    out = copy.deepcopy(sbom)
    out.pop("serialNumber", None)
    meta = out.get("metadata") or {}
    meta.pop("timestamp", None)
    out["metadata"] = meta
    return out


def test_minimal_sbom_top_level_structure() -> None:
    deps = parse_lockfile(FIXTURES / "minimal.json")
    bom = generate_sbom(deps, "minimal-test", "1.0.0")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == CYCLONEDX_SPEC_VERSION
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert isinstance(bom["components"], list)
    assert isinstance(bom["dependencies"], list)
    assert bom["metadata"]["component"]["name"] == "minimal-test"


def test_empty_deps_valid_sbom() -> None:
    bom = generate_sbom([], "empty-proj", "0.0.0")
    assert bom["components"] == []
    assert len(bom["dependencies"]) == 1
    root = bom["dependencies"][0]
    assert root["dependsOn"] == []
    assert root["ref"] == bom["metadata"]["component"]["bom-ref"]
    assert root["ref"].startswith("pkg:project/")


def test_scoped_package_purl_encoding() -> None:
    deps = [
        Dependency(
            name="@types/node",
            version="20.1.0",
            ecosystem="npm",
            direct=True,
            path=["root", "@types/node"],
            parents=["root"],
        )
    ]
    bom = generate_sbom(deps, "app", "1.0.0")
    c = bom["components"][0]
    assert c["purl"] == "pkg:npm/%40types/node@20.1.0"
    assert c["bom-ref"] == c["purl"]


def test_components_deduplicated_by_name_version() -> None:
    deps = [
        Dependency(
            name="left-pad",
            version="1.3.0",
            ecosystem="npm",
            direct=True,
            path=[],
            parents=["root"],
        ),
        Dependency(
            name="left-pad",
            version="1.3.0",
            ecosystem="npm",
            direct=True,
            path=[],
            parents=["root"],
        ),
    ]
    bom = generate_sbom(deps, "dup", "1.0.0")
    assert len(bom["components"]) == 1
    assert bom["components"][0]["name"] == "left-pad"


def test_dependency_graph_logical_from_parents() -> None:
    deps = [
        Dependency(
            name="parent-pkg",
            version="1.0.0",
            ecosystem="npm",
            direct=True,
            path=[],
            parents=["root"],
        ),
        Dependency(
            name="child-pkg",
            version="1.0.0",
            ecosystem="npm",
            direct=False,
            path=[],
            parents=["root", "parent-pkg"],
        ),
    ]
    bom = generate_sbom(deps, "proj", "1.0.0")
    root_ref = bom["metadata"]["component"]["bom-ref"]
    by_ref = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    child_ref = "pkg:npm/child-pkg@1.0.0"
    parent_ref = "pkg:npm/parent-pkg@1.0.0"
    assert root_ref in by_ref
    assert child_ref in by_ref
    assert child_ref in by_ref[root_ref]
    assert parent_ref in by_ref[root_ref]
    assert child_ref in by_ref[parent_ref]


def test_multi_version_parent_fan_out_edges() -> None:
    """Ambiguous parent name 'p' with two versions: both get an edge to the child."""
    deps = [
        Dependency(
            name="p",
            version="1.0.0",
            ecosystem="npm",
            direct=True,
            path=[],
            parents=["root"],
        ),
        Dependency(
            name="p",
            version="2.0.0",
            ecosystem="npm",
            direct=True,
            path=[],
            parents=["root"],
        ),
        Dependency(
            name="c",
            version="1.0.0",
            ecosystem="npm",
            direct=False,
            path=[],
            parents=["p"],
        ),
    ]
    bom = generate_sbom(deps, "fanout", "1.0.0")
    by_ref = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    c_ref = "pkg:npm/c@1.0.0"
    assert c_ref in by_ref["pkg:npm/p@1.0.0"]
    assert c_ref in by_ref["pkg:npm/p@2.0.0"]


def test_deterministic_except_uuid_and_timestamp() -> None:
    deps = parse_lockfile(FIXTURES / "minimal.json")
    a = generate_sbom(deps, "minimal-test", "1.0.0")
    b = generate_sbom(deps, "minimal-test", "1.0.0")
    assert _strip_volatile(a) == _strip_volatile(b)
    assert a["serialNumber"] != b["serialNumber"]


def test_dependencies_root_first_then_sorted_refs() -> None:
    deps = parse_lockfile(FIXTURES / "minimal.json")
    bom = generate_sbom(deps, "minimal-test", "1.0.0")
    root_ref = bom["metadata"]["component"]["bom-ref"]
    refs = [d["ref"] for d in bom["dependencies"]]
    assert refs[0] == root_ref
    assert refs == [root_ref] + sorted(refs[1:])


def test_depends_on_sorted() -> None:
    deps = [
        Dependency(
            name="z",
            version="1.0.0",
            ecosystem="npm",
            direct=True,
            path=[],
            parents=["root"],
        ),
        Dependency(
            name="a",
            version="1.0.0",
            ecosystem="npm",
            direct=True,
            path=[],
            parents=["root"],
        ),
    ]
    bom = generate_sbom(deps, "p", "1.0.0")
    root_entry = bom["dependencies"][0]
    assert root_entry["dependsOn"] == ["pkg:npm/a@1.0.0", "pkg:npm/z@1.0.0"]


def test_all_component_purls_are_pkg_npm() -> None:
    deps = parse_lockfile(FIXTURES / "real-world.json")
    bom = generate_sbom(deps, "lockfiles", "1.0.0")
    for c in bom["components"]:
        assert c["purl"].startswith("pkg:npm/")


def test_real_world_component_count_matches_parser() -> None:
    lock_path = FIXTURES / "real-world.json"
    deps = parse_lockfile(lock_path)
    bom = generate_sbom(deps, "fixture-root", "1.0.0")
    assert len(bom["components"]) == len(deps) == 50
    assert len(bom["dependencies"]) == 1 + len(bom["components"]) == 51


@pytest.mark.skipif(shutil.which("cyclonedx") is None, reason="cyclonedx CLI not installed")
def test_real_world_sbom_validates_against_cyclonedx_spec(tmp_path: Path) -> None:
    deps = parse_lockfile(FIXTURES / "real-world.json")
    bom = generate_sbom(deps, "fixture-root", "1.0.0")
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    cyclonedx = shutil.which("cyclonedx")
    assert cyclonedx is not None
    result = subprocess.run(
        [
            cyclonedx,
            "validate",
            "--input-file",
            str(sbom_path),
            "--input-format",
            "json",
            "--input-version",
            "v1_7",
            "--fail-on-errors",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
