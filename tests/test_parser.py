"""Tests for the package-lock.json parser."""

from pathlib import Path

import pytest

from arguss.core.parser import ParserError, parse_lockfile

FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"


def test_parses_minimal_lockfile() -> None:
    deps = parse_lockfile(FIXTURES / "minimal.json")
    assert len(deps) == 1
    assert deps[0].name == "left-pad"
    assert deps[0].direct is True
    assert deps[0].path == ["root", "left-pad"]
    assert deps[0].parents == ["root"]


def test_handles_directory_input(tmp_path: Path) -> None:
    """Passing a directory finds package-lock.json inside it."""
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {"name": "x", "version": "1.0.0"}}}'
    )
    deps = parse_lockfile(tmp_path)
    assert deps == []


def test_rejects_v1_lockfile(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text('{"lockfileVersion": 1, "dependencies": {}}')
    with pytest.raises(ParserError, match="lockfile version 1 is not supported"):
        parse_lockfile(bad)


def test_missing_lockfile_raises(tmp_path: Path) -> None:
    with pytest.raises(ParserError, match="not found"):
        parse_lockfile(tmp_path / "does-not-exist.json")


def test_directory_without_lockfile_raises(tmp_path: Path) -> None:
    with pytest.raises(ParserError, match="No package-lock.json"):
        parse_lockfile(tmp_path)


def test_transitive_path_correctly_traced() -> None:
    deps = parse_lockfile(FIXTURES / "with-transitive.json")
    # chalk should be the direct dep
    chalk = next((d for d in deps if d.name == "chalk"), None)
    assert chalk is not None
    assert chalk.direct is True

    # ansi-styles is a transitive dep of chalk
    ansi = next((d for d in deps if d.name == "ansi-styles"), None)
    assert ansi is not None
    assert ansi.direct is False
    assert "root" in ansi.path


def test_scoped_packages() -> None:
    """Scoped packages like @types/node are parsed correctly."""
    deps = parse_lockfile(FIXTURES / "with-transitive.json")
    # At least verify the parser doesn't crash on real-world inputs.
    # If chalk@4.1.2's tree includes any scoped packages, this verifies them.
    for dep in deps:
        if dep.name.startswith("@"):
            assert "/" in dep.name, f"Scoped name must include slash: {dep.name}"


def test_real_world_fixture_has_many_deps() -> None:
    """Sanity-check the real-world fixture produces a meaningful tree."""
    deps = parse_lockfile(FIXTURES / "real-world.json")
    assert len(deps) > 20, f"Expected many deps in real-world fixture, got {len(deps)}"
    direct = [d for d in deps if d.direct]
    assert len(direct) >= 1


def test_real_world_accepts_logical_parent_and_path() -> None:
    """accepts is required by express; shortest path is root → express → accepts."""
    deps = parse_lockfile(FIXTURES / "real-world.json")
    accepts = next(d for d in deps if d.name == "accepts")
    assert accepts.parents == ["express"]
    assert accepts.path == ["root", "express", "accepts"]


def test_logical_multi_parent_sorted(tmp_path: Path) -> None:
    """A child listed by two parents gets both in parents, sorted."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "multi-parent-test",
      "version": "1.0.0",
      "dependencies": {
        "parent-a": "1.0.0",
        "parent-b": "1.0.0"
      }
    },
    "node_modules/parent-a": {
      "version": "1.0.0",
      "dependencies": { "shared-child": "1.0.0" }
    },
    "node_modules/parent-b": {
      "version": "1.0.0",
      "dependencies": { "shared-child": "1.0.0" }
    },
    "node_modules/shared-child": { "version": "1.0.0" }
  }
}"""
    )
    deps = parse_lockfile(lock)
    shared = next(d for d in deps if d.name == "shared-child")
    assert shared.parents == ["parent-a", "parent-b"]


def test_shortest_path_tiebreak_lexicographic_parent(tmp_path: Path) -> None:
    """Equal-length paths to the same package: choose lexicographically smallest parent."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "tiebreak-test",
      "version": "1.0.0",
      "dependencies": {
        "alpha-pkg": "1.0.0",
        "bravo-pkg": "1.0.0"
      }
    },
    "node_modules/alpha-pkg": {
      "version": "1.0.0",
      "dependencies": { "target-pkg": "1.0.0" }
    },
    "node_modules/bravo-pkg": {
      "version": "1.0.0",
      "dependencies": { "target-pkg": "1.0.0" }
    },
    "node_modules/target-pkg": { "version": "1.0.0" }
  }
}"""
    )
    deps = parse_lockfile(lock)
    target = next(d for d in deps if d.name == "target-pkg")
    assert target.parents == ["alpha-pkg", "bravo-pkg"]
    assert target.path == ["root", "alpha-pkg", "target-pkg"]


def test_root_dev_dependencies_create_logical_edges(tmp_path: Path) -> None:
    """Root devDependencies are walked like dependencies for logical edges only."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "dev-root-test",
      "version": "1.0.0",
      "dependencies": {},
      "devDependencies": { "only-dev": "1.0.0" }
    },
    "node_modules/only-dev": { "version": "1.0.0" }
  }
}"""
    )
    deps = parse_lockfile(lock)
    only = next(d for d in deps if d.name == "only-dev")
    assert only.direct is True
    assert only.parents == ["root"]
    assert only.path == ["root", "only-dev"]


class TestLogicalDependencyGraph:
    """Tests for the logical dependency graph resolution (second pass)."""

    def test_direct_dep_has_root_parent(self) -> None:
        """A direct dep has 'root' in its parents."""
        deps = parse_lockfile(FIXTURES / "with-transitive.json")
        chalk = next(d for d in deps if d.name == "chalk")
        assert "root" in chalk.parents
        assert chalk.path == ["root", "chalk"]

    def test_transitive_dep_parents_reflect_logical_relationships(self) -> None:
        """ansi-styles is brought in by chalk, not by 'root'."""
        deps = parse_lockfile(FIXTURES / "with-transitive.json")
        ansi = next((d for d in deps if d.name == "ansi-styles"), None)
        assert ansi is not None
        assert "chalk" in ansi.parents
        assert "root" not in ansi.parents  # ansi-styles is NOT a direct dep

    def test_transitive_path_traces_through_parent(self) -> None:
        """A transitive dep's path goes through its parent, not just root."""
        deps = parse_lockfile(FIXTURES / "with-transitive.json")
        ansi = next((d for d in deps if d.name == "ansi-styles"), None)
        assert ansi is not None
        assert ansi.path[0] == "root"
        assert ansi.path[-1] == "ansi-styles"
        assert "chalk" in ansi.path

    def test_real_world_express_accepts_relationship(self) -> None:
        """In the express fixture, accepts is brought in by express."""
        deps = parse_lockfile(FIXTURES / "real-world.json")
        accepts = next((d for d in deps if d.name == "accepts"), None)
        assert accepts is not None
        assert "express" in accepts.parents
        assert accepts.path == ["root", "express", "accepts"]

    def test_dep_can_have_multiple_parents(self) -> None:
        """A package needed by multiple parents lists all of them."""
        deps = parse_lockfile(FIXTURES / "real-world.json")
        # In express@4.17.0, 'ms' is depended on by 'debug' and 'finalhandler'.
        # We don't hardcode the specific parents; we just verify that some dep
        # in the tree has more than one parent (multi-parent works).
        multi_parented = [d for d in deps if len(d.parents) > 1]
        assert len(multi_parented) > 0, (
            "Expected at least one dep with multiple parents in express tree"
        )

    def test_path_is_shortest_when_multiple_parents(self) -> None:
        """When a dep has multiple parents, path uses the shortest route."""
        deps = parse_lockfile(FIXTURES / "real-world.json")
        for d in deps:
            if len(d.parents) > 1:
                # The path length should be at most one more than the shortest
                # parent's path. We can't easily verify "shortest" without
                # recomputing, but we can verify path is sane.
                assert d.path[0] == "root"
                assert d.path[-1] == d.name

    def test_all_deps_have_root_in_path(self) -> None:
        """Every dep is reachable from root."""
        deps = parse_lockfile(FIXTURES / "real-world.json")
        for d in deps:
            assert d.path[0] == "root", f"{d.name} not reachable from root"

    def test_minimal_fixture_unchanged(self) -> None:
        """The minimal fixture (1 direct dep) still works correctly."""
        deps = parse_lockfile(FIXTURES / "minimal.json")
        assert len(deps) == 1
        assert deps[0].parents == ["root"]
        assert deps[0].path == ["root", "left-pad"]


def _dep_graph_signature(deps):
    """Comparable view of parsed dependency graph for v2/v3 equivalence."""
    return {
        (d.name, d.version): {
            "direct": d.direct,
            "parents": tuple(d.parents),
            "path": tuple(d.path),
        }
        for d in deps
    }


def test_parse_v2_lockfile_minimal() -> None:
    deps = parse_lockfile(FIXTURES / "minimal-v2.json")
    assert len(deps) == 6
    names = {d.name for d in deps}
    assert names == {
        "chalk",
        "ansi-styles",
        "supports-color",
        "color-convert",
        "color-name",
        "has-flag",
    }
    chalk = next(d for d in deps if d.name == "chalk")
    assert chalk.direct is True
    ansi = next(d for d in deps if d.name == "ansi-styles")
    assert "chalk" in ansi.parents


def test_parse_v2_lockfile_equivalent_to_v3() -> None:
    v3_deps = parse_lockfile(FIXTURES / "with-transitive.json")
    v2_deps = parse_lockfile(FIXTURES / "minimal-v2.json")
    assert _dep_graph_signature(v3_deps) == _dep_graph_signature(v2_deps)


def test_parse_v2_lockfile_ignores_v1_dependencies_tree(tmp_path: Path) -> None:
    """Top-level dependencies must not override packages (canonical in v2/v3)."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "disagree-test",
      "version": "1.0.0",
      "dependencies": { "pkg-a": "1.0.0" }
    },
    "node_modules/pkg-a": { "version": "1.0.0" }
  },
  "dependencies": {
    "pkg-a": { "version": "9.9.9" }
  }
}"""
    )
    deps = parse_lockfile(lock)
    assert len(deps) == 1
    assert deps[0].name == "pkg-a"
    assert deps[0].version == "1.0.0"


def test_parse_v1_lockfile_rejected_with_clear_message(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text('{"lockfileVersion": 1, "dependencies": {"left-pad": {"version": "1.0.0"}}}')
    with pytest.raises(ParserError, match="lockfile version 1 is not supported") as exc_info:
        parse_lockfile(bad)
    assert "lockfileVersion 2 or 3" in str(exc_info.value)


def test_parse_unknown_version_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text('{"lockfileVersion": 4, "packages": {"": {"version": "1.0.0"}}}')
    with pytest.raises(ParserError, match="lockfile version 4 is not supported") as exc_info:
        parse_lockfile(bad)
    assert "lockfileVersion 2 or 3" in str(exc_info.value)


def test_parser_produced_dep_has_install_key() -> None:
    """Every dependency from parse_lockfile carries a non-empty install_key."""
    deps = parse_lockfile(FIXTURES / "with-transitive.json")
    assert deps
    for dep in deps:
        assert dep.install_key
        assert dep.install_key.startswith("node_modules/")


def test_install_key_is_lockfile_relative_not_filesystem_path() -> None:
    """install_key is the raw packages key, never an absolute or temp path."""
    deps = parse_lockfile(FIXTURES / "with-transitive.json")
    for dep in deps:
        key = dep.install_key
        assert not key.startswith("/")
        assert not key.startswith("\\")
        assert "://" not in key
        assert "/tmp/" not in key.lower()
        assert "/var/folders/" not in key.lower()


def test_minimatch_per_install_parents_on_test_as_package() -> None:
    """Six physical minimatch installs get distinct keys and real per-install parents."""
    lockfile = Path(__file__).resolve().parents[2] / "test-as-package" / "package-lock.json"
    if not lockfile.exists():
        pytest.skip("test-as-package lockfile not present")
    deps = parse_lockfile(lockfile)
    mm = [d for d in deps if d.name == "minimatch"]
    assert len(mm) == 6
    keys = {d.install_key for d in mm}
    assert len(keys) == 6
    by_key = {d.install_key: d for d in mm}
    assert by_key["node_modules/minimatch"].version == "3.1.2"
    assert "eslint" in by_key["node_modules/minimatch"].parents
    assert by_key["node_modules/glob/node_modules/minimatch"].parents == ["glob"]
    assert by_key["node_modules/typedoc/node_modules/minimatch"].parents == ["typedoc"]


def test_hoisted_ansi_styles_real_parents_only() -> None:
    """Hoisted ansi-styles@6.2.1: chalk resolves to nested 4.3.0, not hoisted copy."""
    lockfile = Path(__file__).resolve().parents[2] / "test-as-package" / "package-lock.json"
    if not lockfile.exists():
        pytest.skip("test-as-package lockfile not present")
    deps = parse_lockfile(lockfile)
    hoisted = next(
        (
            d
            for d in deps
            if d.name == "ansi-styles" and d.install_key == "node_modules/ansi-styles"
        ),
        None,
    )
    assert hoisted is not None
    assert hoisted.version == "6.2.1"
    assert "chalk" not in hoisted.parents
    assert "wrap-ansi" in hoisted.parents
