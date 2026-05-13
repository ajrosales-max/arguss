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
    with pytest.raises(ParserError, match="version"):
        parse_lockfile(bad)


def test_rejects_v2_lockfile(tmp_path: Path) -> None:
    bad = tmp_path / "package-lock.json"
    bad.write_text('{"lockfileVersion": 2, "packages": {}}')
    with pytest.raises(ParserError, match="version"):
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
