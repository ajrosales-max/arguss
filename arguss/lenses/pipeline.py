"""Pipeline configuration lens — GitHub Actions (zizmor) + test reality heuristics.

The :class:`PipelineLens` ``scan()`` interface accepts a dependency list for
uniformity with other lenses, but **pipeline analysis is per-repository**, not
per-dependency. Callers pass ``repo_path`` at construction; ``deps`` is ignored.

Two outputs mirror the trust lens pattern:

- **subscore** (0–100): severity-weighted zizmor findings + test-reality penalty,
  consumed by the existing PRS / dashboard path.
- **test_reality.safe_to_auto_merge**: binary veto for the Week 6 fix-confidence
  engine (all four conditions must hold).
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from arguss.core.models import (
    Dependency,
    Finding,
    LensScore,
    PipelineSnapshot,
    Severity,
    TestReality,
    ZizmorFinding,
    ZizmorSeverity,
)
from arguss.lenses._zizmor_client import ZizmorClient

_LOG = logging.getLogger(__name__)

_TEST_INVOCATION_RE = re.compile(
    r"\b(npm|yarn|pnpm|bun)\s+(?:run\s+)?test\b",
    re.IGNORECASE,
)

_NO_OP_ECHO_NO_TEST_RE = re.compile(
    r"echo\b.*\bno\s+tests?\b",
    re.IGNORECASE,
)

_TEST_FILE_SUFFIXES = (
    ".test.js",
    ".test.jsx",
    ".test.ts",
    ".test.tsx",
    ".test.mjs",
    ".spec.js",
    ".spec.jsx",
    ".spec.ts",
    ".spec.tsx",
    ".spec.mjs",
)

_TEST_DIR_NAMES = frozenset({"test", "tests", "__tests__", "spec"})

_SKIP_WALK_DIRS = frozenset({"node_modules", "dist", "build", ".git", "coverage"})

_MAX_TEST_FILE_WALK = 1000

_PIPELINE_SUBSCORE_WEIGHTS: dict[ZizmorSeverity, int] = {
    "informational": 2,
    "low": 5,
    "medium": 15,
    "high": 30,
}

_TEST_REALITY_PENALTY = 40
_SUBSCORE_CAP = 100

_REASON_NO_PACKAGE_JSON = "no package.json in your submission"
_REASON_NO_TEST_SCRIPT = "package.json has no scripts.test"
_REASON_NOOP_SCRIPT = "test script is a no-op (matches sentinel pattern)"
_REASON_NO_TEST_FILES = "no test files in your project"
_REASON_NO_WORKFLOWS_DIR = "no .github/workflows in your project"
_REASON_WORKFLOW_NO_TESTS = "no GitHub Actions workflow runs tests"


def _has_test_script(package_json: dict[str, Any] | None) -> tuple[bool, str]:
    """``package_json`` has ``scripts.test`` as a non-empty string."""
    if package_json is None:
        return False, ""
    scripts = package_json.get("scripts")
    if not isinstance(scripts, dict):
        return False, ""
    raw = scripts.get("test")
    if not isinstance(raw, str):
        return False, ""
    stripped = raw.strip()
    return bool(stripped), stripped


def _test_script_is_no_op(test_script: str) -> bool:
    """True for known no-op sentinel patterns (conservative)."""
    s = test_script.strip()
    if not s:
        return True
    lower = s.lower()
    if lower == "true":
        return True
    if re.fullmatch(r"exit\s+0", lower):
        return True
    return bool(_NO_OP_ECHO_NO_TEST_RE.search(s))


def _has_test_files(repo_path: Path) -> tuple[bool, int]:
    """Return ``(has_any, count)`` for test-like files under ``repo_path``."""
    count = 0
    for dirpath, _dirnames, filenames in _walk_repo(repo_path):
        rel_dir = Path(dirpath).relative_to(repo_path)
        parts = rel_dir.parts
        in_test_dir = bool(parts) and parts[0] in _TEST_DIR_NAMES

        for name in filenames:
            if count >= _MAX_TEST_FILE_WALK:
                return count > 0, count
            if in_test_dir:
                count += 1
                continue
            lower = name.lower()
            if any(lower.endswith(suffix) for suffix in _TEST_FILE_SUFFIXES):
                count += 1

    return count > 0, count


def _walk_repo(repo_path: Path) -> Any:
    """Walk ``repo_path``, pruning ignored directories."""
    for dirpath, dirnames, filenames in os.walk(repo_path, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_WALK_DIRS]
        yield dirpath, dirnames, filenames


def _workflow_runs_tests(workflows_dir: Path) -> bool:
    """True if any workflow step ``run`` invokes a package-manager test command."""
    if not workflows_dir.is_dir():
        return False

    for pattern in ("*.yml", "*.yaml"):
        for wf_path in workflows_dir.glob(pattern):
            if not wf_path.is_file():
                continue
            try:
                text = wf_path.read_text(encoding="utf-8")
            except OSError:
                continue
            if _TEST_INVOCATION_RE.search(text):
                return True
    return False


def _load_package_json(repo_path: Path) -> dict[str, Any] | None:
    pkg_path = repo_path / "package.json"
    if not pkg_path.is_file():
        return None
    try:
        parsed: Any = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _discover_workflow_files(repo_path: Path) -> tuple[str, ...]:
    wf_dir = repo_path / ".github" / "workflows"
    if not wf_dir.is_dir():
        return ()
    paths: list[str] = []
    for pattern in ("*.yml", "*.yaml"):
        for wf in wf_dir.glob(pattern):
            if wf.is_file():
                paths.append(wf.relative_to(repo_path).as_posix())
    return tuple(sorted(paths))


def _build_test_reality(repo_path: Path, package_json: dict[str, Any] | None) -> TestReality:
    """Assemble test reality flags and human-readable block reasons.

    Reasons are short-circuited: when a parent condition is unobservable (no
    ``package.json``, no ``.github/workflows/`` directory), do not emit child
    reasons that depend on it (e.g. missing ``scripts.test`` or workflow test steps).
    """
    has_files, test_count = _has_test_files(repo_path)
    workflows_dir = repo_path / ".github" / "workflows"
    has_workflows_dir = workflows_dir.is_dir()

    if package_json is None:
        has_script = False
        is_noop = False
    else:
        has_script, test_script = _has_test_script(package_json)
        is_noop = _test_script_is_no_op(test_script) if has_script else False

    wf_runs = _workflow_runs_tests(workflows_dir) if has_workflows_dir else False

    reasons: list[str] = []
    if package_json is None:
        reasons.append(_REASON_NO_PACKAGE_JSON)
    elif not has_script:
        reasons.append(_REASON_NO_TEST_SCRIPT)
    elif is_noop:
        reasons.append(_REASON_NOOP_SCRIPT)

    if not has_files:
        reasons.append(_REASON_NO_TEST_FILES)

    if not has_workflows_dir:
        reasons.append(_REASON_NO_WORKFLOWS_DIR)
    elif not wf_runs:
        reasons.append(_REASON_WORKFLOW_NO_TESTS)

    safe = has_script and not is_noop and has_files and wf_runs
    blocked = tuple(sorted(reasons)) if not safe else ()

    return TestReality(
        has_test_script=has_script,
        test_script_is_no_op=is_noop,
        has_test_files=has_files,
        test_count=test_count,
        workflow_runs_tests=wf_runs,
        safe_to_auto_merge=safe,
        reasons_blocked=blocked,
    )


def _compute_subscore(findings: list[ZizmorFinding], test_reality: TestReality) -> int:
    """Severity-weighted zizmor sum plus test-reality penalty, capped at 100."""
    weights_sum = sum(_PIPELINE_SUBSCORE_WEIGHTS[f.severity] for f in findings)
    penalty = _TEST_REALITY_PENALTY if not test_reality.safe_to_auto_merge else 0
    return min(weights_sum + penalty, _SUBSCORE_CAP)


def fetch_pipeline_snapshot(repo_path: Path) -> PipelineSnapshot:
    """Build a :class:`~arguss.core.models.PipelineSnapshot` for a repository.

    Raises :exc:`ZizmorClientError` only when the zizmor binary fails.
    """
    root = repo_path.resolve()
    workflow_files = _discover_workflow_files(root)
    workflows_dir = root / ".github" / "workflows"

    zizmor_findings: list[ZizmorFinding] = []
    if workflows_dir.is_dir() and (
        list(workflows_dir.glob("*.yml")) or list(workflows_dir.glob("*.yaml"))
    ):
        client = ZizmorClient()
        zizmor_findings = client.scan_workflows(workflows_dir)

    package_json = _load_package_json(root)
    test_reality = _build_test_reality(root, package_json)
    subscore = _compute_subscore(zizmor_findings, test_reality)

    return PipelineSnapshot(
        repo_path=str(root),
        workflow_files=workflow_files,
        zizmor_findings=tuple(zizmor_findings),
        test_reality=test_reality,
        subscore=subscore,
    )


def _zizmor_to_lens_severity(severity: ZizmorSeverity) -> Severity:
    if severity == "high":
        return "high"
    if severity == "medium":
        return "medium"
    return "low"


def _pipeline_dep(name: str) -> Dependency:
    return Dependency(
        name=name,
        version="N/A",
        ecosystem="github-actions",
        direct=True,
    )


def _finding_from_zizmor(z: ZizmorFinding) -> Finding:
    return Finding(
        dependency=_pipeline_dep(f".github/workflows/{z.file}"),
        lens="pipeline",
        severity=_zizmor_to_lens_severity(z.severity),
        score=float(_PIPELINE_SUBSCORE_WEIGHTS[z.severity]),
        title=z.description,
        description=f"{z.ident} at {z.file}:{z.line}:{z.column} — {z.annotation}",
        remediation=f"See zizmor audit: {z.audit_url}",
        source_url=z.audit_url,
    )


def _finding_from_test_reality(tr: TestReality) -> Finding:
    reasons = "; ".join(tr.reasons_blocked)
    return Finding(
        dependency=_pipeline_dep("ci-test-reality"),
        lens="pipeline",
        severity="high",
        score=float(_TEST_REALITY_PENALTY),
        title="CI does not verify changes (test reality)",
        description=reasons or "Test reality checks failed.",
        remediation=(
            "Add a non–no-op scripts.test, test files under the repo, "
            "and a workflow step that runs npm/yarn/pnpm/bun test."
        ),
        source_url=None,
    )


def _lens_score_from_snapshot(snapshot: PipelineSnapshot) -> LensScore:
    findings = [_finding_from_zizmor(z) for z in snapshot.zizmor_findings]
    if not snapshot.test_reality.safe_to_auto_merge:
        findings.append(_finding_from_test_reality(snapshot.test_reality))
    return LensScore(
        lens="pipeline",
        score=float(snapshot.subscore),
        findings=findings,
    )


def _stub_lens_score() -> LensScore:
    """Placeholder when no repository root is available."""
    fake_dep = Dependency(
        name=".github/workflows/ci.yml",
        version="N/A",
        ecosystem="github-actions",
        direct=True,
    )
    fake_finding = Finding(
        dependency=fake_dep,
        lens="pipeline",
        severity="medium",
        score=50.0,
        title="Unpinned action reference",
        description=(
            "Pipeline lens stub: no repository root was provided. "
            "Invoke scan against a project directory for real pipeline analysis."
        ),
        remediation="Pin actions to a specific SHA",
        source_url=None,
    )
    return LensScore(lens="pipeline", score=50.0, findings=[fake_finding])


class PipelineLens:
    """Pipeline lens: workflow misconfigurations (zizmor) + test reality."""

    def __init__(self, repo_path: Path | None = None) -> None:
        self._repo_path = repo_path.resolve() if repo_path is not None else None

    def scan(self, deps: list[Dependency]) -> LensScore:
        """Return pipeline lens score and findings.

        ``deps`` is ignored; analysis uses ``repo_path`` from construction.
        """
        del deps
        if self._repo_path is None:
            return _stub_lens_score()
        snapshot = fetch_pipeline_snapshot(self._repo_path)
        return _lens_score_from_snapshot(snapshot)
