"""Tests for chat system prompt and compact scan context (Steps 1–4)."""

from __future__ import annotations

from typing import Any

from arguss.explanations.chat import _SYSTEM_PROMPT_TEMPLATE, _compact_scan_data
from arguss.web.score_formulas import (
    build_chat_score_mechanics_section,
    format_fix_confidence_formula,
    format_pipeline_prs_input_formula,
    format_prs_formula,
    format_trust_formula,
    format_vulnerability_formula,
    format_zizmor_reference_formula,
)


def _chat_system_prompt() -> str:
    return _SYSTEM_PROMPT_TEMPLATE.format(scan_data="{}")


def _axios_mode_a_scan() -> dict[str, Any]:
    """Mode A axios pattern: zizmor findings, test-reality passes, max-rule CVE."""
    trust_packages = [
        ["axios", "1.6.0", 12],
        ["follow-redirects", "1.15.4", 18],
        ["form-data", "4.0.0", 22],
        ["proxy-from-env", "1.1.0", 25],
        ["mime-types", "2.1.35", 28],
        ["combined-stream", "1.0.8", 30],
        ["asynckit", "0.4.0", 32],
        ["delayed-stream", "1.0.0", 35],
        ["es-set-tostringtag", "2.0.1", 38],
        ["hasown", "2.0.0", 40],
    ]
    return {
        "project_scores": {
            "prs": 79,
            "vulnerability_subscore": 98,
            "trust_subscore": 25,
            "pipeline_subscore": 100,
        },
        "summary": {
            "total_findings": 13,
            "kev_count": 0,
            "max_epss_score": 0.00213,
            "max_epss_cve_id": "CVE-2024-XXXX",
            "max_epss_package": "follow-redirects",
        },
        "executive_summary": "Axios scan summary.",
        "entries": [
            {
                "candidate": {
                    "package": "simple-git",
                    "from_version": "3.0.0",
                    "trust_subscore": 15,
                },
                "finding": {
                    "severity": "high",
                    "cvss_score": 9.8,
                    "cve_id": "CVE-2022-25912",
                    "title": "GHSA-28xr-mwxg-7qcc",
                    "dependency": {"name": "simple-git"},
                },
                "verdict": {"score": 45, "tier": "review_required"},
            },
        ],
        "skipped_findings": [],
        "lens_explain": {
            "pipeline": {
                "workflow_files": [
                    ".github/workflows/ci.yml",
                    ".github/workflows/release.yml",
                    ".github/workflows/pr.yml",
                ],
                "zizmor_counts": {
                    "informational": 0,
                    "low": 0,
                    "medium": 3,
                    "high": 8,
                },
                "zizmor_weighted_sum": 285,
                "test_penalty": 0,
                "subscore": 100,
                "test_reality": {
                    "has_test_script": True,
                    "test_script_is_no_op": False,
                    "has_test_files": True,
                    "test_count": 42,
                    "workflow_runs_tests": True,
                    "safe_to_auto_merge": True,
                    "reasons_blocked": [],
                },
            },
            "vulnerability": {
                "findings": [
                    {
                        "advisory_id": "GHSA-28xr-mwxg-7qcc",
                        "package": "simple-git",
                        "cvss_score": 9.8,
                        "normalized_score": 98.0,
                    }
                ]
            },
            "trust": {
                "packages": [{"name": n, "version": v, "subscore": s} for n, v, s in trust_packages]
            },
        },
    }


def test_prompt_contains_risk_score_direction() -> None:
    prompt = _chat_system_prompt()
    assert "Risk scores (higher = MORE risk" in prompt
    assert "0–100 where higher means MORE project risk" in prompt


def test_prompt_contains_fix_confidence_direction() -> None:
    prompt = _chat_system_prompt()
    assert "Fix-confidence scores (higher = SAFER" in prompt
    assert "higher means safer to auto-merge" in prompt


def test_prompt_contains_formula_strings_from_score_formulas() -> None:
    prompt = _chat_system_prompt()
    assert format_prs_formula() in prompt
    assert format_vulnerability_formula() in prompt
    assert format_trust_formula() in prompt
    assert format_zizmor_reference_formula() in prompt
    assert format_pipeline_prs_input_formula() in prompt
    assert format_fix_confidence_formula() in prompt
    assert build_chat_score_mechanics_section() in prompt


def test_prompt_never_invent_and_say_so_if_missing() -> None:
    prompt = _chat_system_prompt()
    assert "Never invent counts, mechanics, or attributions" in prompt
    assert "If the scan context lacks the data needed to answer, say so" in prompt
    assert "Do not invent findings, packages" in prompt


def test_compact_payload_axios_lens_breakdowns() -> None:
    compact = _compact_scan_data(_axios_mode_a_scan())
    lb = compact["lens_breakdowns"]

    pipe = lb["pipeline"]
    assert pipe["workflow_file_count"] == 3
    assert pipe["zizmor_counts"] == {
        "informational": 0,
        "low": 0,
        "medium": 3,
        "high": 8,
    }
    assert pipe["zizmor_weighted_sum"] == 285
    assert pipe["test_reality"]["test_file_count"] == 42
    assert pipe["test_reality"]["test_script_in_package_json"] == "Pass"

    vuln = lb["vulnerability"]
    assert vuln["max_rule_attribution"]["package"] == "simple-git"
    assert vuln["max_rule_attribution"]["cvss_score"] == 9.8
    assert vuln["finding_counts_by_severity"]["critical"] == 1
    assert vuln["finding_counts_by_severity"]["high"] == 0
    assert vuln["kev_count"] == 0
    assert vuln["max_epss"] == 0.00213
    assert not isinstance(vuln["kev_count"], dict)

    trust = lb["trust"]
    assert len(trust["top_10"]) == 10
    assert trust["top_10"][0] == ["axios", "1.6.0", 12]
    assert trust["mean_of_top_subscores"] == 28


def test_compact_payload_mode_b_pipeline_not_applicable() -> None:
    scan: dict[str, Any] = {
        "project_scores": {"pipeline_subscore": 40},
        "summary": {"kev_count": 0},
        "entries": [],
        "lens_explain": {"pipeline": {"workflow_files": []}},
    }
    pipe = _compact_scan_data(scan)["lens_breakdowns"]["pipeline"]
    assert pipe["workflow_file_count"] == 0
    assert pipe["zizmor"] == "not_applicable"
    assert pipe["test_reality"] == "not_applicable"
    assert pipe["prs_pipeline_subscore"] == 40
