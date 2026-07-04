"""Mode C copy honesty: glossary stays conservative; action path describes optional auto-merge."""

from __future__ import annotations

from pathlib import Path

from arguss.web.results_context import GLOSSARY_SHORT_DESCRIPTIONS


def _read(path: str) -> str:
    return Path(path).read_text()


def test_glossary_short_description_pr_only_not_merge() -> None:
    desc = GLOSSARY_SHORT_DESCRIPTIONS["auto-merge"]
    assert "pull request" in desc.lower() or "opens" in desc.lower()
    assert "merges if green" not in desc.lower()
    assert "does not merge" in desc.lower()


def test_glossary_section_mode_c_opens_pr_not_merges() -> None:
    text = _read("arguss/web/templates/partials/_glossary_section.html")
    auto_merge_block = text.split("glossary-auto-merge")[1].split("</div>")[0]
    assert "pull request" in auto_merge_block.lower()
    assert "merges if green" not in auto_merge_block.lower()
    assert "does not merge" in auto_merge_block.lower()


def test_how_it_works_mode_c_no_merge_claim() -> None:
    text = _read("arguss/web/templates/how_it_works.html")
    assert "does not merge" in text.lower()


def test_action_page_describes_optional_auto_merge() -> None:
    text = _read("arguss/web/templates/action.html")
    assert "pull request" in text.lower()
    assert "merges verified upgrades" in text.lower()
    assert "does not merge" not in text.lower()


def test_authorize_page_pr_only_copy() -> None:
    text = _read("arguss/web/templates/authorize.html")
    assert "open pull requests" in text.lower()
    assert "merge" not in text.lower().replace("auto-merge", "").replace("auto_merge", "")
