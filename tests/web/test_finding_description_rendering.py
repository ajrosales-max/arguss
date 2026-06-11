"""Tests for OSV markdown description rendering and /select output."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from arguss.api import app as api_app
from arguss.web.results_context import render_description_html
from tests.test_candidate_selection_ui import _cached_scan_dict
from tests.web.conftest import open_wizard_select
from tests.web.test_candidate_findings_drilldown import _entry, _rf


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _scan_for_description(description: str) -> dict:
    finding = _rf("GHSA-desc-001", 8.2)
    finding["description"] = description
    return _cached_scan_dict(entries=[_entry("pkg-desc", [finding])])


def test_description_with_markdown_headings_renders_as_html_headings() -> None:
    html = render_description_html("### Overview")
    assert html is not None
    assert "<h3>Overview</h3>" in html


def test_description_links_have_safe_attributes() -> None:
    html = render_description_html("[Arguss](https://example.com)")
    assert html is not None
    assert '<a href="https://example.com"' in html
    assert 'rel="noopener noreferrer"' in html
    assert 'target="_blank"' in html


def test_description_strips_disallowed_tags() -> None:
    html = render_description_html("# Top heading")
    assert html is not None
    assert "<h1" not in html
    assert "Top heading" in html


def test_description_strips_script_tags() -> None:
    html = render_description_html("<script>alert(1)</script>Safe")
    assert html is not None
    assert "<script" not in html.lower()
    assert "</script>" not in html.lower()


def test_description_strips_iframe_tags() -> None:
    html = render_description_html('<iframe src="https://example.com"></iframe>Safe')
    assert html is not None
    assert "<iframe" not in html.lower()
    assert "</iframe>" not in html.lower()


def test_description_strips_inline_event_handlers() -> None:
    html = render_description_html('<a href="https://example.com" onclick="alert(1)">Click</a>')
    assert html is not None
    # No executable inline event handlers should remain on rendered tags.
    assert re.search(r"<[^>]+\\son[a-z]+=", html, re.IGNORECASE) is None


def test_empty_description_returns_none() -> None:
    assert render_description_html("") is None
    assert render_description_html("   \n\t") is None
    assert render_description_html(None) is None


def test_description_renders_lists() -> None:
    html = render_description_html("- one\n- two")
    assert html is not None
    assert "<ul>" in html
    assert "<li>one</li>" in html
    assert "<li>two</li>" in html


def test_description_renders_code_spans() -> None:
    html = render_description_html("Use `npm audit` before merging.")
    assert html is not None
    assert "<code>npm audit</code>" in html


def test_description_wrap_includes_truncate_attribute(client: TestClient, wizard_db) -> None:
    scan = _scan_for_description("Paragraph one.\n\nParagraph two.")
    response = open_wizard_select(client, "desc-truncate", scan, wizard_db=wizard_db)

    assert response.status_code == 200
    assert 'class="finding-description" data-truncated="true"' in response.text


def test_description_toggle_button_starts_hidden(client: TestClient, wizard_db) -> None:
    scan = _scan_for_description("A long advisory description.")
    response = open_wizard_select(client, "desc-toggle-hidden", scan, wizard_db=wizard_db)

    assert response.status_code == 200
    assert 'class="finding-description-toggle btn-text" hidden' in response.text


def test_description_html_marked_safe_in_template(client: TestClient, wizard_db) -> None:
    scan = _scan_for_description("### Advisory heading\n\nParagraph body.")
    response = open_wizard_select(client, "desc-safe-render", scan, wizard_db=wizard_db)

    assert response.status_code == 200
    assert "<h3>Advisory heading</h3>" in response.text
    assert "&lt;h3&gt;Advisory heading&lt;/h3&gt;" not in response.text
