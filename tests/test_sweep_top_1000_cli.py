"""Tests for the sweep-top-1000 CLI command."""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from arguss.cli import app


def test_sweep_top_1000_invokes_run_sweep_with_latest() -> None:
    with patch("arguss.cli.run_sweep", return_value=42) as mock_sweep:
        result = CliRunner().invoke(app, ["sweep-top-1000"])

    assert result.exit_code == 0, result.output
    mock_sweep.assert_called_once()
    assert mock_sweep.call_args.kwargs["latest"] is True
    assert "42" in result.output


def test_sweep_top_1000_no_latest_flag() -> None:
    with patch("arguss.cli.run_sweep", return_value=10) as mock_sweep:
        result = CliRunner().invoke(app, ["sweep-top-1000", "--no-latest"])

    assert result.exit_code == 0, result.output
    mock_sweep.assert_called_once()
    assert mock_sweep.call_args.kwargs["latest"] is False
