"""Tests for APScheduler wiring in the FastAPI app lifespan."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from arguss.api import create_app
from arguss.jobs.top_1000_sweep import run_sweep
from arguss.settings import settings


def test_lifespan_does_not_create_scheduler_when_disabled() -> None:
    with patch("apscheduler.schedulers.background.BackgroundScheduler") as mock_bs:
        app = create_app()
        with TestClient(app) as client:
            response = client.get("/health")

    assert response.status_code == 200
    mock_bs.assert_not_called()


def test_lifespan_registers_daily_sweep_job(enable_top_1000_scheduler) -> None:
    mock_scheduler = MagicMock()
    mock_scheduler.get_jobs.return_value = [MagicMock(id="top_1000_sweep")]

    with (
        patch(
            "apscheduler.schedulers.background.BackgroundScheduler",
            return_value=mock_scheduler,
        ) as mock_bs,
        patch("arguss.jobs.top_1000_sweep.run_sweep") as mock_run_sweep,
    ):
        app = create_app()
        with TestClient(app) as client:
            assert client.app.state.scheduler is mock_scheduler

    mock_bs.assert_called_once()
    mock_scheduler.add_job.assert_called_once_with(
        run_sweep,
        "cron",
        hour=settings.top_1000_sweep_cron_hour,
        args=[settings.db_path],
        kwargs={"latest": True},
        id="top_1000_sweep",
    )
    mock_scheduler.start.assert_called_once()
    mock_scheduler.shutdown.assert_called_once_with(wait=False)
    mock_run_sweep.assert_not_called()
