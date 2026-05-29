"""OpenSSF Scorecard client.

Fetches per-package engineering hygiene scores from the public Scorecard
API. Display-only signal — does not influence fix-confidence or any decision.

Fail-soft: any HTTP/network failure or 404 returns None. Callers treat
None as 'no Scorecard available' and render gracefully.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from arguss.core.cache import Cache
from arguss.settings import settings

logger = logging.getLogger(__name__)

_SCORECARD_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_SCORECARD_CACHE_TTL_HOURS = 24 * 7  # 7 days
_SCORECARD_MISS_CACHE_TTL_HOURS = 24
_CACHE_SOURCE = "scorecard"

_TRANSIENT_HTTPX_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.PoolTimeout,
)


@dataclass(frozen=True)
class ScorecardCheck:
    name: str
    score: int
    reason: str


@dataclass(frozen=True)
class ScorecardResult:
    score: float
    date: str
    checks: tuple[ScorecardCheck, ...]

    def top_concerns(self, n: int = 3) -> list[str]:
        """Return up to N lowest-scoring checks as ``'Name (score)'`` strings."""
        scored = [c for c in self.checks if c.score >= 0]
        worst = sorted(scored, key=lambda c: c.score)[:n]
        return [f"{c.name} ({c.score})" for c in worst]


def _cache_key(owner: str, repo: str) -> str:
    return f"scorecard:{owner}/{repo}"


def _parse_float_score(raw: Any) -> float | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        try:
            return float(raw)
        except ValueError:
            return None
    return None


def _parse_check_score(raw: Any) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _parse_response(payload: dict[str, Any]) -> ScorecardResult | None:
    raw_score = payload.get("score")
    raw_date = payload.get("date")
    if not isinstance(raw_date, str) or not raw_date:
        return None
    score = _parse_float_score(raw_score)
    if score is None:
        return None

    checks_raw = payload.get("checks")
    if not isinstance(checks_raw, list):
        return None

    checks: list[ScorecardCheck] = []
    for item in checks_raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        reason = item.get("reason")
        check_score = _parse_check_score(item.get("score"))
        if not isinstance(name, str) or not name or check_score is None:
            continue
        if not isinstance(reason, str):
            reason = ""
        checks.append(ScorecardCheck(name=name, score=check_score, reason=reason))

    return ScorecardResult(score=score, date=raw_date, checks=tuple(checks))


def _result_to_cache_payload(result: ScorecardResult) -> dict[str, Any]:
    return {
        "score": result.score,
        "date": result.date,
        "checks": [{"name": c.name, "score": c.score, "reason": c.reason} for c in result.checks],
    }


def _parse_cached_payload(cached: dict[str, Any]) -> ScorecardResult | None:
    if cached.get("absent") is True:
        return None
    raw_score = cached.get("score")
    raw_date = cached.get("date")
    if not isinstance(raw_date, str):
        return None
    score = _parse_float_score(raw_score)
    if score is None:
        return None
    checks_raw = cached.get("checks")
    if not isinstance(checks_raw, list):
        return None
    checks: list[ScorecardCheck] = []
    for item in checks_raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        reason = item.get("reason")
        check_score = _parse_check_score(item.get("score"))
        if not isinstance(name, str) or check_score is None:
            continue
        if not isinstance(reason, str):
            reason = ""
        checks.append(ScorecardCheck(name=name, score=check_score, reason=reason))
    return ScorecardResult(score=score, date=raw_date, checks=tuple(checks))


async def _fetch_scorecard_http(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    api_base: str,
) -> ScorecardResult | None | str:
    """Fetch from API. Returns result, ``None`` for 404, or ``'error'`` on failure."""
    url = f"{api_base.rstrip('/')}/{owner}/{repo}"
    try:
        resp = await client.get(url, timeout=_SCORECARD_TIMEOUT)
    except _TRANSIENT_HTTPX_ERRORS as exc:
        logger.warning("Scorecard fetch failed (transient) for %s/%s: %s", owner, repo, exc)
        return "error"
    except httpx.HTTPError as exc:
        logger.warning("Scorecard fetch failed for %s/%s: %s", owner, repo, exc)
        return "error"

    if resp.status_code == 404:
        logger.info("No Scorecard for github.com/%s/%s (404)", owner, repo)
        return None

    if resp.status_code != 200:
        logger.warning(
            "Scorecard fetch failed for %s/%s: HTTP %s",
            owner,
            repo,
            resp.status_code,
        )
        return "error"

    try:
        payload = resp.json()
    except ValueError as exc:
        logger.warning("Scorecard JSON decode failed for %s/%s: %s", owner, repo, exc)
        return "error"

    if not isinstance(payload, dict):
        logger.warning("Scorecard response malformed for %s/%s", owner, repo)
        return "error"

    parsed = _parse_response(payload)
    if parsed is None:
        logger.warning("Scorecard response parse failed for %s/%s", owner, repo)
        return "error"
    return parsed


async def fetch_scorecard(
    owner: str,
    repo: str,
    *,
    cache: Cache | None = None,
    http_client: httpx.AsyncClient | None = None,
    api_base: str | None = None,
) -> ScorecardResult | None:
    """Fetch a Scorecard for ``github.com/{owner}/{repo}``.

    Returns ``None`` if the repo has no Scorecard (404), the API is unreachable,
    or the response is malformed. Never raises.
    """
    base = api_base if api_base is not None else settings.scorecard_api_base
    key = _cache_key(owner, repo)

    if cache is not None:
        cached = cache.get_api_response(_CACHE_SOURCE, key)
        if cached is not None:
            try:
                return _parse_cached_payload(cached)
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Scorecard cache parse failed for %s/%s: %s", owner, repo, exc)

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(follow_redirects=True)
    try:
        result = await _fetch_scorecard_http(client, owner, repo, base)
    finally:
        if owns_client:
            await client.aclose()

    if result == "error":
        return None

    if cache is not None:
        if isinstance(result, ScorecardResult):
            cache.set_api_response(
                _CACHE_SOURCE,
                key,
                _result_to_cache_payload(result),
                ttl_hours=_SCORECARD_CACHE_TTL_HOURS,
            )
        elif result is None:
            cache.set_api_response(
                _CACHE_SOURCE,
                key,
                {"absent": True},
                ttl_hours=_SCORECARD_MISS_CACHE_TTL_HOURS,
            )

    return result if isinstance(result, ScorecardResult) else None
