"""Generic Anthropic client wrapper with fail-soft semantics."""

from __future__ import annotations

import logging

from anthropic import Anthropic, APIError, APITimeoutError

from arguss.explanations._budget import try_reserve_anthropic_call
from arguss.settings import settings

_LOG = logging.getLogger(__name__)


def call_claude(
    system_prompt: str,
    user_message: str,
    *,
    max_tokens: int = 400,
    timeout: float = 8.0,
) -> str | None:
    """Call Claude with the given prompts. Returns text on success, None on any failure."""
    if not settings.anthropic_api_key:
        _LOG.debug("Anthropic API key not configured; skipping Claude call")
        return None

    # Global daily spend ceiling (call-count, NOT a token/dollar cap): reserve
    # one slot before calling out. At/over the ceiling we short-circuit to
    # None — the same fail-soft path callers already handle — so AI prose
    # degrades gracefully instead of erroring. A reserved slot is consumed
    # even if the API call below fails (conservative by design).
    if settings.rate_limit_enabled and not try_reserve_anthropic_call(
        settings.db_path,
        ceiling=settings.anthropic_daily_ceiling,
    ):
        _LOG.warning("Anthropic daily call ceiling reached; skipping Claude call")
        return None

    try:
        client = Anthropic(
            api_key=settings.anthropic_api_key,
            timeout=timeout,
        )
        message = client.messages.create(
            model=settings.anthropic_explanation_model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
    except APITimeoutError:
        _LOG.warning("Anthropic API timeout during Claude call")
        return None
    except APIError as exc:
        _LOG.warning("Anthropic API error during Claude call: %s", exc)
        return None
    except Exception as exc:
        _LOG.warning("Unexpected error during Claude call: %s", exc)
        return None

    if not message.content:
        _LOG.warning("Anthropic response had empty content")
        return None

    first_block = message.content[0]
    text = getattr(first_block, "text", None)
    if not isinstance(text, str) or not text.strip():
        _LOG.warning("Anthropic response had no usable text")
        return None

    return text.strip()
