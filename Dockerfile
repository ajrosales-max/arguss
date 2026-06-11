# syntax=docker/dockerfile:1.7

# ---- Build stage ----
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Install dependencies (cached layer when pyproject.toml unchanged)
COPY pyproject.toml README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-install-project

# Copy source and install the project itself
COPY arguss ./arguss
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev

# ---- Runtime stage ----
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# git is required at runtime: Mode C action path shallow-clones via subprocess
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl unzip\
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r arguss && useradd -r -g arguss arguss

WORKDIR /app

# Copy the virtualenv and source from the builder
COPY --from=builder --chown=arguss:arguss /app/.venv /app/.venv
COPY --from=builder --chown=arguss:arguss /app/arguss /app/arguss

# Create data directory for SQLite volume mount
RUN mkdir -p /data && chown arguss:arguss /data

USER arguss

EXPOSE 8080

# Health check for Fly
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health').read()" || exit 1

CMD ["uvicorn", "arguss.api:app", "--host", "0.0.0.0", "--port", "8080"]
