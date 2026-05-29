# GitHub configuration

## Workflows (`.github/workflows/`)

| File | Trigger | Purpose |
|------|---------|---------|
| [`ci.yml`](workflows/ci.yml) | Push / PR | Lint (ruff), typecheck (mypy), pytest |
| [`deploy.yml`](workflows/deploy.yml) | Push to `main` | Deploy to Fly.io |
| [`secret-scan.yml`](workflows/secret-scan.yml) | Scheduled / PR | Secret scanning |

## Issue templates (`ISSUE_TEMPLATE/`)

| File | Purpose |
|------|---------|
| [`feature.md`](ISSUE_TEMPLATE/feature.md) | Feature request template |
| [`bug.md`](ISSUE_TEMPLATE/bug.md) | Bug report template |
