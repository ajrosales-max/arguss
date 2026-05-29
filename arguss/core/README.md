# `arguss.core` — shared contracts and plumbing

Single source of truth for dependency graphs, findings, and API payloads.

## Files

| File | Purpose |
|------|---------|
| [`models.py`](models.py) | Types: `Dependency`, `Finding`, `LensScore`, `FixCandidate`, `FixConfidence`, `TrustDelta`, `PipelineSnapshot`, `ProposalReport`, etc. |
| [`parser.py`](parser.py) | Parses `package-lock.json` (v2/v3) into dependencies; SBOM project helper |
| [`cache.py`](cache.py) | SQLite cache (WAL) for external API responses |
| [`sbom.py`](sbom.py) | CycloneDX 1.7 JSON export |
| [`serialization.py`](serialization.py) | JSON payloads for API/CLI; executive summary attachment |
| [`migrations/`](migrations/README.md) | SQL schema for cache DB |

## Consumers

`lenses/`, `engine/`, `web/routes.py`, `cli.py`, and tests (`test_parser.py`, `test_sbom.py`, …).
