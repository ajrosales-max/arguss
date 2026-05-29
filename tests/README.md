# Arguss tests

Pytest suite. Default run excludes live network tests (`-m 'not integration'` in `pyproject.toml`).

## Configuration

| File | Purpose |
|------|---------|
| [`conftest.py`](conftest.py) | Shared fixtures and pytest hooks |

## Test modules (by area)

| File | Area |
|------|------|
| `test_parser.py` | Lockfile parser |
| `test_sbom.py` | CycloneDX export |
| `test_osv_client.py` | OSV client (mocked) |
| `test_vulnerability_lens.py` | Vulnerability lens |
| `test_epss_client.py`, `test_epss_integration.py` | EPSS |
| `test_kev_client.py`, `test_kev_integration.py` | CISA KEV |
| `test_trust_lens.py`, `test_trust_snapshot.py`, `test_trust_delta.py` | Trust lens |
| `test_trust_client_transport.py` | Trust HTTP transport |
| `test_zizmor_client.py`, `test_pipeline_lens.py` | Pipeline lens |
| `test_fix_confidence.py`, `test_propose_fixes.py` | Engine |
| `test_explanation.py`, `test_executive_summary.py` | Explanations |
| `test_scan_url_endpoint.py`, `test_scan_upload_endpoint.py`, `test_scan_with_action_endpoint.py` | JSON API |
| `test_dashboard_routes.py`, `test_results_context.py`, `test_lens_scores_ui.py` | Web UI |
| `test_chat_panel.py` | Results chat |
| `test_demo_auth.py` | Demo HTTP Basic Auth |
| `test_github_fetch.py`, `test_github_fetch_integration.py` | GitHub fetch |
| `test_integration_osv.py`, `test_integration_lens.py` | Integration (network) |
| `test_skeleton.py` | Smoke / placeholder |

## Fixtures

See [`fixtures/README.md`](fixtures/README.md).

## Commands

```bash
uv run pytest
uv run pytest -m integration
uv run pytest tests/test_parser.py -v
```
