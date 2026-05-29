# `arguss.lenses` — three risk analyses

Each lens consumes parsed dependencies (and sometimes a repo path) and returns findings plus a subscore.

## Public lenses

| File | Lens | External sources |
|------|------|------------------|
| [`vulnerability.py`](vulnerability.py) | CVE / advisory matching | OSV.dev, EPSS, CISA KEV |
| [`trust.py`](trust.py) | Maintainer and typosquat signals | npm, deps.dev, `data/npm-top-1000-*.txt` |
| [`pipeline.py`](pipeline.py) | CI workflow risk + test reality | zizmor, workflow YAML |

## Internal clients

| File | Purpose |
|------|---------|
| [`_osv_client.py`](_osv_client.py) | OSV API (batching, cache) |
| [`_cvss.py`](_cvss.py) | CVSS v3 vector parsing |
| [`_epss_client.py`](_epss_client.py) | EPSS scores |
| [`_kev_client.py`](_kev_client.py) | CISA KEV catalog |
| [`_trust_client.py`](_trust_client.py) | npm and deps.dev HTTP |
| [`_zizmor_client.py`](_zizmor_client.py) | zizmor subprocess wrapper |
| [`__init__.py`](__init__.py) | Exports `VulnerabilityLens`, `TrustLens`, `PipelineLens` |
