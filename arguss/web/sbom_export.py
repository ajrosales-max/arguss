"""SBOM download helpers — reconstruct generator input from cached scan payloads."""

from __future__ import annotations

from typing import Any

from arguss.core.models import Dependency
from arguss.web.wizard import parse_repo_owner_name

_DEFAULT_PROJECT_VERSION = "0.0.0"
# Root project version comes from lockfile packages[""] (lockfile_project_for_sbom) but
# parse_lockfile excludes the root package from deps, so cached scans never carry it.
# Dashboard SBOM therefore uses 0.0.0 while CLI arguss sbom matches the lockfile — accepted
# limitation; not worth a scan-cache schema bump for one string.
_UPLOAD_PROJECT_NAME = "upload"


def deps_from_cached(cached: dict[str, Any]) -> list[Dependency]:
    """Rebuild ``Dependency`` rows from cached ``deps`` (``serialize_lockfile_deps`` shape)."""
    deps_raw = cached.get("deps")
    if not isinstance(deps_raw, list):
        return []
    out: list[Dependency] = []
    for row in deps_raw:
        if not isinstance(row, dict):
            continue
        package = str(row.get("package") or "").strip()
        version = str(row.get("version") or "").strip()
        if not package or not version:
            continue
        parents_raw = row.get("parents")
        path_raw = row.get("path")
        parents = [str(p) for p in parents_raw] if isinstance(parents_raw, list) else []
        path = [str(p) for p in path_raw] if isinstance(path_raw, list) else []
        install_key = str(row.get("install_key") or "").strip()
        out.append(
            Dependency(
                name=package,
                version=version,
                direct=bool(row.get("is_direct")),
                install_key=install_key,
                path=path,
                parents=parents,
            )
        )
    return out


def project_identity_for_sbom(cached: dict[str, Any]) -> tuple[str, str]:
    """Project root metadata for ``generate_sbom`` from cached scan meta."""
    scan_meta = cached.get("scan_meta") or {}
    mode = str(scan_meta.get("mode") or "")
    if mode == "B":
        return (_UPLOAD_PROJECT_NAME, _DEFAULT_PROJECT_VERSION)
    repo_display = str(scan_meta.get("repo_display") or "").strip()
    if repo_display and repo_display != "Unknown repository":
        return (repo_display, _DEFAULT_PROJECT_VERSION)
    return ("unknown", _DEFAULT_PROJECT_VERSION)


def sbom_download_filename(scan_hash: str, cached: dict[str, Any]) -> str:
    """Attachment filename for a cached scan SBOM download."""
    short = scan_hash[:8] if len(scan_hash) >= 8 else scan_hash
    scan_meta = cached.get("scan_meta") or {}
    mode = str(scan_meta.get("mode") or "")
    if mode == "B":
        return f"arguss-sbom-upload-{short}.cdx.json"
    try:
        owner, repo = parse_repo_owner_name(scan_meta)
    except ValueError:
        return f"arguss-sbom-{short}.cdx.json"
    return f"arguss-sbom-{owner}-{repo}-{short}.cdx.json"
