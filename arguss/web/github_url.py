"""Parse and validate GitHub repository URLs for the scan endpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

_GITHUB_HOST = "github.com"
_GITHUB_SEGMENT_RE = re.compile(r"^(?!\.)(?!.*\.\.)[a-zA-Z0-9][a-zA-Z0-9._-]*$")

# Git refs legitimately contain "/" and "." (feature/x, v1.0.0), so this is a
# SEPARATE, looser character class than _GITHUB_SEGMENT_RE. Everything outside
# this set — whitespace, control chars, the git-invalid set (~ ^ : ? * [), "@",
# and "\\" — is rejected by the character class alone; the remaining structural
# rules (.., leading "-", //, leading/trailing "/", trailing .lock) are checked
# explicitly below.
_GIT_REF_ALLOWED_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_GIT_REF_MAX_LEN = 255


@dataclass(frozen=True)
class ParsedGitHubRepo:
    """A parsed GitHub repo reference."""

    owner: str
    name: str
    clone_url: str

    @property
    def repo_identity(self) -> str:
        """Canonical repo key for stable candidate_id across fetch paths."""
        return f"{self.owner}/{self.name}"


class InvalidGitHubURLError(ValueError):
    """The provided URL is not a valid GitHub repository URL."""


class InvalidGitRefError(ValueError):
    """The provided git ref is not a valid or safe ref."""


def _reject(message: str) -> None:
    raise InvalidGitHubURLError(message)


def _reject_ref(message: str) -> None:
    raise InvalidGitRefError(message)


def validate_git_ref(ref: str) -> str:
    """Validate a git ref (branch, tag, or commit SHA) for safe use.

    A ref reaches two sinks: the GitHub API path ``.../git/trees/{ref}`` (where
    ``..`` would traverse to a different endpoint) and ``git clone --branch
    <ref>`` (where a leading ``-`` or control chars are option/injection risks).

    Accepts ``HEAD`` and legitimate refs like ``main``, ``feature/x``,
    ``v1.0.0``. Rejects path traversal, option injection, and git-invalid
    constructs. Raises ``InvalidGitRefError`` on rejection.
    """
    if not isinstance(ref, str):
        _reject_ref("ref must be a string")
    if ref == "" or ref == "HEAD":
        return "HEAD"
    if len(ref) > _GIT_REF_MAX_LEN:
        _reject_ref("git ref is too long")
    if not _GIT_REF_ALLOWED_RE.fullmatch(ref):
        _reject_ref(f"Invalid git ref: {ref!r}")
    if ref.startswith("-"):
        _reject_ref("git ref must not start with '-'")
    if ref.startswith("/") or ref.endswith("/"):
        _reject_ref("git ref must not start or end with '/'")
    if ref.endswith(".lock"):
        _reject_ref("git ref must not end with '.lock'")
    if ".." in ref or "//" in ref:
        _reject_ref("git ref must not contain '..' or '//'")
    return ref


def _valid_segment(segment: str, label: str) -> str:
    if not _GITHUB_SEGMENT_RE.fullmatch(segment):
        _reject(f"Invalid GitHub {label}: {segment!r}")
    return segment


def parse_github_url(url: str) -> ParsedGitHubRepo:
    """Parse a GitHub repo URL into owner/name components.

    Accepts these forms:
    - https://github.com/owner/name
    - https://github.com/owner/name.git
    - https://github.com/owner/name/tree/branch (ignores the tree/branch suffix)
    - github.com/owner/name (adds https://)

    Rejects:
    - URLs with hostnames other than github.com (no enterprise GitHub for v1)
    - URLs with fewer than 2 path components after the host
    - URLs containing path traversal sequences (..)
    - URLs that aren't HTTPS (no SSH, no git:// — fetched over HTTPS only)
    - Non-string inputs, empty strings, whitespace-only

    Raises InvalidGitHubURLError with a clear message on rejection.
    """
    if not isinstance(url, str):
        _reject("URL must be a string")

    stripped = url.strip()
    if not stripped:
        _reject("URL must not be empty")

    if stripped.startswith("git@") or stripped.startswith("ssh://"):
        _reject("SSH GitHub URLs are not supported; use https://github.com/owner/repo")

    normalized = stripped
    if not normalized.startswith(("http://", "https://")):
        normalized = f"https://{normalized}"

    if normalized.startswith("git://"):
        _reject("git:// URLs are not supported; use https://github.com/owner/repo")

    parsed = urlparse(normalized)

    if parsed.scheme != "https":
        _reject("Only HTTPS GitHub URLs are supported")

    hostname = (parsed.hostname or "").lower()
    if hostname != _GITHUB_HOST:
        _reject(f"Only github.com repositories are supported (got host {hostname!r})")

    raw_path = parsed.path.strip("/")
    if not raw_path:
        _reject("URL must include owner and repository name")

    segments = [part for part in raw_path.split("/") if part]
    if len(segments) < 2:
        _reject("URL must include both owner and repository name")

    for segment in segments:
        if segment == ".." or segment == "." or ".." in segment:
            _reject("URL must not contain path traversal sequences")

    owner = _valid_segment(segments[0], "owner")
    name = segments[1]
    if name.endswith(".git"):
        name = name[:-4]
    name = _valid_segment(name, "repository name")

    clone_url = f"https://github.com/{owner}/{name}.git"
    return ParsedGitHubRepo(owner=owner, name=name, clone_url=clone_url)


def extract_github_owner_repo(
    repository_field: str | dict[str, Any] | None,
) -> tuple[str, str] | None:
    """Extract ``(owner, repo)`` from an npm package's ``repository`` field.

    Returns ``None`` if the field is missing, malformed, or non-GitHub.
    Handles ``git+https``, plain ``https``, ``git+ssh``, ``git://``, and
    ``github:owner/repo`` shorthand forms.
    """
    if repository_field is None:
        return None

    url: str | None = None
    if isinstance(repository_field, dict):
        raw = repository_field.get("url")
        if not isinstance(raw, str):
            return None
        url = raw.strip()
    elif isinstance(repository_field, str):
        url = repository_field.strip()
    else:
        return None

    if not url:
        return None

    if url.startswith("github:"):
        rest = url[7:].strip().strip("/")
        parts = [p for p in rest.split("/") if p]
        if len(parts) < 2:
            return None
        owner = parts[0]
        name = parts[1]
        if name.endswith(".git"):
            name = name[:-4]
        try:
            return _valid_segment(owner, "owner"), _valid_segment(name, "repository name")
        except InvalidGitHubURLError:
            return None

    lowered = url.lower()
    if "gitlab.com" in lowered or "bitbucket.org" in lowered:
        return None

    normalized = url
    if normalized.startswith("git+https://"):
        normalized = normalized[4:]
    elif normalized.startswith("git+ssh://git@github.com/"):
        normalized = "https://github.com/" + normalized[len("git+ssh://git@github.com/") :]
    elif normalized.startswith("git@github.com:"):
        normalized = "https://github.com/" + normalized[len("git@github.com:") :]
    elif normalized.startswith("git://github.com/"):
        normalized = "https://" + normalized[len("git://") :]

    if "github.com" not in normalized.lower():
        return None

    try:
        parsed = parse_github_url(normalized)
    except InvalidGitHubURLError:
        return None
    return parsed.owner, parsed.name
