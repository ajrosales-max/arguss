"""Parse and validate GitHub repository URLs for the scan endpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

_GITHUB_HOST = "github.com"
_GITHUB_SEGMENT_RE = re.compile(r"^(?!\.)(?!.*\.\.)[a-zA-Z0-9][a-zA-Z0-9._-]*$")


@dataclass(frozen=True)
class ParsedGitHubRepo:
    """A parsed GitHub repo reference."""

    owner: str
    name: str
    clone_url: str


class InvalidGitHubURLError(ValueError):
    """The provided URL is not a valid GitHub repository URL."""


def _reject(message: str) -> None:
    raise InvalidGitHubURLError(message)


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
