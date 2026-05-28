"""Safely extract a workflows zip into a target directory.

Defends against zip bombs, path traversal in entry names, symlink entries,
oversized archives, and unexpected file types.
"""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path

_MAX_ENTRIES = 200
_MAX_TOTAL_EXTRACTED_BYTES = 10 * 1024 * 1024  # 10 MiB total
_MAX_PER_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB per file
_ALLOWED_EXTENSIONS = frozenset({".yml", ".yaml"})

# Unix file type bits in ZipInfo.external_attr (high 16 bits).
_UNIX_FILE_TYPE_MASK = 0o170000
_UNIX_SYMLINK = 0o120000
_UNIX_REGULAR_FILE = 0o100000

_LOG = logging.getLogger(__name__)


class ZipExtractionError(Exception):
    """Zip archive failed safety checks or extraction failed."""


def _reject(message: str) -> None:
    raise ZipExtractionError(message)


def _is_directory_entry(name: str) -> bool:
    return name.endswith("/")


def _is_macos_metadata(entry_name: str) -> bool:
    """Detect macOS AppleDouble metadata files and the __MACOSX/ directory."""
    basename = entry_name.rsplit("/", 1)[-1]
    return entry_name.startswith("__MACOSX/") or basename.startswith("._")


def _entry_basename(name: str) -> str:
    """Return the leaf filename for a zip entry path."""
    normalized = name.replace("\\", "/").rstrip("/")
    if not normalized:
        _reject(f"invalid zip entry name: {name!r}")
    return Path(normalized).name


def _validate_entry_name(name: str) -> None:
    if not name:
        _reject("zip entry name must not be empty")
    if name.startswith("/"):
        _reject(f"zip entry must not be an absolute path: {name!r}")
    if "\\" in name:
        _reject(f"zip entry must not contain backslashes: {name!r}")
    if ".." in name:
        _reject(f"zip entry must not contain path traversal: {name!r}")


def _validate_entry_type(info: zipfile.ZipInfo) -> None:
    mode = (info.external_attr >> 16) & _UNIX_FILE_TYPE_MASK
    if mode == _UNIX_SYMLINK:
        _reject(f"zip entry must not be a symlink: {info.filename!r}")
    if mode not in (0, _UNIX_REGULAR_FILE):
        _reject(f"zip entry must be a regular file: {info.filename!r}")


def _validate_extension(basename: str) -> None:
    suffix = Path(basename).suffix.lower()
    if suffix not in _ALLOWED_EXTENSIONS:
        _reject(
            f"zip entry must be a .yml or .yaml file, got {basename!r}",
        )


def _validate_target_path(dest_dir: Path, basename: str) -> Path:
    dest = dest_dir.resolve()
    target = (dest / basename).resolve()
    if not target.is_relative_to(dest):
        _reject(f"zip entry resolves outside destination: {basename!r}")
    return target


def extract_workflows_zip(
    zip_bytes: bytes,
    dest_dir: Path,
) -> int:
    """Extract a workflows zip safely into dest_dir.

    Validates each entry against safety rules before extracting. Returns
    the number of files extracted.

    Safety rules (any failure raises ZipExtractionError before extraction):
    - Not a valid zip file → reject
    - More than _MAX_ENTRIES entries → reject
    - Any entry size > _MAX_PER_FILE_BYTES → reject
    - Sum of entry sizes > _MAX_TOTAL_EXTRACTED_BYTES → reject
    - Any entry name with absolute path, '..', or backslash → reject
    - Any entry that's a symlink or device file → reject
    - Any entry that isn't a .yml or .yaml file (case-insensitive) → reject
    - Empty zip (zero file entries) → reject

    Files are written directly into dest_dir (not preserving the original
    zip's directory structure). E.g., a zip with `workflows/ci.yml` and
    `deploy.yml` produces `dest_dir/ci.yml` and `dest_dir/deploy.yml`.
    """
    if not zip_bytes:
        _reject("zip archive is empty")

    if not zipfile.is_zipfile(io.BytesIO(zip_bytes)):
        _reject("not a valid zip file")

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir.resolve()

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise ZipExtractionError("not a valid zip file") from exc

    with zf:
        entries = zf.infolist()
        if len(entries) > _MAX_ENTRIES:
            _reject(f"zip archive has more than {_MAX_ENTRIES} entries")

        file_entries: list[tuple[zipfile.ZipInfo, str, Path]] = []
        total_uncompressed = 0
        seen_basenames: set[str] = set()

        for info in entries:
            name = info.filename
            if _is_directory_entry(name) or _is_macos_metadata(name):
                continue

            _validate_entry_name(name)
            _validate_entry_type(info)

            basename = _entry_basename(name)
            _validate_extension(basename)

            if basename in seen_basenames:
                _reject(f"duplicate zip entry basename: {basename!r}")
            seen_basenames.add(basename)

            uncompressed = info.file_size
            if uncompressed > _MAX_PER_FILE_BYTES:
                _reject(
                    f"zip entry {basename!r} exceeds per-file size limit "
                    f"({_MAX_PER_FILE_BYTES} bytes)",
                )

            total_uncompressed += uncompressed
            if total_uncompressed > _MAX_TOTAL_EXTRACTED_BYTES:
                _reject(
                    f"zip archive exceeds total uncompressed size limit "
                    f"({_MAX_TOTAL_EXTRACTED_BYTES} bytes)",
                )

            target = _validate_target_path(dest, basename)
            file_entries.append((info, basename, target))

        if not file_entries:
            _reject("zip archive contains no workflow files")

        extracted = 0
        for info, basename, target in file_entries:
            data = zf.read(info.filename)
            if len(data) != info.file_size:
                _reject(
                    f"zip entry {basename!r} size mismatch after read "
                    f"(expected {info.file_size}, got {len(data)})",
                )
            if len(data) > _MAX_PER_FILE_BYTES:
                _reject(
                    f"zip entry {basename!r} exceeds per-file size limit "
                    f"({_MAX_PER_FILE_BYTES} bytes)",
                )

            target.write_bytes(data)
            extracted += 1
            _LOG.debug("extracted workflow file %s -> %s", info.filename, target)

        return extracted
