"""Extract only what analysis needs from wheels and sdists, refusing anything unsafe.

Refused: absolute paths, `..` segments, symlinks and other special members, more than
`MAX_MEMBERS` entries, and more than `MAX_TOTAL_BYTES` of extracted data (zip-bomb guard).
Only Python source and package metadata are written; compiled extension modules are recorded by
name (they define importable modules) but never written to disk.
"""

from __future__ import annotations

import stat
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from vexproof.sources.pypi import SourceError

MAX_MEMBERS = 60_000
MAX_TOTAL_BYTES = 600_000_000
MAX_FILE_BYTES = 20_000_000
_EXTENSION_SUFFIXES = (".so", ".pyd")
_METADATA = ("top_level.txt", "RECORD", "entry_points.txt", "METADATA", "PKG-INFO")
_METADATA_DEPTH = 2  # e.g. pkg-1.0.dist-info/top_level.txt
_MIN_SDIST_DEPTH = 2  # sdist members live under one top folder, e.g. pkg-1.0/pkg/__init__.py


@dataclass
class Extracted:
    root: Path
    python_files: list[str] = field(default_factory=list)
    extension_modules: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


def _safe_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts or ":" in path.parts[0]:
        raise SourceError(f"unsafe path in archive: {name!r}")
    return path


def _wanted(path: PurePosixPath) -> str | None:
    """'py', 'ext', 'meta' or None for files analysis does not need."""
    if path.suffix in {".py", ".pyi"}:
        return "py"
    if path.suffix in _EXTENSION_SUFFIXES:
        return "ext"
    if path.name in _METADATA and len(path.parts) <= _METADATA_DEPTH:
        return "meta"
    return None


def _write(dest: Path, rel: PurePosixPath, data: bytes) -> None:
    target = dest.joinpath(*rel.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def extract_wheel(archive: Path, dest: Path) -> Extracted:
    return _extract_zip(archive, dest, strip_top=False)


def _extract_zip(archive: Path, dest: Path, *, strip_top: bool) -> Extracted:
    out = Extracted(root=dest)
    total = 0
    try:
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                raise SourceError(f"{archive.name} has too many members ({len(infos)})")
            for info in infos:
                if info.is_dir():
                    continue
                rel = _safe_name(info.filename)
                if strip_top:
                    if len(rel.parts) < _MIN_SDIST_DEPTH:
                        continue
                    rel = PurePosixPath(*rel.parts[1:])
                file_type = stat.S_IFMT(info.external_attr >> 16)
                if file_type and file_type != stat.S_IFREG:  # symlink, device, fifo...
                    raise SourceError(f"special file in archive: {info.filename!r}")
                kind = _wanted(rel)
                if kind is None:
                    continue
                if kind == "ext":
                    out.extension_modules.append(str(rel))
                    continue
                total += info.file_size
                if info.file_size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    raise SourceError(f"{archive.name} expands beyond the size limit")
                data = zf.read(info)
                if kind == "meta":
                    out.metadata[str(rel)] = data.decode("utf-8", errors="replace")
                else:
                    out.python_files.append(str(rel))
                _write(dest, rel, data)
    except zipfile.BadZipFile as exc:
        raise SourceError(f"{archive.name} is not a valid wheel: {exc}") from exc
    return out


def _tar_members(tf: tarfile.TarFile) -> Iterator[tarfile.TarInfo]:
    for count, member in enumerate(tf):
        if count >= MAX_MEMBERS:
            raise SourceError("sdist has too many members")
        yield member


def extract_sdist(archive: Path, dest: Path) -> Extracted:
    """Extract an sdist, dropping its single top-level directory from every path."""
    if archive.name.endswith(".zip"):
        return _extract_zip(archive, dest, strip_top=True)
    out = Extracted(root=dest)
    total = 0
    try:
        with tarfile.open(archive, "r:*") as tf:
            for member in _tar_members(tf):
                if not member.isfile():
                    continue  # directories, links and devices are never extracted
                rel = _safe_name(member.name)
                if len(rel.parts) < _MIN_SDIST_DEPTH:
                    continue  # files beside the sdist's top folder are not package code
                rel = PurePosixPath(*rel.parts[1:])
                kind = _wanted(rel)
                if kind is None:
                    continue
                if kind == "ext":
                    out.extension_modules.append(str(rel))
                    continue
                total += member.size
                if member.size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    raise SourceError(f"{archive.name} expands beyond the size limit")
                handle = tf.extractfile(member)
                if handle is None:
                    continue
                data = handle.read()
                if kind == "meta":
                    out.metadata[str(rel)] = data.decode("utf-8", errors="replace")
                else:
                    out.python_files.append(str(rel))
                _write(dest, rel, data)
    except tarfile.TarError as exc:
        raise SourceError(f"{archive.name} is not a valid sdist: {exc}") from exc
    return out
