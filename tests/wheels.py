"""Build small wheels and sdists for tests, including deliberately malicious ones."""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path


def make_wheel(
    path: Path,
    name: str,
    version: str,
    files: dict[str, str],
    *,
    top_level: list[str] | None = None,
    entry_points: str | None = None,
    extensions: list[str] = (),  # type: ignore[assignment]
) -> bytes:
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as zf:
        for rel, text in files.items():
            zf.writestr(rel, text)
        for rel in extensions:
            zf.writestr(rel, b"\x7fELF")
        zf.writestr(f"{dist_info}/METADATA", f"Name: {name}\nVersion: {version}\n")
        if top_level is not None:
            zf.writestr(f"{dist_info}/top_level.txt", "\n".join(top_level) + "\n")
        if entry_points is not None:
            zf.writestr(f"{dist_info}/entry_points.txt", entry_points)
    return path.read_bytes()


def make_sdist(path: Path, prefix: str, files: dict[str, str]) -> bytes:
    with tarfile.open(path, "w:gz") as tf:
        for rel, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"{prefix}/{rel}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path.read_bytes()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
