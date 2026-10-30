from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest
import respx

from tests.wheels import make_sdist, make_wheel, sha256
from vexproof.domain import Package
from vexproof.intel.http import JsonHttp
from vexproof.sources.archive import extract_sdist, extract_wheel
from vexproof.sources.pypi import Artifact, PyPIClient, SourceError, choose_artifact
from vexproof.sources.store import SourceStore
from vexproof.sources.tree import SourceTree, build_tree, module_name

PYPI = "https://pypi.test"


def _file(name: str, kind: str, size: int) -> dict[str, object]:
    return {
        "filename": name,
        "packagetype": kind,
        "size": size,
        "url": f"https://files.test/{name}",
        "digests": {"sha256": "ab" * 32},
    }


def test_choose_prefers_pure_then_smallest_wheel_then_sdist() -> None:
    files = [
        _file("x-1.0-cp312-manylinux.whl", "bdist_wheel", 5_000),
        _file("x-1.0-cp312-win_amd64.whl", "bdist_wheel", 1_000),
        _file("x-1.0.tar.gz", "sdist", 10),
    ]
    assert choose_artifact(files) == Artifact(
        "x-1.0-cp312-win_amd64.whl",
        "https://files.test/x-1.0-cp312-win_amd64.whl",
        "ab" * 32,
        1_000,
        "wheel",
    )
    files.append(_file("x-1.0-py3-none-any.whl", "bdist_wheel", 9_000))
    chosen = choose_artifact(files)
    assert chosen is not None
    assert chosen.filename == "x-1.0-py3-none-any.whl"
    sdist_only = choose_artifact(
        [_file("x-1.0.tar.gz", "sdist", 10), _file("x.exe", "bdist_wininst", 1)]
    )
    assert sdist_only is not None
    assert sdist_only.kind == "sdist"
    assert choose_artifact([{"filename": "x.whl", "packagetype": "bdist_wheel"}]) is None


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        ("pkg/sub/mod.py", "pkg.sub.mod"),
        ("pkg/__init__.py", "pkg"),
        ("PIL/_imaging.cpython-312-x86_64-linux-gnu.so", "PIL._imaging"),
        ("top.py", "top"),
        ("not-valid/mod.py", None),
        ("app/migrations/0001_initial.py", "app.migrations.0001_initial"),
        ("pkg/my-module.py", None),
        ("__init__.py", None),
    ],
)
def test_module_names(rel: str, expected: str | None) -> None:
    assert module_name(rel) == expected


def test_wheel_tree_modules_top_level_and_plugins(tmp_path: Path) -> None:
    archive = tmp_path / "x.whl"
    make_wheel(
        archive,
        "example-lib",
        "1.0",
        {
            "examplelib/__init__.py": "",
            "examplelib/parser.py": "def load(): ...\n",
            "README.txt": "x",
        },
        top_level=["examplelib"],
        entry_points=(
            "[console_scripts]\nex = examplelib:main\n[example.plugins]\np = examplelib.parser\n"
        ),
        extensions=["examplelib/_speedups.cpython-312-x86_64-linux-gnu.so"],
    )
    extracted = extract_wheel(archive, tmp_path / "out")
    tree = build_tree("example-lib", "1.0", "wheel", extracted)
    assert tree.modules == {
        "examplelib": "examplelib/__init__.py",
        "examplelib.parser": "examplelib/parser.py",
        "examplelib._speedups": "",
    }
    assert tree.top_level == frozenset({"examplelib"})
    assert tree.plugin_groups == frozenset({"example.plugins"})
    assert tree.source("examplelib.parser") == "def load(): ...\n"
    assert tree.source("examplelib._speedups") is None
    assert not (tmp_path / "out" / "README.txt").exists()
    assert not list((tmp_path / "out").rglob("*.so"))
    tree.save()
    assert SourceTree.load(tree.root) == tree


@pytest.mark.parametrize("evil", ["../escape.py", "/abs/path.py", "C:/x.py"])
def test_wheel_path_traversal_rejected(tmp_path: Path, evil: str) -> None:
    archive = tmp_path / "evil.whl"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(evil, "x = 1\n")
    with pytest.raises(SourceError, match="unsafe path"):
        extract_wheel(archive, tmp_path / "out")
    assert not (tmp_path / "escape.py").exists()


def test_wheel_symlink_member_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "link.whl"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("pkg/link.py")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(SourceError, match="special file"):
        extract_wheel(archive, tmp_path / "out")


def test_bad_zip_and_size_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad = tmp_path / "bad.whl"
    bad.write_bytes(b"not a zip")
    with pytest.raises(SourceError, match="not a valid wheel"):
        extract_wheel(bad, tmp_path / "o1")
    big = tmp_path / "big.whl"
    make_wheel(big, "big", "1", {"big/__init__.py": "x" * 1000})
    monkeypatch.setattr("vexproof.sources.archive.MAX_TOTAL_BYTES", 100)
    with pytest.raises(SourceError, match="size limit"):
        extract_wheel(big, tmp_path / "o2")
    monkeypatch.setattr("vexproof.sources.archive.MAX_MEMBERS", 1)
    with pytest.raises(SourceError, match="too many members"):
        extract_wheel(big, tmp_path / "o3")


def test_sdist_tree_strips_prefix_src_and_tests(tmp_path: Path) -> None:
    archive = tmp_path / "x-1.0.tar.gz"
    make_sdist(
        archive,
        "x-1.0",
        {
            "src/xpkg/__init__.py": "",
            "src/xpkg/core.py": "def f(): ...\n",
            "tests/test_core.py": "def test(): ...\n",
            "setup.py": "from setuptools import setup\n",
            "PKG-INFO": "Name: x\n",
        },
    )
    tree = build_tree("x", "1.0", "sdist", extract_sdist(archive, tmp_path / "out"))
    assert tree.modules == {"xpkg": "src/xpkg/__init__.py", "xpkg.core": "src/xpkg/core.py"}
    assert tree.top_level == frozenset({"xpkg"})


def test_sdist_skips_links_and_rejects_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        link = tarfile.TarInfo("x-1.0/pkg/link.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
        data = b"x = 1\n"
        info = tarfile.TarInfo("x-1.0/../../escape.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(SourceError, match="unsafe path"):
        extract_sdist(archive, tmp_path / "out")
    assert not (tmp_path / "out" / "pkg" / "link.py").exists()


def _mock_release(
    router: respx.MockRouter, name: str, version: str, filename: str, data: bytes
) -> respx.Route:
    router.get(f"{PYPI}/pypi/{name}/{version}/json").respond(
        json={
            "urls": [
                {
                    "filename": filename,
                    "packagetype": "bdist_wheel",
                    "size": len(data),
                    "url": f"https://files.test/{filename}",
                    "digests": {"sha256": sha256(data)},
                }
            ]
        }
    )
    return router.get(f"https://files.test/{filename}").respond(content=data)


def test_store_downloads_verifies_and_caches(tmp_path: Path, http: JsonHttp) -> None:
    data = make_wheel(
        tmp_path / "w.whl",
        "examplelib",
        "1.4.2",
        {"examplelib/__init__.py": ""},
        top_level=["examplelib"],
    )
    with respx.mock as router, httpx.Client() as client:
        download = _mock_release(
            router, "examplelib", "1.4.2", "examplelib-1.4.2-py3-none-any.whl", data
        )
        store = SourceStore(tmp_path / "cache", PyPIClient(http, client, PYPI, 10_000_000))
        package = Package(name="examplelib", version="1.4.2")
        first = store.get(package)
        second = store.get(package)
    assert first == second
    assert first.modules == {"examplelib": "examplelib/__init__.py"}
    assert download.call_count == 1


def test_store_rejects_digest_mismatch_and_oversize(tmp_path: Path, http: JsonHttp) -> None:
    data = make_wheel(tmp_path / "w.whl", "examplelib", "1.0", {"examplelib/__init__.py": ""})
    with respx.mock as router, httpx.Client() as client:
        router.get(f"{PYPI}/pypi/examplelib/1.0/json").respond(
            json={
                "urls": [
                    {
                        "filename": "e-1.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "size": len(data),
                        "url": "https://files.test/e.whl",
                        "digests": {"sha256": "00" * 32},
                    }
                ]
            }
        )
        router.get("https://files.test/e.whl").respond(content=data)
        _mock_release(router, "huge", "1.0", "huge-1.0-py3-none-any.whl", data)
        router.get(f"{PYPI}/pypi/missing/1.0/json").respond(404)
        store = SourceStore(tmp_path / "cache", PyPIClient(http, client, PYPI, 10_000_000))
        with pytest.raises(SourceError, match="SHA-256 mismatch"):
            store.get(Package(name="examplelib", version="1.0"))
        small = SourceStore(tmp_path / "c2", PyPIClient(http, client, PYPI, 10))
        with pytest.raises(SourceError, match="above the"):
            small.get(Package(name="huge", version="1.0"))
        trees, failures = store.get_many([Package(name="missing", version="1.0")])
    assert trees == {}
    assert "not found on PyPI" in failures[Package(name="missing", version="1.0")]
    assert not list((tmp_path / "cache" / "sources").glob("examplelib*"))


def test_sdist_code_under_lib_gets_its_import_names() -> None:
    from vexproof.sources.archive import Extracted
    from vexproof.sources.tree import build_tree

    files = [
        "lib/sqlalchemy/__init__.py",
        "lib/sqlalchemy/orm/__init__.py",
        "lib/sqlalchemy/orm/query.py",
        "lib/six.py",
        "lib3/yaml/__init__.py",
        "lib/yaml/__init__.py",
        "tools/release.py",
        "examples/demo.py",
        "setup.py",
    ]
    tree = build_tree("x", "1", "sdist", Extracted(root=Path("/nowhere"), python_files=files))
    assert tree.modules["sqlalchemy.orm.query"] == "lib/sqlalchemy/orm/query.py"
    assert tree.modules["six"] == "lib/six.py"
    assert tree.modules["yaml"] == "lib3/yaml/__init__.py"  # the Python 3 copy wins
    assert "tools.release" in tree.modules  # not a layout folder: left as it is
    assert not any(m.startswith(("lib.", "examples")) for m in tree.modules)
