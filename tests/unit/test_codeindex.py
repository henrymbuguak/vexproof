from __future__ import annotations

from pathlib import Path

from tests.codebase import FRAME, build
from vexproof.static.codeindex import BARE, LITERAL, CodeIndex, Scope, Site, parse_module


def _scopes(index: CodeIndex, *names: str) -> list[Scope]:
    found = [index.scope(n) for n in names]
    missing = [n for n, s in zip(names, found, strict=True) if s is None]
    assert not missing, missing
    return [s for s in found if s is not None]


def _site(index: CodeIndex, scope: str, name: str) -> Site:
    found = index.scope(scope)
    assert found is not None
    return next(s for s in found.sites if s.name == name)


def test_parse_module_scopes_sites_and_types() -> None:
    code = parse_module(
        "pkg.mod",
        """\
import os
from pkg import other as alias
from .helpers import *


class Thing(alias.Base):
    def __init__(self):
        self.part = Part()

    def run(self, item: "Item", count):
        local = Part()
        local.go()
        self.part.go()
        item.use()
        super().run()
        count.anything()
        open("x")
        os.path.join("a")
        "{}".format(1)
        return alias.helper(self.run)


class Part:
    def go(self):
        return 1
""",
    )
    assert set(code.scopes) == {"pkg.mod", "pkg.mod.Thing.__init__", "pkg.mod.Thing.run",
                                "pkg.mod.Part.go"}  # fmt: skip
    assert code.classes["pkg.mod.Thing"] == ["pkg.other.Base"]
    assert code.star_imports == ["pkg.helpers"]
    run = {(s.name, s.kind, s.recv) for s in code.scopes["pkg.mod.Thing.run"].sites}
    assert ("go", "call", "@pkg.mod.Part") in run  # local = Part(); local.go()
    assert ("go", "call", "@pkg.mod.Part") in run  # self.part.go(), typed in __init__
    assert ("use", "call", "@Item") in run  # annotated parameter (unresolved name)
    assert ("run", "call", "super") in run
    assert ("anything", "call", "") in run  # unknown type
    assert ("format", "call", LITERAL) in run
    assert ("helper", "call", "%alias") in run
    assert ("run", "attr", "self") in run  # bound method passed as a callback
    assert not any(name == "open" for name, _, _ in run)  # builtin, not a module binding
    assert not any(name == "count" for name, _, _ in run)  # a parameter, not a reference


def test_unparseable_module_is_empty() -> None:
    code = parse_module("pkg.bad", "def broken(:\n")
    assert code.scopes == {}


def test_edges_are_certain_possible_or_absent(tmp_path: Path) -> None:
    _, index, _ = build(tmp_path)
    frame, getimage, load, process = _scopes(
        index,
        FRAME,
        "PIL.IcoPlugin.IcoFile.getimage",
        "PIL.IcoPlugin.IcoImageFile.load",
        "shop.views.process",
    )
    assert index.edge(frame, _site(index, getimage.qualname, "frame"), getimage) == "certain"
    # self.ico.getimage(): the class of self.ico is set in _open
    assert index.edge(getimage, _site(index, load.qualname, "getimage"), load) == "certain"
    # obj.frame(): obj has no known type
    assert index.edge(frame, _site(index, process.qualname, "frame"), process) == "possible"
    # "{}".format(...).split(): builtin methods on literals never reach library code
    text = index.scope("shop.views.text")
    assert text is not None
    assert all(s.recv in {LITERAL, ""} for s in text.sites if s.name in {"format", "split"})


def test_functions_follow_imports(tmp_path: Path) -> None:
    _, index, _ = build(tmp_path)
    getrgb, convert = _scopes(index, "PIL.ImageColor.getrgb", "PIL.Image.Image.convert")
    assert index.edge(getrgb, _site(index, convert.qualname, "getrgb"), convert) == "certain"
    wrong = Site(1, "getrgb", "call", BARE, "other.module.getrgb")
    assert index.edge(getrgb, wrong, convert) is None  # same name, different function


def test_constructors_and_inheritance(tmp_path: Path) -> None:
    _, index, _ = build(tmp_path)
    assert index.resolve("PIL.ImageFile.Image.Image") == "PIL.Image.Image"
    assert "PIL.IcoPlugin.IcoImageFile" in index.subclasses("PIL.Image.Image")
    assert index.related("PIL.IcoPlugin.IcoImageFile", "PIL.ImageFile.ImageFile")
    assert not index.related("PIL.IcoPlugin.IcoFile", "PIL.Image.Image")
    init, opener = _scopes(
        index, "PIL.IcoPlugin.IcoFile.__init__", "PIL.IcoPlugin.IcoImageFile._open"
    )
    assert index.edge(init, _site(index, opener.qualname, "IcoFile"), opener) == "certain"
    assert index.registered("PIL.IcoPlugin", ["register_open"]) == {"PIL.IcoPlugin.IcoImageFile"}


def test_callers_and_source(tmp_path: Path) -> None:
    _, index, _ = build(tmp_path)
    frame = index.scope(FRAME)
    assert frame
    found = {(s.qualname, how) for s, _, how in index.callers(frame)}
    assert found == {
        ("PIL.IcoPlugin.IcoFile.getimage", "certain"),
        ("shop.views.process", "possible"),
    }
    assert index.ambiguity(frame) == 1
    source = index.source(FRAME)
    assert source is not None
    assert "def frame(self, idx):" in source
    assert index.source("PIL.IcoPlugin") is None  # modules have no single source
    assert index.source("no.such.function") is None
    assert index.line("PIL.ImageColor", 1) == "def getrgb(color):"
    assert index.line("PIL.ImageColor", 99) == ""


def test_shortest_path_prefers_what_it_is_told(tmp_path: Path) -> None:
    _, index, _ = build(tmp_path)
    frame = index.scope(FRAME)
    assert frame
    loose = index.shortest_path(frame)
    assert loose is not None
    assert [s.qualname for s, _, _ in loose] == ["shop.views.process", FRAME]
    assert index.shortest_path(frame, certain_only=True) is None  # needs the registry edge
    assert index.shortest_path(frame, avoid={"shop.views.process"}) is None


EXTRA = """\
from PIL.IcoPlugin import IcoFile

ROUTES = ["PIL.ImageColor.getrgb"]


class Mine(IcoFile):
    def __init__(self, fp):
        super().__init__(fp)
        IcoFile.__init__(self, fp)
        IcoFile.frame(self, 0)

    def __len__(self):
        return 1


def size(m):
    return m.__len__()
"""


def test_explicit_super_string_and_dunder_edges(tmp_path: Path) -> None:
    from tests.codebase import PROJECT

    _, index, _ = build(tmp_path, project={**PROJECT, "shop/extra.py": EXTRA})
    init, frame, getrgb, length, mine_init, size, module = _scopes(
        index,
        "PIL.IcoPlugin.IcoFile.__init__",
        FRAME,
        "PIL.ImageColor.getrgb",
        "shop.extra.Mine.__len__",
        "shop.extra.Mine.__init__",
        "shop.extra.size",
        "shop.extra",
    )
    via = {(s.qualname, site.line, how) for s, site, how in index.callers(init)}
    assert ("shop.extra.Mine.__init__", 8, "certain") in via  # super().__init__(fp)
    assert ("shop.extra.Mine.__init__", 9, "certain") in via  # IcoFile.__init__(self, fp)
    assert index.edge(frame, _site(index, mine_init.qualname, "frame"), mine_init) == "certain"
    route = next(s for s in module.sites if s.kind == "string")
    assert index.edge(getrgb, route, module) == "certain"  # a dotted string naming it
    assert index.edge(length, _site(index, size.qualname, "__len__"), size) is None
    assert index.edge(module, route, module) is None  # modules are never callees


MRO = """\
class Base:
    def load(self):
        return 1

    def run(self):
        return self.load()


class Child(Base):
    def load(self):
        return super().load()

    def go(self):
        return self.load()

    def base_only(self):
        return Base.load(self)


class Grandchild(Child):
    def load(self):
        return 3
"""


def test_calls_follow_method_resolution_order(tmp_path: Path) -> None:
    from tests.codebase import PROJECT

    _, index, _ = build(tmp_path, project={**PROJECT, "shop/mro.py": MRO})
    base_load, child_load, grand_load, run, go, base_only = _scopes(
        index,
        "shop.mro.Base.load",
        "shop.mro.Child.load",
        "shop.mro.Grandchild.load",
        "shop.mro.Base.run",
        "shop.mro.Child.go",
        "shop.mro.Child.base_only",
    )
    in_run, in_go, in_only, in_child = (
        _site(index, s.qualname, "load") for s in (run, go, base_only, child_load)
    )
    # self.load() in Base: Base's own, or any subclass override
    assert all(index.edge(t, in_run, run) for t in (base_load, child_load, grand_load))
    # self.load() in Child: Child overrides it, so never Base.load
    assert index.edge(base_load, in_go, go) is None
    assert index.edge(grand_load, in_go, go) == "certain"
    # super().load() in Child: the next definition above, Base.load
    assert index.edge(base_load, in_child, child_load) == "certain"
    assert index.edge(grand_load, in_child, child_load) is None
    # Base.load(self): exactly Base's, never an override
    assert index.edge(base_load, in_only, base_only) == "certain"
    assert index.edge(child_load, in_only, base_only) is None
    assert index.mro_owner("shop.mro.Grandchild", "run") == "shop.mro.Base"
    assert index.mro_owner("shop.mro.Base", "missing") is None
