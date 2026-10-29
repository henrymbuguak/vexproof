"""A small synthetic codebase that mirrors the real case: a Pillow-like library and a project.

`PIL` (distribution "pillow", so its computed imports count as reviewed):
- `PIL.Image.open` instantiates whatever plugins registered with `register_open`;
- `IcoPlugin` registers `IcoImageFile`, whose `_open` -> `load` -> `self.ico.getimage()` ->
  `IcoFile.frame` (the "vulnerable" function): a fully certain chain once `open` is reached;
- `ImageMath` is never loaded by anything; `ImageColor` is loaded by `Image`.

`shop` (the project): `views.thumbnail` calls `Image.open`; `views.color` calls `convert` on an
`Image.Image`; `views.upload` builds an `UploadForm`, so `OtherForm.clean` is not reachable from
it; `views.process` calls `.frame()` on an object of unknown type (a possible hop).
"""

from __future__ import annotations

from pathlib import Path

from tests.trees import make_tree
from vexproof.domain import Package
from vexproof.sources.tree import SourceTree
from vexproof.static.codeindex import CodeIndex
from vexproof.static.modules import ModuleReach, module_reachability

PILLOW = Package(name="pillow", version="9.0.0")

LIBRARY = {
    "PIL/__init__.py": '_plugins = ["IcoPlugin"]\n',
    "PIL/Image.py": """\
from PIL import _plugins
from . import ImageColor

OPEN = {}
SAVE = {}


def init():
    for plugin in _plugins:
        __import__("PIL.%s" % plugin)


def register_open(name, factory):
    OPEN[name] = factory


def register_save(name, func):
    SAVE[name] = func


def open(fp):
    for factory in OPEN.values():
        im = factory(fp)
        return im


class Image:
    def load(self):
        return None

    def save(self, fp, format):
        save_handler = SAVE[format]
        save_handler(self, fp)

    def convert(self, mode):
        return ImageColor.getrgb(mode)
""",
    "PIL/ImageFile.py": """\
from . import Image


class ImageFile(Image.Image):
    def __init__(self, fp):
        self.fp = fp
        self._open()
""",
    "PIL/IcoPlugin.py": """\
from . import Image, ImageFile


class IcoFile:
    def __init__(self, fp):
        self.fp = fp

    def frame(self, idx):
        return idx

    def getimage(self):
        return self.frame(0)


class IcoImageFile(ImageFile.ImageFile):
    def _open(self):
        self.ico = IcoFile(self.fp)
        self.load()

    def load(self):
        return self.ico.getimage()


def _save(im, fp):
    return None


Image.register_open("ICO", IcoImageFile)
Image.register_save("ICO", _save)
""",
    "PIL/ImageColor.py": "def getrgb(color):\n    return color\n",
    "PIL/ImageMath.py": "def eval(expression):\n    return expression\n",
}

PROJECT = {
    "shop/__init__.py": "",
    "shop/views.py": """\
from PIL import Image
from shop.forms import UploadForm


def upload(request):
    form = UploadForm(request)
    return form.validate()


def thumbnail(fp):
    im = Image.open(fp)
    return im


def color(name):
    im = Image.Image()
    return im.convert(name)


def process(obj):
    return obj.frame(1)


def text(value):
    return "{}".format(value).split(",")
""",
    "shop/forms.py": """\
class UploadForm:
    def __init__(self, request):
        self.request = request

    def validate(self):
        return self.clean()

    def clean(self):
        return True


class OtherForm(UploadForm):
    def clean(self):
        return False
""",
    "shop/tests.py": "import PIL.ImageMath\n",
}

FRAME = "PIL.IcoPlugin.IcoFile.frame"


def write_project(root: Path, files: dict[str, str] | None = None) -> Path:
    for rel, text in (files or PROJECT).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def build(
    tmp: Path,
    *,
    library: dict[str, str] | None = None,
    project: dict[str, str] | None = None,
) -> tuple[ModuleReach, CodeIndex, dict[Package, SourceTree]]:
    trees = {PILLOW: make_tree(tmp / "sources", PILLOW, library or LIBRARY)}
    root = write_project(tmp / "project", project)
    reach = module_reachability(root, trees, {})
    return reach, CodeIndex(reach), trees
