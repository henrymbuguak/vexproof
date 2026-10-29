from __future__ import annotations

from pathlib import Path

import pytest

from tests.codebase import FRAME, build
from vexproof.evidence.paths import (
    PathRejected,
    Step,
    VerifiedPath,
    find_path,
    registry_edges,
    verify_path,
)
from vexproof.static.codeindex import CodeIndex

THUMB = "shop.views.thumbnail"
CERTAIN_CHAIN = [
    Step("shop.views.thumbnail", 11),
    Step("PIL.Image.open", 23),
    Step("PIL.ImageFile.ImageFile.__init__", 7),
    Step("PIL.IcoPlugin.IcoImageFile._open", 18),
    Step("PIL.IcoPlugin.IcoImageFile.load", 21),
    Step("PIL.IcoPlugin.IcoFile.getimage", 12),
    Step(FRAME, 8),
]


@pytest.fixture
def index(tmp_path: Path) -> CodeIndex:
    return build(tmp_path)[1]


def test_a_certain_chain_through_the_plugin_registry(index: CodeIndex) -> None:
    result = verify_path(CERTAIN_CHAIN, FRAME, index)
    assert isinstance(result, VerifiedPath), result
    assert result.possible_hops == 0
    assert [h.via for h in result.hops] == [
        "start", "call", "pillow_open_registry", "call", "call", "call", "call"
    ]  # fmt: skip
    assert result.hops[0].file == "shop/views.py"
    assert result.hops[-1].line == 8  # the target's definition
    assert result.render().startswith("shop.views.thumbnail -> PIL.Image.open")


def test_types_carried_along_the_path(index: CodeIndex) -> None:
    # upload builds an UploadForm, so self.clean() inside validate is UploadForm's
    ok = verify_path(
        [Step("shop.views.upload", 7), Step("shop.forms.UploadForm.validate", 6),
         Step("shop.forms.UploadForm.clean", 8)],
        "shop.forms.UploadForm.clean",
        index,
    )  # fmt: skip
    assert isinstance(ok, VerifiedPath)
    wrong = verify_path(
        [Step("shop.views.upload", 7), Step("shop.forms.UploadForm.validate", 6),
         Step("shop.forms.OtherForm.clean", 13)],
        "shop.forms.OtherForm.clean",
        index,
    )  # fmt: skip
    assert isinstance(wrong, PathRejected)
    assert "when self is a shop.forms.UploadForm" in wrong.reasons[0]
    assert wrong.blame == "shop.views.upload"


@pytest.mark.parametrize(
    ("steps", "reason"),
    [
        ([], "empty"),
        ([Step("shop.views.thumbnail", 11), Step("PIL.Image.open", 23)], "must end at"),
        ([Step("PIL.Image.open", 23), Step(FRAME, 8)], "project's own code"),
        ([Step(THUMB, 11), Step("no.such.thing", 1), Step(FRAME, 8)], "not a known"),
        ([Step(THUMB, 11), Step("PIL.ImageMath.eval", 1), Step(FRAME, 8)], "never loads"),
        ([Step("shop.views.color", 17), Step(FRAME, 8)], "does not call or refer"),
        ([Step("shop.views.process", 21), Step("shop.views.process", 21), Step(FRAME, 8)], "twice"),
    ],
)  # fmt: skip
def test_rejections(index: CodeIndex, steps: list[Step], reason: str) -> None:
    target = steps[-1].symbol if reason == "does not call or refer" else FRAME
    result = verify_path(steps, target, index)
    assert isinstance(result, PathRejected)
    assert any(reason in r for r in result.reasons), result.reasons


def test_too_long(index: CodeIndex) -> None:
    result = verify_path([Step("shop.views.process", 21)] * 40, FRAME, index)
    assert isinstance(result, PathRejected)
    assert "more than" in result.reasons[0]


def test_registry_edges_and_save_rule(index: CodeIndex) -> None:
    edges = registry_edges(index)
    assert [(s.qualname, how) for s, _, how in edges["PIL.ImageFile.ImageFile.__init__"]] == [
        ("PIL.Image.open", "pillow_open_registry")
    ]
    assert [(s.qualname, line) for s, line, _ in edges["PIL.IcoPlugin._save"]] == [
        ("PIL.Image.Image.save", 33)  # the save_handler(...) line
    ]


def test_find_path_prefers_certain_when_asked(index: CodeIndex) -> None:
    frame = index.scope(FRAME)
    assert frame
    extra = registry_edges(index)
    certain = find_path(frame, index, extra, certain_only=True)
    assert certain.path is not None
    assert certain.path.possible_hops == 0
    assert certain.path.hops[0].symbol == "shop.views.thumbnail"
    loose = find_path(frame, index, extra)
    assert loose.path is not None
    assert loose.path.possible_hops == 1  # shop.views.process -> frame is cheaper but uncertain
    routed = find_path(frame, index, extra, through=["PIL.Image.open"])
    assert routed.path is not None
    assert "PIL.Image.open" in [h.symbol for h in routed.path.hops]
    assert find_path(frame, index, extra, through=["no.such"]).rejected == (
        "no.such is not a known function in loaded code",
    )
    blocked = find_path(frame, index, extra, avoid={"shop.views.process", "shop.views.thumbnail"})
    assert blocked.path is None


def test_find_path_searches_again_around_a_type_conflict(index: CodeIndex) -> None:
    other = index.scope("shop.forms.OtherForm.clean")
    assert other
    result = find_path(other, index, {}, through=["shop.views.upload"])
    assert result.path is None  # the only route from upload has the wrong self type
    assert "when self is a shop.forms.UploadForm" in result.rejected[0]


def test_a_wrong_line_is_corrected_when_another_line_works(index: CodeIndex) -> None:
    result = verify_path([Step(THUMB, 3), Step("PIL.Image.open", 23)], "PIL.Image.open", index)
    assert isinstance(result, VerifiedPath)
    assert result.hops[0].line == 11  # where thumbnail actually calls Image.open


SETTINGS_LIBRARY = {
    "PIL/Hooks.py": """\
class Mixin:
    def __call__(self, request):
        return self.process_request(request)


class First(Mixin):
    def process_request(self, request):
        return request


class Common(Mixin):
    def process_request(self, request):
        return self.slash(request)

    def slash(self, request):
        return request
""",
}
SETTINGS = 'HOOKS = [\n    "PIL.Hooks.First",\n    "PIL.Hooks.Common",\n]\n'


def test_classes_named_in_settings(tmp_path: Path) -> None:
    from tests.codebase import LIBRARY, PROJECT

    _, index, _ = build(
        tmp_path,
        library={**LIBRARY, **SETTINGS_LIBRARY},
        project={**PROJECT, "shop/settings.py": SETTINGS},
    )
    slash = index.scope("PIL.Hooks.Common.slash")
    assert slash is not None
    result = find_path(slash, index, {})
    assert result.path is not None
    assert [(h.symbol, h.line, h.via, h.certain) for h in result.path.hops] == [
        ("shop.settings", 3, "start", True),  # the line naming Common, not First on line 2
        ("PIL.Hooks.Mixin.__call__", 3, "string", False),  # called by convention: reviewed
        ("PIL.Hooks.Common.process_request", 13, "call", True),
        ("PIL.Hooks.Common.slash", 15, "call", True),
    ]


VIEWS_LIBRARY = {
    "django/__init__.py": "",
    "django/views/__init__.py": "",
    "django/views/generic/__init__.py": "",
    "django/views/generic/base.py": """\
class View:
    @classmethod
    def as_view(cls):
        def view(request):
            self = cls()
            return self.dispatch(request)

        return view

    def dispatch(self, request):
        handler = getattr(self, request.method.lower())
        return handler(request)
""",
}
PAGES = """\
from django.views.generic.base import View


class Page(View):
    def post(self, request):
        return request


class Other(View):
    def post(self, request):
        return request


ROUTE = Page.as_view()
"""


def test_django_class_based_view_dispatch(tmp_path: Path) -> None:
    from tests.codebase import LIBRARY, PROJECT

    _, index, _ = build(
        tmp_path,
        library={**LIBRARY, **VIEWS_LIBRARY},
        project={**PROJECT, "shop/pages.py": PAGES},
    )
    route = [
        Step("shop.pages", 14),
        Step("django.views.generic.base.View.as_view", 6),
        Step("django.views.generic.base.View.dispatch", 11),
    ]
    page = verify_path([*route, Step("shop.pages.Page.post", 5)], "shop.pages.Page.post", index)
    assert isinstance(page, VerifiedPath), page
    assert [h.via for h in page.hops] == ["start", "call", "call", "django_view_dispatch"]
    assert page.possible_hops == 0  # Page.as_view() fixes the class of self all the way down
    other = verify_path([*route, Step("shop.pages.Other.post", 10)], "shop.pages.Other.post", index)
    assert isinstance(other, PathRejected)  # the dispatched view is a Page, not an Other
    edges = registry_edges(index)
    assert {s.qualname for s, _, _ in edges["shop.pages.Page.post"]} == {
        "django.views.generic.base.View.dispatch"
    }
