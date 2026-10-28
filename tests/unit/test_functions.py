from __future__ import annotations

from vexproof.static.functions import enclosing, function_spans

CODE = """import sys


@decorator
def top(a):
    def inner():
        return a
    return inner


class Outer:
    attr = 1

    def method(self):
        pass

    class Inner:
        async def deep(self):
            pass


if sys.version_info >= (3,):
    def conditional():
        pass
"""


def test_spans_qualnames_and_decorators() -> None:
    spans = {s.qualname: (s.start, s.end, s.col) for s in function_spans(CODE)}
    assert spans == {
        "top": (4, 8, 0),
        "Outer.method": (14, 15, 4),
        "Outer.Inner.deep": (18, 19, 8),
        "conditional": (23, 24, 4),
    }


def test_enclosing_lines_and_insertions() -> None:
    spans = function_spans(CODE)
    assert enclosing(spans, 6) is not None
    assert enclosing(spans, 6).qualname == "top"  # type: ignore[union-attr]  # nested -> outer
    assert enclosing(spans, 12) is None  # class attribute: module-level code
    assert enclosing(spans, 19).qualname == "Outer.Inner.deep"  # type: ignore[union-attr]
    # insertion after the last line of `method`: inside only if indented deeper than the def
    assert enclosing(spans, 15, indent=8).qualname == "Outer.method"  # type: ignore[union-attr]
    assert enclosing(spans, 15, indent=4) is None


def test_unparseable_source_has_no_spans() -> None:
    assert function_spans("def broken(:\n") == []
    assert function_spans('x = "\\d"\ndef f():\n    pass\n')[0].qualname == "f"
