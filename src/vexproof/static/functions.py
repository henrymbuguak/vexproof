"""Where each function of a module starts and ends: the "callable surface" of a file.

Recorded: module-level functions and methods of (nested) classes, by qualified name such as
`Image.open` or `ImageFile.Parser.feed`. Functions defined inside other functions are folded
into their outer function, because only the outer one can be called from other code.
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass


@dataclass(frozen=True)
class FunctionSpan:
    qualname: str
    start: int  # first decorator line, or the def line
    end: int
    col: int  # indentation of the def


def function_spans(text: str) -> list[FunctionSpan]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    spans: list[FunctionSpan] = []

    def visit(body: list[ast.stmt], prefix: str) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, f"{prefix}{node.name}.")
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
                spans.append(
                    FunctionSpan(
                        f"{prefix}{node.name}",
                        start,
                        node.end_lineno or node.lineno,
                        node.col_offset,
                    )
                )
            elif isinstance(node, ast.If | ast.Try | ast.With):
                # functions defined conditionally (if PY2: def f...) are still module functions
                for block in _blocks(node):
                    visit(block, prefix)

    visit(tree.body, "")
    return spans


def _blocks(node: ast.If | ast.Try | ast.With) -> list[list[ast.stmt]]:
    if isinstance(node, ast.If):
        return [node.body, node.orelse]
    if isinstance(node, ast.Try):
        return [node.body, *(h.body for h in node.handlers), node.orelse, node.finalbody]
    return [node.body]


def enclosing(
    spans: list[FunctionSpan], line: int, indent: int | None = None
) -> FunctionSpan | None:
    """The innermost recorded function containing `line`.

    For a pure insertion after `line` (indent given), a function also contains it when `line` is
    its last line and the inserted code is indented deeper than the def, i.e. appended to its body.
    """
    best: FunctionSpan | None = None
    for span in spans:
        inside = span.start <= line < span.end or (
            line == span.end and (indent is None or indent > span.col)
        )
        if inside and (best is None or span.start >= best.start):
            best = span
    return best
