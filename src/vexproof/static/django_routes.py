"""Routes Django takes on the project's behalf, found in the project's own code.

Some calls happen because of a declaration rather than a call in the code. One matters a lot for
image and file libraries: a model registered with a mounted admin site gets add and change pages,
and saving one validates each file field with the form field Django maps it to. For
`models.ImageField` that is `django.forms.fields.ImageField.to_python`, which opens the upload
with `PIL.Image.open`.

A route is reported only when all three are visible in project code:
- a model class with a `models.ImageField(...)` or `models.FileField(...)` attribute;
- `admin.site.register(Model, ...)` or `@admin.register(Model)` for that model;
- the admin site's URLs mounted somewhere (`admin.site.urls`).

The second route is the admin login page. Mounting the admin site serves `login/`, and
`AdminSite.login` validates every attempt with `AdminAuthenticationForm` unless the project sets
its own `login_form`; that form's `clean()` (inherited from `AuthenticationForm`) checks the
username and password a visitor typed. Reported when the admin site is mounted and project code
never assigns `login_form`.
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass

from vexproof.static.codeindex import CodeIndex

MODEL_FILE_FIELDS = {
    "django.db.models.fields.files.ImageField": "django.forms.fields.ImageField",
    "django.db.models.fields.files.FileField": "django.forms.fields.FileField",
}
_ADMIN = "django.contrib.admin"


@dataclass(frozen=True)
class Route:
    caller: str  # project module that registers the model
    line: int
    callee: str  # the form field's to_python
    rule: str
    note: str


@dataclass(frozen=True)
class _FileField:
    model: str
    name: str
    form_field: str
    where: str  # "shop/models.py:25"


def _parse(text: str) -> ast.Module | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def _dotted(node: ast.expr, bindings: dict[str, str]) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in bindings:
        return ""
    return ".".join([bindings[node.id], *reversed(parts)])


def _modules(index: CodeIndex) -> list[tuple[str, ast.Module, dict[str, str], str]]:
    found = []
    for module in sorted(index.reach.project_modules):
        source = index.reach.modules[module]
        code = index.code(module)
        tree = _parse(source.path.read_text(encoding="utf-8", errors="replace"))
        if code is not None and tree is not None:
            found.append((module, tree, code.bindings, source.rel))
    return found


def _file_fields(index: CodeIndex) -> dict[str, list[_FileField]]:
    """Project model class (dotted) -> its file fields."""
    fields: dict[str, list[_FileField]] = {}
    for module, tree, bindings, rel in _modules(index):
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            for stmt in node.body:
                if not (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)):
                    continue
                kind = index.resolve(_dotted(stmt.value.func, bindings))
                if kind in MODEL_FILE_FIELDS:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            fields.setdefault(f"{module}.{node.name}", []).append(
                                _FileField(
                                    f"{module}.{node.name}",
                                    target.id,
                                    MODEL_FILE_FIELDS[kind],
                                    f"{rel}:{stmt.lineno}",
                                )
                            )
    return fields


def _registrations(index: CodeIndex) -> list[tuple[str, int, str]]:
    """(project module, line, model dotted) for every admin registration."""
    found: list[tuple[str, int, str]] = []
    for module, tree, bindings, _ in _modules(index):
        for call in ast.walk(tree):  # admin.site.register(M, ...) and @admin.register(M)
            if isinstance(call, ast.Call):
                target = _dotted(call.func, bindings)
                if target.startswith(_ADMIN) and target.endswith("register"):
                    found += [
                        (module, call.lineno, index.resolve(_dotted(arg, bindings)))
                        for arg in call.args
                        if isinstance(arg, ast.Name) and _dotted(arg, bindings)
                    ]
    return found


def _admin_mounts(index: CodeIndex) -> list[tuple[str, int]]:
    """(project module, line) of every `admin.site.urls` in project code."""
    found = []
    for module in sorted(index.reach.project_modules):
        scope = index.scope(module)
        if scope:
            found += [
                (module, s.line)
                for s in scope.sites
                if s.name == "urls" and s.ref.startswith(_ADMIN)
            ]
    return found


def _admin_mounted(index: CodeIndex) -> bool:
    return bool(_admin_mounts(index))


def _sets_login_form(index: CodeIndex) -> bool:
    for _, tree, _, _ in _modules(index):
        for node in ast.walk(tree):
            targets = node.targets if isinstance(node, ast.Assign) else []
            for target in targets:
                name = target.attr if isinstance(target, ast.Attribute) else ""
                name = target.id if isinstance(target, ast.Name) else name
                if name == "login_form":
                    return True
    return False


ADMIN_LOGIN_FORM = "django.contrib.admin.forms.AdminAuthenticationForm"


def admin_login_routes(index: CodeIndex) -> list[Route]:
    """The admin login page: every attempt is validated by the admin's authentication form."""
    if not index.reach.is_reached(f"{_ADMIN}.sites") or _sets_login_form(index):
        return []
    owner = index.mro_owner(ADMIN_LOGIN_FORM, "clean")
    if owner is None:
        return []
    return [
        Route(
            caller=module,
            line=line,
            callee=f"{owner}.clean",
            rule="django_admin_login",
            note=(
                f"the admin site mounted here serves a login page that validates every attempt "
                f"with {ADMIN_LOGIN_FORM} (clean() from {owner})"
            ),
        )
        for module, line in _admin_mounts(index)
    ]


def admin_upload_routes(index: CodeIndex) -> list[Route]:
    """Admin pages that validate uploads to a project model's image or file fields."""
    if not index.reach.is_reached(f"{_ADMIN}.options") or not _admin_mounted(index):
        return []
    fields = _file_fields(index)
    routes: list[Route] = []
    for module, line, model in _registrations(index):
        for field in fields.get(model, []):
            routes.append(
                Route(
                    caller=module,
                    line=line,
                    callee=f"{field.form_field}.to_python",
                    rule="django_admin_upload",
                    note=(
                        f"the admin form for {model} validates uploads to its "
                        f"'{field.name}' field ({field.where}) with {field.form_field}"
                    ),
                )
            )
    return sorted(set(routes), key=lambda r: (r.caller, r.line, r.callee))
