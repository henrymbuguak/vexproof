from __future__ import annotations

from pathlib import Path

from tests.codebase import LIBRARY, PROJECT, build
from vexproof.evidence.paths import Step, VerifiedPath, registry_edges, verify_path
from vexproof.static.django_routes import admin_login_routes, admin_upload_routes

DJANGO = {
    "django/__init__.py": "",
    "django/db/__init__.py": "",
    "django/db/models/__init__.py": "from django.db.models.fields.files import ImageField\n"
    "class Model:\n    pass\n",
    "django/db/models/fields/__init__.py": "",
    "django/db/models/fields/files.py": "class ImageField:\n    pass\n",
    "django/forms/__init__.py": "",
    "django/forms/fields.py": """\
from PIL import Image


class ImageField:
    def to_python(self, data):
        return Image.open(data)
""",
    "django/contrib/__init__.py": "",
    "django/contrib/admin/__init__.py": "from django.contrib.admin.sites import site\n"
    "from django.contrib.admin import options\n",
    "django/contrib/admin/options.py": "class ModelAdmin:\n    pass\n",
    "django/contrib/admin/sites.py": """\
import django.forms.fields
from django.contrib.admin.forms import AdminAuthenticationForm


class AdminSite:
    def register(self, model, admin_class=None):
        return model

    @property
    def urls(self):
        return []


site = AdminSite()
""",
    "django/contrib/admin/forms.py": """\
from django.contrib.auth.forms import AuthenticationForm


class AdminAuthenticationForm(AuthenticationForm):
    def confirm_login_allowed(self, user):
        return user
""",
    "django/contrib/auth/__init__.py": "",
    "django/contrib/auth/forms.py": """\
class AuthenticationForm:
    def clean(self):
        return self.confirm_login_allowed(None)

    def confirm_login_allowed(self, user):
        return user
""",
}
SHOP = {
    "shop/models.py": "from django.db import models\n\n\nclass Product(models.Model):\n"
    "    image = models.ImageField()\n",
    "shop/admin.py": "from django.contrib import admin\nfrom .models import Product\n\n"
    "admin.site.register(Product)\n",
    "shop/urls.py": "from django.contrib import admin\n\nurlpatterns = [admin.site.urls]\n",
}


def test_admin_upload_route(tmp_path: Path) -> None:
    _, index, _ = build(tmp_path, library={**LIBRARY, **DJANGO}, project={**PROJECT, **SHOP})
    routes = admin_upload_routes(index)
    assert [(r.caller, r.line, r.callee, r.rule) for r in routes] == [
        ("shop.admin", 4, "django.forms.fields.ImageField.to_python", "django_admin_upload")
    ]
    assert routes[0].note == (
        "the admin form for shop.models.Product validates uploads to its 'image' field "
        "(shop/models.py:5) with django.forms.fields.ImageField"
    )
    registry_edges(index)  # registers the route with the verifier
    path = verify_path(
        [
            Step("shop.admin", 4),
            Step("django.forms.fields.ImageField.to_python", 6),
            Step("PIL.Image.open", 23),
            Step("PIL.ImageFile.ImageFile.__init__", 7),
            Step("PIL.IcoPlugin.IcoImageFile._open", 18),
            Step("PIL.IcoPlugin.IcoImageFile.load", 21),
            Step("PIL.IcoPlugin.IcoFile.getimage", 12),
            Step("PIL.IcoPlugin.IcoFile.frame", 8),
        ],
        "PIL.IcoPlugin.IcoFile.frame",
        index,
    )
    assert isinstance(path, VerifiedPath), path
    assert path.possible_hops == 0
    assert path.hops[1].via == "django_admin_upload"


def test_no_route_without_all_three(tmp_path: Path) -> None:
    unmounted = {**SHOP, "shop/urls.py": "urlpatterns = []\n"}
    _, index, _ = build(
        tmp_path / "a", library={**LIBRARY, **DJANGO}, project={**PROJECT, **unmounted}
    )
    assert admin_upload_routes(index) == []
    unregistered = {**SHOP, "shop/admin.py": "from django.contrib import admin\n"}
    _, index, _ = build(
        tmp_path / "b", library={**LIBRARY, **DJANGO}, project={**PROJECT, **unregistered}
    )
    assert admin_upload_routes(index) == []


def test_admin_login_route(tmp_path: Path) -> None:
    _, index, _ = build(tmp_path, library={**LIBRARY, **DJANGO}, project={**PROJECT, **SHOP})
    routes = admin_login_routes(index)
    assert [(r.caller, r.line, r.callee, r.rule) for r in routes] == [
        ("shop.urls", 3, "django.contrib.auth.forms.AuthenticationForm.clean", "django_admin_login")
    ]
    assert "AdminAuthenticationForm (clean() from django.contrib.auth.forms" in routes[0].note
    registry_edges(index)
    path = verify_path(
        [Step("shop.urls", 3), Step("django.contrib.auth.forms.AuthenticationForm.clean", 2)],
        "django.contrib.auth.forms.AuthenticationForm.clean",
        index,
    )
    assert isinstance(path, VerifiedPath), path
    assert path.hops[1].via == "django_admin_login"


def test_no_login_route_with_a_custom_login_form_or_no_mount(tmp_path: Path) -> None:
    custom = {**SHOP, "shop/admin.py": SHOP["shop/admin.py"] + "admin.site.login_form = None\n"}
    _, index, _ = build(
        tmp_path / "a", library={**LIBRARY, **DJANGO}, project={**PROJECT, **custom}
    )
    assert admin_login_routes(index) == []
    unmounted = {**SHOP, "shop/urls.py": "urlpatterns = []\n"}
    _, index, _ = build(
        tmp_path / "b", library={**LIBRARY, **DJANGO}, project={**PROJECT, **unmounted}
    )
    assert admin_login_routes(index) == []
