"""Workload for henrymbuguak/Shopping-Cart-Using-Django-2.0-and-Python-3.6.

What a visitor and a shop admin actually do: browse, add to cart, check out, log in to the
admin, and upload a product image in each format a browser or attacker could send. Test images
are made in a separate process, so making them does not count as the app running code.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
from pathlib import Path

# Made by the project's own Pillow in a child process (see make_images).
FORMATS = ["png", "jpeg", "gif", "ico", "bmp", "pcx", "tiff", "xbm", "eps", "dcx", "psd", "fpx"]

_MAKE = r"""
import io, struct, sys
from pathlib import Path
from PIL import Image
out = Path(sys.argv[1])
rgb = Image.new("RGB", (16, 16), (200, 30, 30))
rgb.save(str(out / "upload.ico"), "ICO", sizes=[(16, 16)])
for fmt, ext in [("PNG", "png"), ("JPEG", "jpeg"), ("BMP", "bmp"),
                 ("PCX", "pcx"), ("TIFF", "tiff"), ("EPS", "eps")]:
    rgb.save(str(out / ("upload." + ext)), fmt)
frames = [Image.new("P", (8, 8), i) for i in (1, 2)]
frames[0].save(str(out / "upload.gif"), "GIF", save_all=True, append_images=frames[1:])
rgb.convert("1").save(str(out / "upload.xbm"), "XBM")
pcx = io.BytesIO(); rgb.save(pcx, "PCX")
# DCX: magic, one component offset, end of directory, then a PCX image
(out / "upload.dcx").write_bytes(struct.pack("<III", 0x3ADE68B1, 12, 0) + pcx.getvalue())
"""


def _psd():
    """A 1x1 RGB Photoshop file with an empty layer table, so the layer parser runs."""
    header = b"8BPS" + struct.pack(">H6xHIIHH", 1, 3, 1, 1, 8, 3)
    layers = struct.pack(">I", 2) + struct.pack(">h", 0)  # layer info: 0 layers
    sections = struct.pack(">I", 0) + struct.pack(">I", 0) + struct.pack(">I", len(layers)) + layers
    return header + sections + struct.pack(">H", 0) + b"\x00\x00\x00"


def _fpx():
    """An OLE2 compound file whose root has the FlashPix class id and nothing else.

    Enough for Pillow to pick its FlashPix reader and start parsing; the image itself is empty.
    """
    endchain, free, nostream = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF
    header = (
        bytes.fromhex("D0CF11E0A1B11AE1") + bytes(16)
        + struct.pack("<HHHHH6xIIIIIIIII", 0x3E, 3, 0xFFFE, 9, 6, 0, 1, 1, 0, 4096,
                      endchain, 0, endchain, 0)
        + struct.pack("<109I", 0, *([free] * 108))
    )
    fat = struct.pack("<128I", 0xFFFFFFFD, endchain, *([free] * 126))
    name = "Root Entry".encode("utf-16-le") + b"\x00\x00"
    clsid = struct.pack("<IHH", 0x56616700, 0xC154, 0x11CE) + bytes.fromhex("855300AA00A1F95B")
    root = (
        name.ljust(64, b"\x00") + struct.pack("<HBBIII", len(name), 5, 1, nostream, nostream,
                                               nostream)
        + clsid + struct.pack("<IQQIQ", 0, 0, 0, endchain, 0)
    )
    empty = bytes(64) + struct.pack("<HBBIII", 0, 0, 0, nostream, nostream, nostream) + bytes(52)
    return header + fat + root + empty * 3


def make_images(scratch):
    folder = scratch / "images"
    folder.mkdir(exist_ok=True)
    subprocess.run([sys.executable, "-c", _MAKE, str(folder)], check=True)  # noqa: S603
    (folder / "upload.psd").write_bytes(_psd())
    (folder / "upload.fpx").write_bytes(_fpx())
    return folder


def setup(project, settings, scratch):
    """Before observation: a throwaway database, an admin user and one product."""
    images = make_images(scratch)
    (scratch / "eval_settings.py").write_text(
        "from {} import *  # noqa\n"
        "DATABASES = {{'default': {{'ENGINE': 'django.db.backends.sqlite3', "
        "'NAME': {!r}}}}}\n"
        "MEDIA_ROOT = {!r}\n"
        "ALLOWED_HOSTS = ['testserver']\n".format(
            settings, str(scratch / "db.sqlite3"), str(scratch / "media")
        ),
        encoding="utf-8",
    )
    sys.path.insert(0, str(scratch))
    os.environ["DJANGO_SETTINGS_MODULE"] = "eval_settings"
    import django  # noqa: PLC0415

    django.setup()
    from django.core.management import call_command  # noqa: PLC0415
    from django.db.backends.signals import connection_created  # noqa: PLC0415

    # Django 2.0 predates SQLite 3.26's ALTER TABLE change (fixed in Django 2.0.10); restore
    # the old behaviour so its migrations run on a current SQLite.
    connection_created.connect(
        lambda connection, **_: connection.cursor().execute("PRAGMA legacy_alter_table = ON"),
        weak=False,
    )

    call_command("migrate", run_syncdb=True, verbosity=0)  # the repo ships no migrations
    from django.contrib.auth import get_user_model  # noqa: PLC0415
    from shop.models import Category, Product  # noqa: PLC0415

    get_user_model().objects.create_superuser("admin", "admin@example.com", "s3cret-pass")
    category = Category.objects.create(name="Shoes", slug="shoes")
    Product.objects.create(
        category=category, name="Red shoe", slug="red-shoe", price="49.90", stock=5
    )
    return {"images": images, "category": category.id}


def run(project, settings, scratch, state):
    from django.test import Client  # noqa: PLC0415
    from django.test.utils import setup_test_environment  # noqa: PLC0415
    from django.urls import reverse  # noqa: PLC0415

    setup_test_environment()
    client = Client()
    steps = []

    def step(name, response):
        steps.append({"step": name, "status": response.status_code})

    step("home", client.get("/"))
    step("category", client.get("/shoes/"))
    step("product", client.get("/1/red-shoe/"))
    # the project mounts the cart at 'cart' without a slash, so ask its URLconf for the paths
    step("cart add", client.post(reverse("cart:cart_add", args=[1]), {"quantity": "2"}))
    step("cart", client.get(reverse("cart:cart_detail")))
    step("checkout form", client.get("/orders/create/"))
    step("no trailing slash", client.get("/orders/create"))
    step("not found", client.get("/no/such/page/"))
    step(
        "checkout",
        client.post(
            "/orders/create/",
            {"first_name": "Ann", "last_name": "Lee", "email": "ann@example.com",
             "address": "1 Road", "postal_code": "00100", "city": "Nairobi"},
        ),
    )
    step("cart add again", client.post(reverse("cart:cart_add", args=[1]), {"quantity": "1"}))
    step("cart remove", client.get(reverse("cart:cart_remove", args=[1])))
    step("admin redirect", client.get("/admin"))
    step("admin login form", client.get("/admin/login/"))
    step("admin bad login", client.post("/admin/login/", {"username": "admin", "password": "x"}))
    step(
        "admin login",
        client.post(
            "/admin/login/", {"username": "admin", "password": "s3cret-pass", "next": "/admin/"}
        ),
    )
    step("admin products", client.get("/admin/shop/product/"))
    step("admin add form", client.get("/admin/shop/product/add/"))
    for fmt in FORMATS:
        path = Path(state["images"]) / ("upload." + fmt)
        with path.open("rb") as image:
            response = client.post(
                "/admin/shop/product/add/",
                {"category": state["category"], "name": "Upload " + fmt, "slug": "up-" + fmt,
                 "description": "", "price": "1.00", "stock": "1", "available": "on",
                 "image": image},
            )
        step("admin upload " + fmt, response)
    step("admin logout", client.get("/admin/logout/"))
    return steps
