"""Workload for justdjango/django-ecommerce at 260952e7 (Django 2.2, allauth, debug toolbar).

A visitor browses, signs up, fills a cart, checks out, applies a coupon and asks for a refund;
an admin logs in and uploads item images in every format. Payment is left out: it calls Stripe
over the network. Settings are the project's own development settings (DEBUG on, debug toolbar
on), so the most code loads.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from shop import FORMATS, make_images  # noqa: E402 - the same test images as the shop


def setup(project, settings, scratch):
    images = make_images(scratch)
    # python-decouple reads these from the environment; the values are placeholders
    os.environ.update(
        SECRET_KEY="eval-only-not-secret",
        STRIPE_TEST_PUBLIC_KEY="pk_test_eval",
        STRIPE_TEST_SECRET_KEY="sk_test_eval",
    )
    (scratch / "eval_settings.py").write_text(
        "from {} import *  # noqa\n"
        "DATABASES = {{'default': {{'ENGINE': 'django.db.backends.sqlite3', "
        "'NAME': {!r}}}}}\n"
        "MEDIA_ROOT = {!r}\n"
        "ALLOWED_HOSTS = ['testserver']\n"
        "EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'\n".format(
            settings, str(scratch / "db.sqlite3"), str(scratch / "media")
        ),
        encoding="utf-8",
    )
    sys.path.insert(0, str(scratch))
    os.environ["DJANGO_SETTINGS_MODULE"] = "eval_settings"
    import django  # noqa: PLC0415

    django.setup()
    from django.core.management import call_command  # noqa: PLC0415

    call_command("migrate", verbosity=0)
    from django.contrib.auth import get_user_model  # noqa: PLC0415
    from core.models import Coupon, Item  # noqa: PLC0415

    get_user_model().objects.create_superuser("admin", "admin@example.com", "s3cret-pass")
    Item.objects.create(
        title="Red shirt", price=20.0, category="S", label="P", slug="red-shirt",
        description="A shirt", image="red.png",
    )
    Coupon.objects.create(code="SAVE5", amount=5)
    return {"images": images}


def run(project, settings, scratch, state):
    from django.test import Client  # noqa: PLC0415
    from django.test.utils import setup_test_environment  # noqa: PLC0415

    setup_test_environment()
    visitor, admin = Client(), Client()
    steps = []

    def step(name, call):
        # the project has bugs of its own (a bad coupon raises); record them and carry on
        try:
            steps.append({"step": name, "status": call().status_code})
        except Exception as exc:  # noqa: BLE001
            steps.append({"step": name, "status": "error: " + type(exc).__name__, "detail": str(exc)[:200]})

    step("home", lambda: visitor.get("/"))
    step("product", lambda: visitor.get("/product/red-shirt/"))
    step("no trailing slash", lambda: visitor.get("/checkout"))
    step("not found", lambda: visitor.get("/no/such/page/"))
    step("signup form", lambda: visitor.get("/accounts/signup/"))
    step(
        "signup",
        lambda: visitor.post(
            "/accounts/signup/",
            {"email": "ann@example.com", "username": "ann", "password1": "Tr0ub4dor&3x",
             "password2": "Tr0ub4dor&3x"},
        ),
    )
    step("logout", lambda: visitor.post("/accounts/logout/"))
    step("bad login", lambda: visitor.post("/accounts/login/", {"login": "ann", "password": "x"}))
    step("login", lambda: visitor.post("/accounts/login/", {"login": "ann", "password": "Tr0ub4dor&3x"}))
    step("password reset form", lambda: visitor.get("/accounts/password/reset/"))
    step("password reset", lambda: visitor.post("/accounts/password/reset/", {"email": "ann@example.com"}))
    step("add to cart", lambda: visitor.get("/add-to-cart/red-shirt/"))
    step("add again", lambda: visitor.get("/add-to-cart/red-shirt/"))
    step("remove one", lambda: visitor.get("/remove-item-from-cart/red-shirt/"))
    step("order summary", lambda: visitor.get("/order-summary/"))
    step("checkout form", lambda: visitor.get("/checkout/"))
    step(
        "checkout",
        lambda: visitor.post(
            "/checkout/",
            {"shipping_address": "1 Road", "shipping_address2": "", "shipping_country": "KE",
             "shipping_zip": "00100", "same_billing_address": "on", "set_default_shipping": "on",
             "payment_option": "S"},
        ),
    )
    step("coupon", lambda: visitor.post("/add-coupon/", {"code": "SAVE5"}))
    step("bad coupon", lambda: visitor.post("/add-coupon/", {"code": "NOPE"}))
    step("refund form", lambda: visitor.get("/request-refund/"))
    step(
        "refund",
        lambda: visitor.post(
            "/request-refund/",
            {"ref_code": "abc", "message": "Too small", "email": "ann@example.com"},
        ),
    )
    step("remove from cart", lambda: visitor.get("/remove-from-cart/red-shirt/"))

    step("admin login form", lambda: admin.get("/admin/login/"))
    step(
        "admin login",
        lambda: admin.post("/admin/login/", {"username": "admin", "password": "s3cret-pass",
                                     "next": "/admin/"}),
    )
    step("admin items", lambda: admin.get("/admin/core/item/"))
    step("admin add form", lambda: admin.get("/admin/core/item/add/"))
    for fmt in FORMATS:
        path = Path(state["images"]) / ("upload." + fmt)
        with path.open("rb") as image:
            step(
                "admin upload " + fmt,
                lambda: admin.post(
                    "/admin/core/item/add/",
                    {"title": "Upload " + fmt, "price": "1", "category": "S", "label": "P",
                     "slug": "up-" + fmt, "description": "x", "image": image},
                ),
            )
    return steps
