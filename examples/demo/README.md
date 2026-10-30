# Demo result

`findings.json` here is a real scan of the demo project, which the web app shows as
**Demo result**: no scan, model or network needed to look around.

Project: https://github.com/henrymbuguak/Shopping-Cart-Using-Django-2.0-and-Python-3.6 at
commit `1aa90f67f4559a36d8049d8a2d3fe622791ee95c`, scanned with Muse Spark Open. To refresh it:

```bash
uv run vexproof scan https://github.com/henrymbuguak/Shopping-Cart-Using-Django-2.0-and-Python-3.6 \
    --commit 1aa90f67f4559a36d8049d8a2d3fe622791ee95c --json examples/demo/findings.json
```

The web app pairs it with `examples/shop_profile.yaml` (priority) and with
`eval/observed/shop-1aa90f6.json` (the run-time evaluation, shown as "How this was checked").
