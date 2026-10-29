#!/usr/bin/env bash
# Re-create eval/observed/shop-1aa90f6.json: run the demo shop under its workload.
# EXECUTES the target project, in a throwaway Python 3.8 venv with its exact pinned packages.
# Needs: uv, git, a C compiler and libjpeg + zlib headers (Pillow 4.3.0 builds from source):
#   Debian/Ubuntu: apt-get install gcc libjpeg-dev zlib1g-dev   macOS: brew install jpeg zlib
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
work="${1:-$(mktemp -d)}"
commit=1aa90f67f4559a36d8049d8a2d3fe622791ee95c

git clone -q https://github.com/henrymbuguak/Shopping-Cart-Using-Django-2.0-and-Python-3.6 "$work/shop"
git -C "$work/shop" checkout -q "$commit"
uv python install 3.8 >/dev/null   # Python 3.6 is not available from uv; Django 2.0 runs on 3.8
uv venv -q -p 3.8 "$work/venv"
uv pip install -q -p "$work/venv/bin/python" -r "$work/shop/requirements.txt"
mkdir -p "$repo_root/eval/observed"
"$work/venv/bin/python" "$here/observe.py" --project "$work/shop" --settings myshop.settings \
    --workload "$here/workloads/shop.py" --out "$repo_root/eval/observed/shop-1aa90f6.json"
