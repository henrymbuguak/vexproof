#!/usr/bin/env bash
# Re-create eval/observed/justdjango-260952e.json: run justdjango/django-ecommerce under its
# workload. EXECUTES the target project, in a throwaway Python 3.8 venv with its exact pins.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
work="${1:-$(mktemp -d)}"
commit=260952e75344a88a2b4af56a357ec457fa354542

git clone -q https://github.com/justdjango/django-ecommerce "$work/project"
git -C "$work/project" checkout -q "$commit"
uv python install 3.8 >/dev/null
uv venv -q -p 3.8 "$work/venv"
# some of its 2019 sdists still call setuptools APIs removed in 2024
echo "setuptools<70" > "$work/build-constraints.txt"
uv pip install -q -p "$work/venv/bin/python" --build-constraints "$work/build-constraints.txt" \
    -r "$work/project/requirements.txt"
mkdir -p "$repo_root/eval/observed"
"$work/venv/bin/python" "$here/observe.py" --project "$work/project" \
    --settings djecommerce.settings.development \
    --workload "$here/workloads/justdjango.py" --out "$repo_root/eval/observed/justdjango-260952e.json"
