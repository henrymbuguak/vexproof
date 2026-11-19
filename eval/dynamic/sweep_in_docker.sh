#!/usr/bin/env bash
# Import sweep of one project in Docker: install its pins (network on), then import every
# production module with the network OFF, and write an observation for `vexproof eval`.
# The project's code runs only inside the container (ADR 0001, ADR 0011).
#
#   sweep_in_docker.sh NAME CHECKOUT PYTHON SETTINGS REQUIREMENTS OUT [KEY=VALUE ...]
#     NAME          a short label, e.g. healthchecks
#     CHECKOUT      the project at its pinned commit (vexproof's own checkout works)
#     PYTHON        3.8, 3.9, ...
#     SETTINGS      Django settings module, or - for Flask and FastAPI
#     REQUIREMENTS  requirements file(s) inside the checkout, comma-separated
#     OUT           observation file to write (its folder is the only writable mount)
#     KEY=VALUE     environment the app needs to start (SECRET_KEY, DATABASE_URL, ...)
set -euo pipefail
name=$1 checkout=$(cd "$2" && pwd) py=$3 settings=$4 requirements=$5 out=$6
shift 6
here=$(cd "$(dirname "$0")" && pwd)
outdir=$(mkdir -p "$(dirname "$out")" && cd "$(dirname "$out")" && pwd)
base="vexproof-sweep:py$py"
image="vexproof-sweep-$name:installed"
envs=()
for kv in "$@"; do envs+=(-e "$kv"); done

docker image inspect "$base" >/dev/null 2>&1 \
  || docker build -q -t "$base" --build-arg "PY=$py" -f "$here/Dockerfile.sweep" "$here" >/dev/null

if ! docker image inspect "$image" >/dev/null 2>&1; then
  pip_args=()
  IFS=, read -ra files <<<"$requirements"
  for f in "${files[@]}"; do pip_args+=(-r "/src/$f"); done
  container="vexproof-install-$name"
  docker rm -f "$container" >/dev/null 2>&1 || true
  # network on, project read-only: pip may build sdists, which runs their setup code in here
  docker run --name "$container" -v "$checkout:/src:ro" "$base" \
    pip install --user --no-cache-dir -q "${pip_args[@]}"
  docker commit "$container" "$image" >/dev/null
  docker rm "$container" >/dev/null
fi

docker run --rm --network none --read-only --tmpfs /tmp:rw,size=512m \
  --cap-drop ALL --security-opt no-new-privileges --memory 2g --pids-limit 256 \
  -v "$checkout:/src:ro" -v "$here:/harness:ro" -v "$outdir:/out" \
  -e PYTHONDONTWRITEBYTECODE=1 ${envs[@]+"${envs[@]}"} "$image" \
  python /harness/observe.py --project /src --settings "$settings" \
    --workload /harness/workloads/import_sweep.py --out "/out/$(basename "$out")"
