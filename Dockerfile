# vexproof: the web app and command line in one image.
#   docker build -t vexproof .
#   docker run --rm -p 127.0.0.1:8000:8000 -v vexproof-data:/data --env-file .env \
#     --add-host host.docker.internal:host-gateway vexproof
# Every download below is pinned and checked against its published SHA-256.

FROM ubuntu:24.04

ARG TARGETARCH
ARG UV_VERSION=0.11.32
ARG SYFT_VERSION=1.54.1

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PYTHON_PREFERENCE=only-managed

# git fetches repositories and fix commits; Syft lists a project's dependencies.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) uv_arch=x86_64; uv_sha=aab924fd522efd06f1c5f3b93a243864fc453132c94b2dc49f1371b528a4b967; \
             syft_sha=c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47 ;; \
      arm64) uv_arch=aarch64; uv_sha=4d4fa08d95b06642e5800df6a22bd71455f23f988269e18da2847971d8c0bf31; \
             syft_sha=dfdf0537610113edbefe1f1fc6548bc957b2d77439636ec824fcf0e10d46d054 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    curl -fsSLo uv.tgz "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${uv_arch}-unknown-linux-gnu.tar.gz"; \
    echo "${uv_sha}  uv.tgz" | sha256sum -c -; \
    tar -xzf uv.tgz --strip-components=1 -C /usr/local/bin "uv-${uv_arch}-unknown-linux-gnu/uv"; \
    curl -fsSLo syft.tgz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH:-amd64}.tar.gz"; \
    echo "${syft_sha}  syft.tgz" | sha256sum -c -; \
    tar -xzf syft.tgz -C /usr/local/bin syft; \
    rm -f uv.tgz syft.tgz; \
    uv --version; syft version | head -2

WORKDIR /app
# Dependencies first, so code changes rebuild only the last layers.
COPY pyproject.toml uv.lock .python-version README.md ./
RUN uv python install \
 && uv sync --locked --no-dev --group web --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --group web
# The demo result, its run-time evaluation and the example service profiles.
COPY examples ./examples
COPY eval/gold ./eval/gold
COPY eval/observed ./eval/observed

RUN useradd --create-home --uid 10001 vexproof \
 && mkdir -p /data \
 && chown vexproof /data
USER vexproof

# A model server your .env puts at localhost (Ollama) is on the host computer, not in here.
ENV PATH="/app/.venv/bin:${PATH}" \
    VEXPROOF_CACHE_DIR=/data \
    VEXPROOF_LOCALHOST_ALIAS=host.docker.internal
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]
CMD ["vexproof", "serve", "--host", "0.0.0.0", "--port", "8000"]
