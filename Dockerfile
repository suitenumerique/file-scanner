# Multi-stage build mirroring suitenumerique/messages: uv-managed CPython
# (python-build-standalone) built into a venv, then copied into a distroless
# runtime for production. Messages factors the uv+Python base into a shared
# image (deploy/python-uv); we inline it here since this is a single service.
#
# Targets:
#   runtime-dev              debian + venv + shell  → docker compose / `make test`
#   runtime-distroless-prod  gcr.io/distroless      → published production image
#
# Because the worker scans over INSTREAM (no filesystem shared with clamd), the
# production image needs no writable data volume and runs as the distroless
# `nonroot` user (uid 65532) with no entrypoint gymnastics.

ARG PYTHON_VERSION=3.14.6
ARG UV_VERSION=0.11.28

# ---- uv + managed Python ----
FROM debian:trixie-slim AS uv
ENV MIN_UPDATE_DATE="2026-07-20"
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_PREFERENCE=only-managed \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PROJECT_ENVIRONMENT=/venv \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
ARG PYTHON_VERSION
RUN uv python install "${PYTHON_VERSION}"
WORKDIR /app

# ---- Production dependencies into /venv (from pyproject + uv.lock) ----
FROM uv AS build
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# ---- Development dependencies (adds pytest, ruff, … onto the runtime venv) ----
FROM build AS build-dev
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

# ---- Application source ----
FROM uv AS app-prod
COPY src/ /app/src/

# ---- Strip the managed Python for the distroless image ----
FROM uv AS python-stripped
COPY --chmod=0755 deploy/strip-python.sh /usr/local/bin/strip-python
RUN strip-python

# ---- Development runtime (has a shell; used by docker compose and `make test`) ----
FROM uv AS runtime-dev
COPY --from=build-dev /venv /venv
ENV PATH="/venv/bin:$PATH" \
    VIRTUAL_ENV=/venv \
    PYTHONPATH=/app/src \
    SCAN_DIR=/tmp/file-scanner
# The whole repo is bind-mounted over /app by docker compose in dev (so pyproject
# + client-examples are present for `make test`); copy source + pyproject too so
# the image is runnable on its own.
COPY src/ /app/src/
COPY pyproject.toml /app/
EXPOSE 8090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]

# ---- Distroless production runtime ----
# cc-debian13 provides glibc + libstdc++ for the compiled wheels (pydantic-core,
# uvloop, httptools); everything else is pure Python. Runs as `nonroot`.
# Debug with: docker run --entrypoint=sh gcr.io/distroless/cc-debian13:debug-nonroot
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime-distroless-prod
WORKDIR /app
COPY --from=python-stripped /opt/python /opt/python
COPY --from=build /venv /venv
COPY --from=app-prod /app/ /app/
ENV PATH="/venv/bin:$PATH" \
    VIRTUAL_ENV=/venv \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PORT=8090 \
    SCAN_DIR=/tmp/file-scanner
EXPOSE 8090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8090')+'/check', timeout=4).status==200 else 1)"]
