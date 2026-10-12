# check=skip=SecretsUsedInArgOrEnv
# Image for Anthropic's OSS Scanner. See .oss-scanner/threat_model.md.
# The scan runs with no network, so this build installs every dependency and
# the services the test suite needs: Redis and a ClamAV daemon with its
# signatures.
# Scanner contract: the repository is the build context, the checkout is /src.
# The layout mirrors suitenumerique/messages' .oss-scanner/Dockerfile.
#
# The same Debian release as the Dockerfile at the root, pinned by digest.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONUNBUFFERED=1

# policy-rc.d stops the redis and clamav packages from starting a server: a
# server killed at the end of a layer leaves a stale pid file in the image.
# git fetches dramatiq-redis-streams, which uv.lock pins by revision.
RUN <<EOR
set -eux
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
apt-get update
apt-get upgrade -y
apt-get install -y --no-install-recommends \
    ca-certificates \
    clamav-daemon \
    clamav-freshclam \
    curl \
    git \
    netcat-openbsd \
    redis-server
rm -f /usr/sbin/policy-rc.d
rm -rf /var/lib/apt/lists/*
EOR

# clamd on 127.0.0.1:3310, the address CiConfig in src/config.py uses, with
# the limits of the clamav service in docker-compose.yml: AlertExceedsMax makes
# clamd report a limit it hit instead of answering OK on a partial scan.
RUN printf '%s\n' \
      "TCPSocket 3310" \
      "TCPAddr 127.0.0.1" \
      "StreamMaxLength 2147483645" \
      "MaxFileSize 2147483645" \
      "MaxScanSize 2147483645" \
      "MaxScanTime 900000" \
      "AlertExceedsMax yes" \
      >> /etc/clamav/clamd.conf

# The signatures, downloaded now because the scan has no network. ClamAV's
# CDN can refuse a build host; then clamd stays down and the integration tests
# skip themselves, as they do in a bare `pytest`.
RUN freshclam --stdout \
    || echo "WARNING: freshclam failed; clamd will not start and the integration tests will skip"

# The scanner replaces ENTRYPOINT and CMD, so the image cannot start the
# services itself. svcctl starts them, and every shell sources the init file.
COPY --chmod=0755 <<'EOF' /usr/local/bin/svcctl
#!/bin/sh
set -eu

redis_ready() {
    redis-cli -h 127.0.0.1 -p 6379 ping >/dev/null 2>&1
}

clamd_ready() {
    [ "$(printf 'PING\n' | nc -w2 127.0.0.1 3310 2>/dev/null)" = "PONG" ]
}

wait_for() {
    i=0
    while [ "$i" -lt "$3" ]; do
        if "$1"; then return 0; fi
        sleep 0.5
        i=$((i + 1))
    done
    echo "svcctl: $2 did not become ready" >&2
    return 1
}

start_redis() {
    if redis_ready; then return 0; fi
    install -d -o redis -g redis -m 2775 /var/run/redis
    redis-server /etc/redis/redis.conf --daemonize yes --save "" --appendonly no
    wait_for redis_ready redis 60
}

start_clamd() {
    if clamd_ready; then return 0; fi
    if ! ls /var/lib/clamav/main.* >/dev/null 2>&1; then
        echo "svcctl: no ClamAV signatures in /var/lib/clamav, clamd not started" >&2
        return 1
    fi
    install -d -o clamav -g clamav -m 0755 /run/clamav
    # A stale socket or pid file from the scanner's own layer stops clamd.
    rm -f /run/clamav/clamd.ctl /run/clamav/clamd.pid
    clamd
    # Loading the signatures takes a while.
    wait_for clamd_ready clamd 360
}

case "${1:-start}" in
start)
    start_redis
    # clamd serves the integration tests only, so its failure must not stop
    # the others.
    start_clamd || echo "svcctl: clamd did not start, see /var/log/clamav/clamav.log" >&2
    ;;
stop)
    redis-cli -h 127.0.0.1 -p 6379 shutdown nosave >/dev/null 2>&1 || true
    pkill -x clamd || true
    ;;
status)
    if redis_ready; then echo "redis: up"; else echo "redis: down"; fi
    if clamd_ready; then echo "clamd: up"; else echo "clamd: down"; fi
    ;;
*)
    echo "usage: svcctl [start|stop|status]" >&2
    exit 2
    ;;
esac
EOF

# Sourced by BASH_ENV, /etc/profile.d and /root/.bashrc. It must stay silent
# and must not change the exit status.
COPY --chmod=0644 <<'EOF' /etc/oss-scanner-shell-init
if [ -z "${OSS_SCANNER_SERVICES_STARTED:-}" ]; then
    if /usr/local/bin/svcctl start >/dev/null 2>&1; then
        OSS_SCANNER_SERVICES_STARTED=1
        export OSS_SCANNER_SERVICES_STARTED
    fi
fi
:
EOF

# uv and the managed CPython, the versions of the Dockerfile at the root.
COPY --from=ghcr.io/astral-sh/uv@sha256:3af4716e991d6956a41e573eab705d0ee08500cd829ed30293eb8472f372c65a /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PYTHON_PREFERENCE=only-managed

RUN uv python install 3.14.8

# The environment sits outside /src, so a search of the checkout does not read
# it. No cache mount: a cache mount is not kept in the image, and the agent
# needs the download caches to install anything with no network.
COPY pyproject.toml uv.lock .python-version /src/
RUN cd /src && UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen

COPY . /src
WORKDIR /src

# CiConfig is the profile CI runs the tests with: it ignores the environment,
# relaxes the request-time SSRF check and runs tasks eagerly. The values below
# are for running the service by hand with ProductionConfig; they mirror
# deploy/env/app.defaults, the public development values, not secrets.
ENV PATH=/opt/venv/bin:$PATH \
    VIRTUAL_ENV=/opt/venv \
    PYTHONPATH=/src/src \
    APP_CONFIG=config.CiConfig \
    JWT_ISSUER_KEYS=dev-issuer:8sicDCDZLZY5SPNNjr4aBwwh0Dyrqr7Ca9neK_nA6Eg \
    JWT_SIGNING_KEY=uGyAqjXdgjOXWLLzChBCzgzzvUUJcSsy6-ctdhqeHhM \
    JWT_SIGNING_KID=dev-1 \
    CLAMAV_HOSTS=127.0.0.1:3310 \
    WORKER_BROKER_URL=redis://127.0.0.1:6379/0 \
    WORKER_RESULT_TTL=3600 \
    WORKER_DASHBOARD_PASSWORD=dev-dashboard-password

# A failing test must not fail the build, and the run has a time limit. -k
# kills a worker that ignores the first signal.
RUN <<EOR
set -eux
svcctl start
cd /src
timeout -k 30 900 pytest -q -p no:cacheprovider --no-cov \
    || echo "WARNING: the test run did not finish cleanly (exit $?)"
svcctl stop
EOR

RUN <<EOR
set -eux
echo '. /etc/oss-scanner-shell-init' > /etc/profile.d/oss-scanner.sh
echo '. /etc/oss-scanner-shell-init' >> /root/.bashrc
git config --system --add safe.directory /src
EOR

# From here on every tool reads the caches in this image and fails fast
# instead of waiting for a network that is not there.
ENV BASH_ENV=/etc/oss-scanner-shell-init \
    PIP_NO_INDEX=1 \
    UV_FROZEN=1 \
    UV_NO_SYNC=1 \
    UV_OFFLINE=1
