# Deployment & operations

## Process types

The service runs as **two** processes off the same image:

| Process | Command | Purpose |
| --- | --- | --- |
| `web` | `uvicorn app:app` | Serves the REST API (and the optional queue dashboard — see [Queue dashboard](#queue-dashboard)). |
| `worker` | `python -m worker` | Runs async scans from the queue (dramatiq). |

Both are needed for `/api/v1.0/scan-async`; the sync `/api/v1.0/scan` needs only
the web process. The `Procfile` declares both, and `docker-compose.yml` wires
them up as `app` and `worker` alongside `clamav` and Redis.

> ⚠️ **The worker is not optional.** If you deploy without the `Procfile` (e.g. a
> hand-rolled orchestration), you must start the dramatiq worker yourself.
> Without it, `scan-async` requests are accepted (`202`) but their jobs sit in
> the queue forever and no webhook is ever delivered.

Async scans use [dramatiq](https://dramatiq.io/) over the
[`dramatiq-redis-streams`](https://github.com/sylvinus/dramatiq-redis-streams)
broker (as in suitenumerique/st-home and /messages). The task streams the file
to clamd/exav over the socket (INSTREAM), so the worker needs **no filesystem
shared with the scanner** — just network reachability and the Redis broker.

## Authentication

Scan endpoints require an `X-API-Key` header. Keys are configured via `API_KEYS`
as a comma-separated list of `name:key` pairs (`name` identifies the caller in
logs):

```
API_KEYS="drive:s3cr3t-key,another-service:other-key"
```

Requests without a valid key get `401`. If `API_KEYS` is empty, every request is
rejected. Keys are compared in constant time.

## Configuration

All settings are environment variables (see `config.py`). `APP_CONFIG` selects a
profile: `config.ProductionConfig` (default), `config.TestConfig`,
`config.CiConfig`, `config.LocalConfig`.

| Variable | Default | Description |
| --- | --- | --- |
| `API_KEYS` | *(empty)* | Comma-separated `name:key` pairs. **Required** in production. |
| `PROMETHEUS_API_KEY` | *(empty)* | If set, `/metrics` requires `Authorization: Bearer <key>`. Empty = open (isolate it at the network layer). |
| `DEFAULT_SCANNERS` | `{"malware": ["clamav"]}` | JSON `category → [engines]` map: the categories that exist and which engines compose each. |
| `DEFAULT_CATEGORIES` | `malware` | Comma-separated categories run when a request names neither `categories` nor `scanners`. Must be keys of `DEFAULT_SCANNERS`. |
| `CLAMAV_HOST` | `clamav` | Single clamav daemon hostname. |
| `CLAMAV_PORT` | `3310` | Single clamav daemon TCP port. |
| `CLAMAV_SOCKET` | *(empty)* | Unix socket path; takes precedence over host/port. |
| `CLAMAV_HOSTS` | *(empty)* | `host:port,…` pool for client-side balancing; overrides the single host/socket. |
| `EXAV_HOSTS` | *(empty)* | `host:port,…` pool for the exav scanner (required to use `exav`). |
| `CLAMAV_TXT_URI` | `current.cvd.clamav.net` | DNS TXT record for the latest signature version (freshness gauge). |
| `JCOP_BASE_URL` / `JCOP_API_KEY` | *(empty)* | jcop backend endpoint + token (required to use `jcop`). |
| `JCOP_RESULT_TIMEOUT` / `JCOP_SUBMIT_TIMEOUT` / `JCOP_POLL_INTERVAL` | `30` / `600` / `5` | jcop poll timeout / total budget / poll interval (s). |
| `WORKER_BROKER_URL` | `redis://localhost:6379/0` | Redis broker for async scans. |
| `WORKER_PROCESSES` / `WORKER_THREADS` / `WORKER_QUEUES` | `2` / `8` / `default` | dramatiq worker sizing. |
| `WORKER_DASHBOARD_PASSWORD` | *(empty)* | Basic-auth password — the secret. **Empty ⇒ the dashboard is not served**; setting it mounts it (fail-closed 401 otherwise). |
| `WORKER_DASHBOARD_USER` | *(empty)* | Optional Basic-auth username to also require; empty accepts **any** username. |
| `WORKER_DASHBOARD_PATH` | `/dashboard` | Path the dashboard is mounted at on the web app. |
| `WORKER_DASHBOARD_ALLOWED_IPS` | *(empty)* | Optional client-IP allowlist (IPs/CIDRs); empty = any IP, still password-gated. |
| `WORKER_DASHBOARD_FORWARDED_IP_HEADER` | *(empty)* | If set (e.g. `X-Forwarded-For`), the allowlist trusts this header's leftmost IP instead of the direct peer. Only behind a proxy that overwrites it. |
| `SCAN_DIR` | `/tmp/file-scanner` | Worker-local scratch dir for the download (not shared with the scanner). |
| `MAX_UPLOAD_SIZE` | `104857600` (100 MiB) | Max size for a direct `/api/v1.0/scan` upload. |
| `MAX_URL_SIZE` | `2147483648` (2 GiB) | Max size for an async download. |
| `URL_DOWNLOAD_TIMEOUT` | `30` | Per-read timeout (s) on the async download. |
| `DOWNLOAD_MAX_SECONDS` | `300` | Total wall-clock budget (s) for an async download. |
| `WEBHOOK_TIMEOUT` / `WEBHOOK_MAX_ATTEMPTS` | `10` / `3` | Per-attempt timeout (s) / attempts before giving up. |
| `ALLOWED_URL_HOSTS` | *(empty)* | If set, **only** these hostnames may be submitted (positive allowlist). |
| `SSRF_ALLOWED_HOSTS` | *(empty)* | Hosts trusted to resolve to a private/internal address (SSRF bypass). |

## Running locally

Requires Docker. `make help` lists every target.

```bash
make bootstrap   # build images & start app + worker + clamav + redis
make logs        # follow app + worker logs
make stop        # stop the stack
make test        # run the test suite in the app container (against clamav)
```

Wait for `clamav` to finish loading its database before scanning
(`docker compose logs -f clamav`).

To also exercise the **exav** backend, bring up the opt-in `exav` service (it
shares clamav's signature volume) before running the suite:

```bash
docker compose --profile exav up -d exav   # needs an exav image (see the compose comment)
make test                                   # the exav-marked tests now run (they skip otherwise)
```

### Without Docker

```bash
uv sync   # dependencies from pyproject.toml + uv.lock

# The application code lives in src/. Start a clamd (or exav) daemon and a Redis
# on localhost, then run the two processes:
APP_CONFIG=config.LocalConfig \
  uv run uvicorn app:app --app-dir src --host 0.0.0.0 --port 8090           # web
APP_CONFIG=config.LocalConfig PYTHONPATH=src uv run python -m worker        # worker
```

Run the tests from the repository root (they resolve fixtures under
`client-examples/` relative to it):

```bash
APP_CONFIG=config.CiConfig uv run pytest
```

## Container image

The production image is **distroless** and multi-stage, mirroring
suitenumerique/messages: uv-managed CPython 3.14 (python-build-standalone) is
built into a `/venv`, stripped, and copied into `gcr.io/distroless/cc-debian13`.
It runs as the distroless `nonroot` user (uid 65532) with **no entrypoint
gymnastics** — because the worker scans over INSTREAM there is no writable data
volume to own, so nothing needs root. Build target: `runtime-distroless-prod`
(what the GHCR workflow publishes). `docker compose` uses the debian-based
`runtime-dev` target (has a shell, dev dependencies) for local work and tests.

A `HEALTHCHECK` polls `GET /check`.

## Monitoring

`GET /metrics` exposes Prometheus metrics — default process metrics, scan
counters (`filescanner_scans_total{scanner,category,verdict,api_client}`,
`filescanner_scan_duration_seconds{scanner,api_client}`), and signature freshness
(`filescanner_signature_outdated{scanner}`,
`filescanner_signature_version{scanner}`, refreshed lazily on scrape, 300 s TTL).
Set **`PROMETHEUS_API_KEY`** to require `Authorization: Bearer <key>` on
`/metrics` (constant-time; Prometheus sends it via `bearer_token`/`authorization`
in the scrape config) — matching the convention in suitenumerique/messages. Left
unset, `/metrics` is **open**, which is only safe when the endpoint is isolated
at the network layer (a dedicated metrics port the public ingress doesn't route,
`kube-rbac-proxy`, or mTLS). This matters here because the `api_client` label is
the `API_KEYS` name of the calling service — caller identities and their scan
volumes — so **set `PROMETHEUS_API_KEY` on any deployment where `/metrics` is
reachable from an untrusted network**. Sync scans are counted in the web process;
the worker process counts async scans, so scrape it too (or use
`PROMETHEUS_MULTIPROC_DIR`). Keep each scanner's own updater (`freshclam` /
exav's reload) running.

## Queue dashboard

The `dramatiq-redis-streams` broker ships a dashboard (queue depth, pending
messages, dead-letter queues) with **destructive, unauthenticated** endpoints
upstream (flush / remove / requeue). This service serves it from the **web app**
(`uvicorn app:app`) at `WORKER_DASHBOARD_PATH` (default `/dashboard`), wrapped in
`src/dashboard.py` with:

- **mandatory HTTP Basic auth** — fail-closed: with no `WORKER_DASHBOARD_PASSWORD`
  set, the dashboard is **not mounted at all**; once set, a wrong/missing password
  gets `401`. The username is ignored unless `WORKER_DASHBOARD_USER` is set;
- an **optional IP allowlist** (`WORKER_DASHBOARD_ALLOWED_IPS`).

Locally the dev compose sets a password, so it's at
`http://localhost:8090/dashboard` (any username / `dev-dashboard-password`).

Because it rides the **public web tier**, treat it as privileged: set a strong
`WORKER_DASHBOARD_PASSWORD` and restrict access with `WORKER_DASHBOARD_ALLOWED_IPS`
and/or a reverse proxy / network policy. The IP allowlist checks the **connecting
peer**; behind a proxy the peer is the proxy, so set
`WORKER_DASHBOARD_FORWARDED_IP_HEADER` (e.g. `X-Forwarded-For`) to trust the
proxy's client-IP header instead — only when a trusted proxy overwrites it, since
it is otherwise client-spoofable. To keep queue administration off the API tier
entirely, leave `WORKER_DASHBOARD_PASSWORD` unset and run the dashboard elsewhere
against the same broker.

## Scaling

The scanner daemon is the heavy tier (each loads the full signature DB). Because
scans go over INSTREAM there is no shared filesystem, so scale the tiers
independently: run a **pool of clamav/exav daemons** (behind a load balancer via
`CLAMAV_HOST`, or client-side via `CLAMAV_HOSTS` / `EXAV_HOSTS`) and scale
**worker replicas** — the Redis Streams broker distributes jobs across them.
Keep total worker concurrency ≤ the scanner pool's capacity, stagger signature
reloads, and cap clamd (`MaxScanSize`, `StreamMaxLength`, …).
