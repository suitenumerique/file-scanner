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

### Queues

Two queues separate the heavy work from the light: **`scans`** (`scan_task` —
download + AV scan, minutes for a big file) and **`webhooks`** (`deliver_webhook`
— one HTTP POST). The single `worker` consumes **both** (`WORKER_QUEUES` defaults
to `webhooks scans`), which is enough for most deployments.

Within one worker, `deliver_webhook` is given a higher dramatiq **actor
priority** than `scan_task` (`priority=5` vs `10` — lower runs first), so when a
worker thread frees it picks a buffered callback ahead of buffered scans. This is
*soft* ordering only: dramatiq applies priority in an in-memory queue *after*
fetching, so it reorders waiting work but **cannot preempt a scan already
running** — if every thread is mid-scan, a webhook still waits for one to finish.
(Queue *order* in `--queues` is not priority — one worker feeds every queue it
consumes into a shared thread pool.) To keep callbacks prompt even under a full
scan backlog, run a **dedicated webhooks worker** — a second `python -m worker`
with `WORKER_QUEUES=webhooks` (it needs Redis + outbound network, but **not**
clamav) — and set `WORKER_QUEUES=scans` on the scan worker. This is a pure
deployment change; no code change is needed. **If you split them, both workers
are required** — without the webhooks worker, no callback is delivered.

## Authentication

Scan endpoints authenticate with a short-lived EdDSA (Ed25519) **Bearer JWT** in
`Authorization: Bearer <jwt>`, verified against the caller's public key looked up
by the token's `iss` claim. This side stores only *public* keys, so a config/env
leak here can't forge caller tokens. The token also **binds the request** (`htm`
method + `htu` target, plus `bh` = SHA-256 of the JSON body on the async
endpoint) so a captured token can't be replayed on a different call or with a
swapped `webhook_url`.

Configure the accepted callers with `JWT_ISSUER_KEYS` — comma-separated
`iss:pubkey` pairs, each the base64url raw Ed25519 public key (`iss` identifies
the caller in logs and the `api_client` metric):

```
JWT_ISSUER_KEYS="drive:<drive-pubkey>,transfers:<transfers-pubkey>"
```

Onboard a caller with **`make new-issuer NAME=<iss>`** (wraps
`deploy/scripts/new-issuer.py`): it generates the Ed25519 keypair, prints the
caller's private key to hand over securely, and prints the `iss:pubkey` fragment
to append to `JWT_ISSUER_KEYS`.

Requests without a valid token get `401`; with no issuer keys configured, every
request is rejected. See [security.md](security.md#authentication) for the token
claims, request binding, and signed webhooks.

## Configuration

All settings are environment variables (see `config.py`). `APP_CONFIG` selects a
profile: `config.ProductionConfig` (default), `config.TestConfig`,
`config.CiConfig`, `config.LocalConfig`.

For local development, docker compose loads these from `deploy/env/` — committed
`*.defaults` (dev-safe values) plus gitignored `*.local` overrides that
`make create-env-files` scaffolds (run automatically by `make bootstrap`).
Production supplies real values via its own environment; **never commit real
secrets** — the `*.defaults` keys are throwaway.

| Variable | Default | Description |
| --- | --- | --- |
| `JWT_ISSUER_KEYS` | *(empty)* | **Required for any caller.** Incoming caller keys, `iss:pubkey,…` (base64url raw Ed25519 public keys). `iss` names the caller in logs + the `api_client` metric. Empty ⇒ every request is `401`. |
| `JWT_AUDIENCE` | `file-scanner` | Expected `aud` on incoming tokens (this service's identity). |
| `JWT_MAX_AGE` | `300` | Hard cap (s) on an incoming token's `exp - iat`; also the TTL of tokens we mint for webhooks. |
| `JWT_LEEWAY` | `60` | Clock-skew leeway (s) for `exp`/`iat`/`nbf`. |
| `JWT_SIGNING_KEY` | *(empty)* | base64url raw Ed25519 private seed for **signing outgoing webhooks**. Public half is derived + served at `/.well-known/jwks.json`. Empty ⇒ webhooks unsigned. |
| `JWT_SIGNING_KID` / `JWT_ISSUER` | *(empty)* / `file-scanner` | `kid` advertised in the JWKS + webhook token headers (any stable label — a date/version like `2026-07` or `v1`, or a JWK thumbprint; **set one** so receivers can match keys across a rotation); `iss` we stamp on webhook tokens. |
| `PROMETHEUS_API_KEY` | *(empty)* | If set, `/metrics` requires `Authorization: Bearer <key>`. Empty = open (isolate it at the network layer). |
| `DEFAULT_SCANNERS` | `{"malware": ["clamav"]}` | JSON `category → [engines]` map: the categories that exist and which engines compose each. |
| `DEFAULT_CATEGORIES` | `malware` | Comma-separated categories run when a request names neither `categories` nor `scanners`. Must be keys of `DEFAULT_SCANNERS`. |
| `CLAMAV_SOCKET` | *(empty)* | Unix socket path; takes precedence over the host list. |
| `CLAMAV_HOSTS` | `localhost:3310` | `host:port,…` clamav daemon pool; a single entry is one daemon, several enable client-side balancing. |
| `EXAV_HOSTS` | *(empty)* | `host:port,…` pool for the exav scanner (required to use `exav`). |
| `CLAMAV_TXT_URI` | `current.cvd.clamav.net` | DNS TXT record for the latest signature version (freshness gauge). |
| `JCOP_BASE_URL` / `JCOP_API_KEY` | *(empty)* | jcop backend endpoint + token (required to use `jcop`). |
| `JCOP_RESULT_TIMEOUT` / `JCOP_SUBMIT_TIMEOUT` / `JCOP_POLL_INTERVAL` | `30` / `600` / `5` | jcop poll timeout / total budget / poll interval (s). |
| `WORKER_BROKER_URL` | `redis://localhost:6379/0` | Redis broker for async scans. |
| `WORKER_PROCESSES` / `WORKER_THREADS` | `2` / `8` | dramatiq worker sizing (processes forked / threads per process). |
| `WORKER_QUEUES` | `webhooks scans` | Space-separated queues the worker consumes. Default runs both on one worker; set `scans` here and run a second worker with `webhooks` to dedicate capacity to callback delivery. |
| `WORKER_DASHBOARD_PASSWORD` | *(empty)* | Basic-auth password — the secret. **Empty ⇒ the dashboard is not served**; setting it mounts it (fail-closed 401 otherwise). |
| `WORKER_DASHBOARD_USER` | *(empty)* | Optional Basic-auth username to also require; empty accepts **any** username. |
| `WORKER_DASHBOARD_PATH` | `/dashboard` | Path the dashboard is mounted at on the web app. |
| `WORKER_DASHBOARD_ALLOWED_IPS` | *(empty)* | Optional client-IP allowlist (IPs/CIDRs); empty = any IP, still password-gated. |
| `WORKER_DASHBOARD_FORWARDED_IP_HEADER` | *(empty)* | If set (e.g. `X-Forwarded-For`), the allowlist trusts this header's leftmost IP instead of the direct peer. Only behind a proxy that overwrites it. |
| `DOWNLOAD_DIR` | `/tmp/file-scanner` | Worker-local scratch dir for the async download (not shared with the scanner). |
| `MAX_UPLOAD_SIZE` | `104857600` (100 MiB) | Max size for a direct `/api/v1.0/scan` upload. |
| `MAX_URL_SIZE` | `2147483648` (2 GiB) | Max size for an async download. |
| `URL_DOWNLOAD_TIMEOUT` | `30` | Per-read timeout (s) on the async download. |
| `DOWNLOAD_MAX_SECONDS` | `300` | Total wall-clock budget (s) for an async download. |
| `ENCRYPTION_MIN_CHUNK_SIZE` | `4096` (4 KiB) | Floor on a client-encrypted source's `chunk_size` (guards a chunk-count CPU cost). |
| `ENCRYPTION_MAX_CHUNK_SIZE` | `52428800` (50 MiB) | Ceiling on `chunk_size` — the worker buffers one whole chunk in RAM, so this × worker concurrency bounds memory. |
| `WEBHOOK_TIMEOUT` / `WEBHOOK_MAX_ATTEMPTS` | `10` / `3` | Per-attempt timeout (s) / attempts before giving up. |
| `WORKER_RESULT_TTL` | `0` | TTL (s) for an async job's stored result, enabling `GET /api/v1.0/jobs/{job_id}` (record kept in the broker's Redis). `0` = disabled (fully stateless, webhook-only, `webhook_url` mandatory); `> 0` makes `webhook_url` optional. |
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

Run the tests from the repository root:

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
the JWT `iss` of the calling service — caller identities and their scan
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

> ⚠️ **The dashboard is highly sensitive.** Beyond the destructive queue ops, it
> renders each queued / delayed / **dead-lettered** message's task **arguments** —
> which for a scan job include the source **URL** and, for a client-encrypted
> source, the **decryption key** (`encryption_params`). A dead-lettered encrypted
> job keeps its key visible until the message is requeued or deleted. Anyone who
> can reach the dashboard can read those inputs and flush/replay the queue, so
> treat access as equivalent to broker access. (It does **not** show scan
> results — nothing is persisted.)

Because it rides the **public web tier**, treat it as privileged: set a strong
`WORKER_DASHBOARD_PASSWORD`, restrict access with `WORKER_DASHBOARD_ALLOWED_IPS`
and/or a reverse proxy / network policy, and purge the dead-letter queue so keys
don't linger. The IP allowlist checks the **connecting peer**; behind a proxy the
peer is the proxy, so set `WORKER_DASHBOARD_FORWARDED_IP_HEADER` (e.g.
`X-Forwarded-For`) to trust the proxy's client-IP header instead — only when a
trusted proxy overwrites it, since it is otherwise client-spoofable.

### Disabling it entirely

`WORKER_DASHBOARD_PASSWORD` is the on/off switch. **Leave it unset (the default)
and the dashboard is not served at all** — no `/dashboard` route is registered
and `src/dashboard.py` (and the broker introspection it does) is never even
imported; the app logs `Dashboard disabled` at startup. There is nothing to reach
and no code path to exploit. Set the password only on a deployment where you
actively need queue administration; to inspect the queue without exposing it on
the API tier, keep it unset here and run the dashboard as a separate,
network-restricted process against the same broker.

## Scaling

The scanner daemon is the heavy tier (each loads the full signature DB). Because
scans go over INSTREAM there is no shared filesystem, so scale the tiers
independently: run a **pool of clamav/exav daemons** (behind a load balancer, or
client-side via `CLAMAV_HOSTS` / `EXAV_HOSTS`) and scale
**worker replicas** — the Redis Streams broker distributes jobs across them.
Keep total worker concurrency ≤ the scanner pool's capacity, stagger signature
reloads, and cap clamd (`MaxScanSize`, `StreamMaxLength`, …).

Because `scan_task` (queue `scans`) and `deliver_webhook` (queue `webhooks`) are
separate queues, you can also scale them independently — bound the `scans`
worker's concurrency by the scanner pool while giving a `webhooks` worker high
concurrency (it only makes HTTP calls) so callbacks stay prompt (see
[Queues](#queues)).
