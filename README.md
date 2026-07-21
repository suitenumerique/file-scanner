# File Scanner

A small REST service, written in Python, that scans files on demand across one or
more **categories** (axes of judgment, e.g. `malware`) using pluggable
**scanners**, and reports a per-category verdict plus a per-scanner breakdown.

The app and worker only ever see a normalized verdict, never the engine. The
built-in scanners all feed the `malware` category: `clamav` / `exav` (the
[clamd](https://docs.clamav.net/manual/Usage/Scanning.html#clamd) wire protocol —
[exav](https://github.com/sylvinus/exav) gives richer verdicts and never marks a
skipped file clean) and `jcop` (the cyber.gouv.fr HTTP service). A request picks
work by category and/or scanner (`?categories=malware`, `?scanners=clamav,jcop`,
which union); otherwise `DEFAULT_CATEGORIES` is used. See
[docs/categories.md](docs/categories.md) and
[docs/scanner-backends.md](docs/scanner-backends.md).

The service is **stateless**: a synchronous scan returns its verdict in the HTTP
response; an asynchronous scan delivers its verdict only via a webhook callback.

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/v1.0/scan` | JWT | Synchronous scan of an uploaded file → per-category + per-scanner report. |
| `POST` | `/api/v1.0/scan-async` | JWT | Async scan of a file fetched from a URL; result delivered to a webhook. |
| `GET`  | `/check`, `/` | — | Liveness: `200 Service OK` when the scanners answer, else `503`. |
| `GET`  | `/.well-known/jwks.json` | — | Webhook-signing public key(s) (JWK Set) for receivers to verify signed callbacks. |
| `GET`  | `/metrics` | — | Prometheus exposition, incl. signature freshness (see [Monitoring](#monitoring)). |

Full request/response schemas: [docs/api.md](docs/api.md).

## Quick start

Requires Docker. `make help` lists every target.

```bash
make bootstrap                 # scaffold env files + build + start app + worker + clamav + redis
docker compose logs -f clamav  # wait for the signature database to load
```

`make bootstrap` is the one-time setup; afterwards use `make start` / `make stop`
to bring the stack up and down (both read config from `deploy/env/`, see
[Configuration](docs/deployment.md#configuration)).

Scan the harmless EICAR test file. Auth is a **request-bound JWT** ([Auth &
callers](#auth--callers)), so mint a short-lived token for the throwaway dev
caller `dev-issuer` with the `mint-token.py` helper (run in the app container) and
send it as a Bearer token:

```bash
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Throwaway dev private key for caller "dev-issuer" (matches JWT_ISSUER_KEYS in deploy/env/app.defaults).
DEV_PRIV=Higc3cLT742BJB5GiPnW5Ypg0xCGoVYY-s07ssMVlsg
TOKEN=$(docker compose exec -T app python deploy/scripts/mint-token.py "$DEV_PRIV" dev-issuer POST /api/v1.0/scan)

curl -sf -H "Authorization: Bearer $TOKEN" -F "file=@/tmp/eicar.txt" \
     http://localhost:8090/api/v1.0/scan
# {"malware": true,
#  "scanners": [{"scanner": "clamav", "category": "malware", "kind": "malware",
#                "reason": "Eicar-Test-Signature", "time": 0.003}]}
```

```bash
make test      # run the test suite in docker
make lint      # ruff check + format check
make start     # (re)start the stack after the initial bootstrap
make stop      # stop the stack
```

## Services & ports (docker compose)

| Service | URL / Port | Description | Credentials |
| --- | --- | --- | --- |
| **app** (web) | [http://localhost:8090](http://localhost:8090) | FastAPI REST API + `/metrics` | JWT — dev caller `dev-issuer` (throwaway key, see [Auth & callers](#auth--callers)) |
| **worker** | — | dramatiq worker (async scans) | — |
| **clamav** | `localhost:3310` | ClamAV / exav daemon (clamd protocol) | none |
| **redis** | `localhost:6380` | dramatiq broker (Redis Streams) | none |

## Auth & callers

Scan endpoints authenticate with a short-lived **EdDSA (Ed25519) Bearer JWT**.
Callers sign the token with their *private* key; the service verifies it with
their *public* key, selected by the token's **`iss`** claim (which also
identifies the caller in logs and the `api_client` metric, e.g. `drive`,
`transfers`). Because the service stores only public keys, a leak of its config
can't forge caller tokens.

Configure the accepted callers with `JWT_ISSUER_KEYS` — `iss:pubkey` pairs, each
the base64url raw Ed25519 public key:

```env
JWT_ISSUER_KEYS="drive:<drive-pubkey>,transfers:<transfers-pubkey>"
```

Onboard a new caller with **`make new-issuer NAME=<iss>`** — it generates an
Ed25519 keypair and prints the caller's private key (hand it over securely) plus
the `iss:pubkey` line to append here.

The token **binds the request** — method + target, plus a SHA-256 of the JSON
body on the async endpoint — so a captured token can't be replayed on a
different call or with a swapped `webhook_url`. Mint one per request (see the
[quick start](#quick-start) for a dev example). Outgoing webhooks are signed with
the service's own key (`JWT_SIGNING_KEY`) and are verifiable at
`/.well-known/jwks.json`. Requests without a valid token get `401`. Full model:
[docs/security.md](docs/security.md#authentication).

## Monitoring

- **`GET /metrics`** exposes Prometheus metrics: default process metrics plus
  `filescanner_scans_total{scanner,category,verdict,api_client}` and
  `filescanner_scan_duration_seconds{scanner,api_client}` (`api_client` is the
  calling service's JWT `iss`, so scans break down per consumer). Set
  **`PROMETHEUS_API_KEY`** to require `Authorization: Bearer <key>` (unset = open,
  so isolate it at the network layer — and note the `api_client` label exposes
  caller identities). Sync scans are counted in the web process; the worker
  process counts async scans (scrape it separately, or use prometheus
  multiprocess mode).
- **Queue dashboard.** The broker
  ([`dramatiq-redis-streams`](https://github.com/sylvinus/dramatiq-redis-streams))
  ships a dashboard for inspecting/replaying/**deleting** queued jobs. Upstream
  it is destructive and unauthenticated, so `uvicorn app:app` serves it at
  **`/dashboard`** behind a mandatory Basic-auth + optional IP-allowlist guard
  (`src/dashboard.py`) — and only when `WORKER_DASHBOARD_PASSWORD` is set (unset ⇒
  it isn't mounted; the path is `WORKER_DASHBOARD_PATH`). It's **highly
  sensitive** — it renders queued/dead-letter task **args**, which include the
  source URL and, for encrypted sources, the **decryption key** — so treat access
  as broker-equivalent. **Leaving `WORKER_DASHBOARD_PASSWORD` unset (the default)
  disables it entirely** (no route, no code). The dev compose enables it at
  [http://localhost:8090/dashboard](http://localhost:8090/dashboard) (any username
  / `dev-dashboard-password`). In production set a strong password, restrict with
  `WORKER_DASHBOARD_ALLOWED_IPS` (or `WORKER_DASHBOARD_FORWARDED_IP_HEADER` behind
  a trusted proxy), purge the DLQ, and keep the broker private
  (`WORKER_BROKER_URL=redis://:PASSWORD@host:6379/0`, Redis bound internally). See
  [docs/deployment.md](docs/deployment.md#queue-dashboard).

## Repository layout

```text
src/               application code (FastAPI app, scanners, dramatiq worker, SSRF guard, …)
tests/             pytest suite (one file per area)
deploy/env/        per-service env files: committed *.defaults + gitignored *.local (make create-env-files)
deploy/scripts/    dev/ops CLIs: JWT issuer keygen (new-issuer.py) + token minting (mint-token.py)
deploy/docker/     image build helpers (strip-python.sh)
docs/              reference documentation (see below)
```

## Stack

- **API**: FastAPI + uvicorn
- **Async scans**: dramatiq over the [`dramatiq-redis-streams`](https://github.com/sylvinus/dramatiq-redis-streams) broker (Redis)
- **Scanners**: `clamav` / `exav` (clamd protocol) and `jcop` (HTTP)
- **Metrics**: Prometheus (`/metrics`)
- **Image**: multi-stage, distroless (uv-managed CPython 3.14), nonroot

## Documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Components, request flows, statelessness. |
| [docs/categories.md](docs/categories.md) | The category model: request grammar, multi-axis verdicts, config. |
| [docs/api.md](docs/api.md) | Full endpoint reference and payload schemas. |
| [docs/scanner-backends.md](docs/scanner-backends.md) | clamav / exav / jcop and the extended verdicts. |
| [docs/deployment.md](docs/deployment.md) | Configuration, process types, running it. |
| [docs/security.md](docs/security.md) | SSRF protection, resource limits, threat model. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits follow the
[gitmoji](https://gitmoji.dev/) convention. Report vulnerabilities per
[SECURITY.md](SECURITY.md).

## Credits

This project stands on a decade of prior work. Its lineage, oldest first:

1. **[solita/clamav-java](https://github.com/solita/clamav-java)** — a minimal
   Java client for ClamAV's clamd protocol.
2. **[solita/clamav-rest](https://github.com/solita/clamav-rest)** — a Java REST
   proxy (INSTREAM + PING) built on clamav-java, by [Solita](https://www.solita.fi/).
3. **uktrade/dit-clamav-rest** — a Python reimplementation by the UK Department
   for International Trade, inspired by solita/clamav-rest. The original repo is
   no longer online; a mirror survives at
   [heikipikker/dit-clamav-rest](https://github.com/heikipikker/dit-clamav-rest).
4. **[betagouv/clamav-service](https://github.com/betagouv/clamav-service)** — a
   fork of DIT ClamAV REST by [beta.gouv.fr](https://beta.gouv.fr/), adding
   GitHub Actions and Scalingo deployment. The **direct predecessor** of this
   repository.
5. **This repository** (La Suite Numérique) — reworked into a FastAPI service
   with a pluggable scanner interface, dramatiq async scanning, SSRF hardening,
   and a distroless image.

It also adapts code and patterns from sibling La Suite Numérique projects:

- the SSRF guard (`ssrf.py`) is vendored from
  [suitenumerique/messages](https://github.com/suitenumerique/messages), whose
  distroless/uv Docker build this image also mirrors;
- the dramatiq broker/worker setup follows
  [suitenumerique/st-home](https://github.com/suitenumerique/st-home);
- the `jcop` backend mirrors
  [suitenumerique/django-lasuite](https://github.com/suitenumerique/django-lasuite);
- it integrates [exav](https://github.com/sylvinus/exav) and the
  [dramatiq-redis-streams](https://github.com/sylvinus/dramatiq-redis-streams)
  broker.
```
