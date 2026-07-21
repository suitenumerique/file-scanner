# Architecture

The service is a thin REST/queue layer in front of one or more **pluggable
scanner backends**. A file is scanned across one or more **categories** (axes of
judgment, e.g. `malware`); each backend feeds a category and returns a normalized
`Verdict`, so nothing above `scanners/` knows the engine. Built-in backends are
`clamav`/`exav` (the clamd wire protocol) and `jcop` (an HTTP analyser), and the
interface is engine-agnostic — a category need not even be antivirus.

```text
             ┌───────────────┐    scan     ┌──────────────────────────┐
  client ──▶ │  FastAPI web  │ ──────────▶ │  scanner backends        │
             │  (uvicorn)    │             │  clamav/exav (INSTREAM)  │
             └──────┬────────┘             │  jcop (HTTP), …          │
                    │ scan-async           └──────────────────────────┘
                    ▼                                  ▲
             ┌───────────────┐   task    ┌─────────────┴────┐
             │  Redis broker │ ────────▶ │ dramatiq worker  │ ──▶ webhook
             └───────────────┘           └──────────────────┘
```

The clamd-protocol backends (`clamav`/`exav`) scan over **INSTREAM** — the file
is streamed to the daemon over the socket — so the worker shares no filesystem
with them; other backends use their own transport (`jcop` submits over HTTP).

## Components

| Component | Module | Role |
| --- | --- | --- |
| Web API | `app.py` | FastAPI app: auth, request validation, sync scan, async enqueue. |
| Worker | `tasks.py` | dramatiq actor: download → scan → deliver webhook. |
| Broker | `broker.py` / `worker.py` | dramatiq broker setup + `@register_task`; the worker entrypoint. |
| Scanner interface | `scanner.py` | `Scanner` ABC, `Verdict`, the backend registry, category resolution (`resolve_scanners`, `category_map`, `validate_registry`), and `run_scanners()` (parallel orchestration + per-category `ScanReport`). |
| Scanner backends | `scanners/` | Concrete engines, each declaring its `category`: `clamav.py`, `exav.py` (subclass), `jcop.py`. |
| Metrics | `metrics.py` | Prometheus counters/gauges; `/metrics` exposition. |
| SSRF guard | `ssrf.py` | Hostname/IP validation, IP-pinned HTTP session. Vendored from [messages](https://github.com/suitenumerique/messages). |
| Policy | `validation.py` | Positive host allowlist + SSRF guard, enforced at the web layer AND the worker. |
| Config | `config.py` | Environment-driven settings with named profiles. |

The app and worker depend only on `scanner.py` (the `Scanner` interface, the
normalized `Verdict`, and `run_scanners`); nothing outside `scanners/` knows the
engine. Adding a backend is a new module implementing `Scanner` plus a builder in
`_BUILDERS` — no change to `app.py` or `tasks.py`.

## Request flows

### Synchronous — `POST /api/v1.0/scan`

1. Authenticate (request-bound Bearer JWT); resolve `categories` ∪ `scanners`
   into a scanner set (`DEFAULT_CATEGORIES` if neither is named).
2. Reject oversized uploads (`413`); read the file once.
3. `run_scanners` streams it to every selected scanner **in parallel** (each its
   own handle), recording metrics.
4. Return per-category aggregates + the per-scanner breakdown
   (`{malware, …, scanners: [...]}`; `503` if every scanner failed). See
   [categories.md](categories.md).

### Asynchronous — `POST /api/v1.0/scan-async`

1. Authenticate; resolve `categories` ∪ `scanners`; validate the download URL
   and webhook URL against the SSRF guard + allowlist.
2. Enqueue a dramatiq task and return `202 {job_id, status: pending}`.
3. The worker re-checks the policy, downloads the URL (SSRF-safe, size- and
   time-bounded), runs the scanners in parallel over the temp file, deletes it,
   and POSTs the report to `webhook_url`. When the result store is enabled it
   also writes the terminal record (see below).

## Statelessness

Stateless by default. A synchronous scan returns its verdict inline; an
asynchronous scan delivers its verdict through the webhook. The `job_id` is a
correlation handle echoed in the webhook. With no result store configured nothing
is persisted — a caller that needs durability runs its own reaper and re-submits
lost jobs — which keeps the service horizontally scalable and free of a database.

### Optional result store (polling)

Setting `WORKER_RESULT_TTL > 0` turns on a small, TTL-bounded result store
(`results.py`) so a caller can **poll** `GET /api/v1.0/jobs/{job_id}` instead of —
or as a fallback to — the webhook. It is deliberately additive: the `job_id` was
already part of the contract, so no existing caller changes.

1. The store is **dramatiq's own result backend** (`RedisBackend`, in the same
   Redis as the streams broker; eager mode uses the in-memory `StubBackend`).
   `results.py` writes/reads a record keyed by `job_id` — dramatiq keys results
   by message, so a minimal keying `Message` is minted from the `job_id`
   (`{WORKER_QUEUE_NAMESPACE}:default:scan_task:{job_id}`), expiring after
   `WORKER_RESULT_TTL` seconds. It drives the backend directly rather than via
   `store_results=True`, because the record is owner-scoped and pending-aware
   (and the store must run in the task body, where a worker's return-value
   auto-capture doesn't). A storage failure is swallowed — it never fails a scan.
2. The web endpoint seeds a `pending` record on `202`; the worker overwrites it
   with the terminal `{status: done|error, …}` record at the same point it
   enqueues the webhook. Records are **owner-scoped** by the caller `iss` (a poll
   only returns your own jobs, else `404`).
3. The webhook stays the **primary** delivery channel; polling is the durability
   / fallback path. With the store on, `webhook_url` becomes optional (a caller
   may poll instead); with it off, the service is fully stateless and
   `webhook_url` is mandatory.

This trades the database-free property for durability, so it stays **off by
default** — enable it only when a consumer needs poll-based delivery.
