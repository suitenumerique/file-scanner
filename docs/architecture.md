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

1. Authenticate (`X-API-Key`, constant-time); resolve `categories` ∪ `scanners`
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
   and POSTs the report to `webhook_url`.

## Statelessness

Nothing is persisted. A synchronous scan returns its verdict inline; an
asynchronous scan delivers its verdict **only** through the webhook. The
`job_id` is a correlation handle, not a key to any store — a caller that needs
durability is expected to run its own reaper and re-submit lost jobs. This keeps
the service horizontally scalable and free of a database.

### Forward path: polling

The `job_id` is deliberately part of the contract (returned in the `202` and
echoed in the webhook) so a future **poll** API is a purely additive change — no
existing caller breaks:

1. Add a small result store (e.g. Redis with a TTL) that the worker writes the
   final `ScanReport` to, keyed by `job_id`, at the same point it POSTs the
   webhook.
2. Add `GET /api/v1.0/jobs/{job_id}` returning `{status: pending|done|error, …}`
   — the same report shape the webhook delivers, or `404` past the TTL.
3. The webhook stays the **primary** delivery channel; polling is the durability
   / fallback path for callers that can't receive callbacks. Callers that
   already persist the returned `job_id` can adopt it without any request change.

This is intentionally *not* implemented — it trades the current
database-free/statelessness property for durability, so it should land only when
a consumer actually needs poll-based delivery. Until then, `job_id` stays a
correlation handle and the store stays absent.
