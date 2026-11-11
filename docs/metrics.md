# Metrics

Prometheus metrics come from **two endpoints**, one per kind of process, each
scraped as its own target. Run several instances and each one is one more
target; aggregate in PromQL (`sum by (...)`).

| Endpoint | Process | Covers |
| --- | --- | --- |
| `GET http://<app>:8090/metrics` | web (`uvicorn app:app`, one process) | HTTP traffic, sync scans, ClamAV signature database, queue state, Python process metrics |
| `GET http://<worker>:9191/metrics` | worker (`python -m worker`) | async scans, downloads, webhook deliveries, dramatiq per-message metrics |

Both require `Authorization: Bearer <PROMETHEUS_API_KEY>` when that key is set
(and are open otherwise — isolate them at the network layer then: the
`api_client` label names the calling services).

## Labels

| Label | Values |
| --- | --- |
| `mode` | `sync` (`POST /scan`, web process) / `async` (`POST /scan-async`, worker) |
| `verdict` | `clean`, `malware`, `flagged`, `partial`, `error` — see [categories.md](categories.md) |
| `api_client` | the caller's JWT `iss` (`drive`, `transfers`, …). Only on the counters that attribute work to a caller, not on histograms. |
| `scanner` / `category` | engine (`clamav`, `exav`, `jcop`) / axis (`malware`, …) |
| `queue` | `scans`, `webhooks` (the per-container `ping.<hostname>` healthcheck queues are left out) |

## Web process

### Scans (sync; the worker emits the same series with `mode="async"`)

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `filescanner_scans_total` | counter | scanner, category, verdict, mode, api_client | One per scanner run. An async job retried after a transient failure counts once per attempt. |
| `filescanner_scan_duration_seconds` | histogram | scanner, verdict, mode | Duration of one scanner run (buckets 50 ms … 15 min). |
| `filescanner_reports_total` | counter | category, verdict, mode, api_client | One per category per result returned to a caller, after combining the category's scanners — what the caller was told. |
| `filescanner_file_size_bytes` | histogram | mode | Size of the scanned file (plaintext, after decryption). Buckets 1 KiB … 4 GiB, ×4. |

### HTTP

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `filescanner_http_requests_total` | counter | route, method, status | `route` is the route template (`/api/v2.0/jobs/{job_id}`), `other` for anything that matched no API route (404s, the dashboard); unknown methods are `other`. |
| `filescanner_http_request_duration_seconds` | histogram | route, method | |

### ClamAV signature database

freshclam keeps clamd's signature database current on its own, but fails
silently: clamd then keeps scanning — and answering `clean` — with stale
signatures. These gauges show the database each clamd daemon has **loaded**,
read with clamd's `VERSION` command at scrape time (cached 60 s, 2 s timeout).
Every daemon of `CLAMAV_HOSTS` is asked, not one at random, so a stale one
can't hide behind its peers. Present when clamav is in `DEFAULT_SCANNERS`.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `filescanner_clamav_up` | gauge | daemon | 1 if the daemon answered `VERSION`; the two gauges below are absent for it when 0. |
| `filescanner_clamav_db_version` | gauge | daemon | Version of the loaded `daily` database. |
| `filescanner_clamav_db_timestamp_seconds` | gauge | daemon | Build time (Unix) of the loaded database. clamd prints it in its own timezone, read as UTC (the official image's). |

`daily` is published several times a day, so a database more than a day or two
old means updates are broken (freshclam failing, or clamd no longer
reloading) — see the alert below. Comparing against the latest *published*
version instead would flag every gap between two freshclam runs.

### Queue state

Read from the broker's Redis at scrape time (one pipelined round-trip, cached
5 s). They describe the **shared** broker, so every web instance reports the
same values: with several, aggregate with `max`, not `sum`, or turn them off on
all but one with `METRICS_QUEUE_STATS=false`. Absent in eager mode.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `filescanner_queue_stats_success` | gauge | | 0 when Redis could not be read; the gauges below are then absent. |
| `filescanner_queue_backlog` | gauge | queue | Enqueued, not yet delivered to any worker. Absent when Redis can't tell (right after a flush). |
| `filescanner_queue_in_flight` | gauge | queue | Delivered to a worker, not yet acknowledged. |
| `filescanner_queue_consumers` | gauge | queue | Consumers registered on the queue. 0 ⇒ no worker is consuming it. |
| `filescanner_queue_oldest_message_age_seconds` | gauge | queue | Age of the oldest unacknowledged message, waiting or in flight; 0 when empty. |
| `filescanner_queue_dead_letters` | gauge | queue | Messages in the dead-letter queue. |
| `filescanner_queue_delayed` | gauge | | Delayed messages — retry back-offs included — across all queues. |

Redis itself (memory, evictions, connections) is not covered: use a Redis
exporter (e.g. Alloy's `prometheus.exporter.redis`).

## Worker

### Async pipeline

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `filescanner_async_jobs_total` | counter | status, error_kind, api_client | Jobs that reached a terminal result: `status` `done` / `error`, `error_kind` `file` / `transient` (empty when done). |
| `filescanner_downloads_total` | counter | outcome | `ok`, `too_large`, `timeout`, `decrypt_failed`, `blocked` (allowlist / SSRF guard), `http_error`, `error`. |
| `filescanner_download_duration_seconds` | histogram | | Successful downloads, decryption included. |
| `filescanner_webhook_deliveries_total` | counter | outcome | `ok`; `retry` (failed, will be retried); `gave_up` (failed on its last attempt, dead-lettered); `blocked` (host rejected, dropped). |
| `filescanner_webhook_duration_seconds` | histogram | | One webhook POST, whatever its outcome. |

The scan metrics above, with `mode="async"`.

### dramatiq

From dramatiq's `Prometheus` middleware, labelled `queue_name`, `actor_name`:
`dramatiq_messages_total`, `dramatiq_message_errors_total`,
`dramatiq_message_retries_total`, `dramatiq_message_rejects_total`,
`dramatiq_messages_inprogress`, `dramatiq_delayed_messages_inprogress`,
`dramatiq_message_duration_milliseconds`. The healthcheck's `ping` actor shows
up under its `ping.<hostname>` queue.

### How the worker exposes them

A worker forks `WORKER_PROCESSES` processes, so it runs prometheus_client in
multiprocess mode: `worker.py` points `PROMETHEUS_MULTIPROC_DIR` at
`WORKER_METRICS_DIR` (wiped at start), every process writes its samples there,
and one extra process aggregates them on `WORKER_METRICS_HOST:WORKER_METRICS_PORT`
(see `src/worker_metrics.py`). The directory must belong to one worker
instance — don't share it between two workers on the same host. No
`process_*` / `python_*` metrics come from the worker (they don't aggregate
across processes); take host metrics from a node exporter.

| Variable | Default | |
| --- | --- | --- |
| `WORKER_METRICS_PORT` | `9191` | `0` disables the endpoint (and dramatiq's middleware). |
| `WORKER_METRICS_HOST` | `0.0.0.0` | Bind to the private interface where possible. |
| `WORKER_METRICS_DIR` | `<tmp>/file-scanner-metrics` | |
| `METRICS_QUEUE_STATS` | `true` | Queue-state gauges on the web `/metrics`. |

## Scraping (Grafana Alloy)

```alloy
prometheus.scrape "file_scanner_app" {
  targets         = [{"__address__" = "app-1:8090"}, {"__address__" = "app-2:8090"}]
  job_name        = "file-scanner-app"
  bearer_token    = sys.env("PROMETHEUS_API_KEY")
  forward_to      = [prometheus.remote_write.default.receiver]
}

prometheus.scrape "file_scanner_worker" {
  targets         = [{"__address__" = "worker-1:9191"}, {"__address__" = "worker-2:9191"}]
  job_name        = "file-scanner-worker"
  bearer_token    = sys.env("PROMETHEUS_API_KEY")
  forward_to      = [prometheus.remote_write.default.receiver]
}
```

## Not covered here

- **exav's database**: exav manages its own reloads and its `VERSION` isn't
  the ClamAV format.
- **Redis** internals: see above.
- **Host metrics** (CPU, memory, disk): a node exporter.

## Dashboard

[`deploy/grafana/file-scanner.json`](../deploy/grafana/file-scanner.json):
a Grafana dashboard over the metrics above (Dashboards → New → Import). It
asks for a Prometheus data source and filters by caller (`api_client`) and
`mode`. Rows: overview, scans, async pipeline (queues, jobs, downloads,
webhooks), workers (dramatiq), HTTP, ClamAV.

## Useful queries

```promql
# Detections per category, per caller
sum by (category, api_client) (rate(filescanner_reports_total{verdict="malware"}[1h]))

# Share of scanner runs that failed, per engine
sum by (scanner) (rate(filescanner_scans_total{verdict="error"}[5m]))
  / sum by (scanner) (rate(filescanner_scans_total[5m]))

# p95 scan time
histogram_quantile(0.95, sum by (le, scanner) (rate(filescanner_scan_duration_seconds_bucket[10m])))

# Async jobs waiting too long (alert)
max by (queue) (filescanner_queue_oldest_message_age_seconds) > 600

# No worker consuming scans (alert)
max(filescanner_queue_consumers{queue="scans"}) == 0

# Webhooks lost (alert)
increase(filescanner_webhook_deliveries_total{outcome="gave_up"}[1h]) > 0

# ClamAV signatures more than 2 days old, or a daemon not answering (alert)
time() - max by (daemon) (filescanner_clamav_db_timestamp_seconds) > 2 * 86400
max by (daemon) (filescanner_clamav_up) == 0
```
