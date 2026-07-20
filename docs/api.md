# API reference

Scan endpoints require an `X-API-Key` header (see
[deployment.md](deployment.md#authentication)). `/check` and `/metrics` are
unauthenticated.

## `POST /api/v1.0/scan` — synchronous

Multipart upload of a single file under the `file` field. Selects work by
**category** and/or **scanner** and returns per-category aggregates plus a
per-scanner report. See [categories.md](categories.md) for the model.

| Param | In | Default | Meaning |
| --- | --- | --- | --- |
| `file` | form | — | The file to scan. |
| `categories` | query | `DEFAULT_CATEGORIES` | Comma-separated axes, e.g. `?categories=malware,nsfw`. The deployment picks the engines. |
| `scanners` | query | — | Comma-separated engine names, e.g. `?scanners=clamav,exav`. **Unions** with `categories`. |

Naming neither uses `DEFAULT_CATEGORIES`. Naming a scanner without its category
narrows an axis; naming it alongside the category adds to it.

```bash
curl -sf -H "X-API-Key: $API_KEY" -F "file=@file.pdf" \
     "http://localhost:8090/api/v1.0/scan?categories=malware,nsfw"
```

**Response `200`** — one key per **category** that ran (in its native type) plus
each scanner's result:

```json
{
  "malware": true,
  "nsfw": 0.02,
  "scanners": [
    {"scanner": "clamav",  "category": "malware", "kind": "malware", "reason": "Eicar-Test-Signature", "time": 0.01},
    {"scanner": "nudenet", "category": "nsfw",    "kind": "clean",   "score": 0.02, "time": 0.02}
  ]
}
```

- **Top-level per-category value**: a discrete axis (`malware`) is a bool
  reduced by *any* detection; a scored axis (`nsfw`) is a float reduced by *max*
  of the scanners' scores, or `null` when no scanner in that axis produced a
  score (didn't run / errored) — never `0.0`.
- **Per-scanner `kind`** is one of `clean`, `malware` (`reason` = signature),
  `flagged` (scored hit; `reason` = label, `score` = confidence), `unscannable`
  (`reason` = tag, e.g. `PASSWORD-PROTECTED` — could not be fully scanned,
  **not** clean), or `error` (transient failure to run that scanner).
- The scanners run **in parallel**. Aggregation within an axis is strict: the
  file is only clean on that axis if *every* scanner scanned it and found nothing.

**Errors:** `400` (unknown category/scanner or empty selection), `401`
(bad/missing key), `413` (over `MAX_UPLOAD_SIZE`), `503` (every scanner failed to
run).

## `POST /api/v1.0/scan-async` — asynchronous

`POST /v2/scan-async` is a deprecated alias (used by suitenumerique/transfers).

JSON body describing a file to fetch and scan; the report is delivered to
`webhook_url` (required).

```json
{
  "url": "https://storage.example.com/presigned/file.pdf",
  "filename": "file.pdf",
  "webhook_url": "https://app.example.com/av-callback",
  "metadata": { "file_id": "abc123" },
  "categories": ["malware"],
  "scanners": ["exav"]
}
```

`categories` and `scanners` are the same union selectors as the sync endpoint,
both optional (neither → `DEFAULT_CATEGORIES`); `metadata` is opaque and echoed
back. **Response `202`:** `{ "job_id": "…", "status": "pending" }`.

### Webhook payloads

On success the worker POSTs the report plus the job context:

```jsonc
{ "job_id": "…", "filename": "file.pdf", "metadata": {…},
  "malware": false,
  "scanners": [{"scanner": "clamav", "category": "malware", "kind": "clean", "time": 0.01}] }
```

A **pre-scan** failure (bad host, download error, too large) instead posts
`{…, "status": "error", "error_kind": "file"|"transient", "error": "…"}`.
`error_kind` is `transient` (retryable infra — the service already exhausted its
own retries) or `file` (permanent property of the file). If *every* scanner fails
transiently, the report is delivered with `status: error`, `error_kind:
transient`.

## `GET /check` · `GET /` — health

`200 Service OK` when the default scanners answer, otherwise `503`.

## `GET /metrics` — Prometheus

Unauthenticated exposition: default process metrics, scan counters
(`filescanner_scans_total{scanner,category,verdict,api_client}`,
`filescanner_scan_duration_seconds{scanner,api_client}`; `api_client` is the
caller's `API_KEYS` name), and signature-freshness gauges
(`filescanner_signature_outdated{scanner}`,
`filescanner_signature_version{scanner}`). See
[deployment.md](deployment.md#monitoring) for how to secure it.
