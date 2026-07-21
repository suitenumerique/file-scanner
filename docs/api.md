# API reference

Scan endpoints require an EdDSA **Bearer JWT** (`Authorization: Bearer <jwt>`);
see [deployment.md](deployment.md#authentication) and
[security.md](security.md#authentication). The token binds the request (method +
target, plus the JSON body on the async endpoint), so mint one per request.
`/check` and `/.well-known/jwks.json` are unauthenticated; `/metrics` is open
unless `PROMETHEUS_API_KEY` is set (then it needs `Authorization: Bearer <key>`).

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
# $TOKEN is a request-bound JWT (see the README quick start for how to mint one);
# htu must include the query string, e.g. "/api/v1.0/scan?categories=malware,nsfw".
curl -sf -H "Authorization: Bearer $TOKEN" -F "file=@file.pdf" \
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
  **not** clean), or `error` (transient failure to run that scanner). A `malware`
  result may also carry **`location`** — the inner path of the matched member
  within a container (`report.zip/payload.exe`) — when the backend reports it
  (exav); it's omitted otherwise.
- The scanners run **in parallel**. Aggregation within an axis is strict: the
  file is only clean on that axis if *every* scanner scanned it and found nothing.

**Errors:** `400` (unknown category/scanner or empty selection), `401`
(bad/missing key), `413` (over `MAX_UPLOAD_SIZE`), `503` (every scanner failed to
run).

## `POST /api/v1.0/scan-async` — asynchronous

JSON body describing a file to fetch and scan. The report is delivered to
`webhook_url` and, when the result store is enabled (`WORKER_RESULT_TTL > 0`), is
also retrievable by polling [`GET /api/v1.0/jobs/{job_id}`](#get-apiv10jobsjob_id--poll-a-job).
`webhook_url` is **required unless the store is enabled** — there must be at least
one way to get the result.

```json
{
  "url": "https://storage.example.com/presigned/file.pdf",
  "filename": "file.pdf",
  "webhook_url": "https://app.example.com/av-callback",
  "metadata": { "file_id": "abc123" },
  "categories": ["malware"],
  "scanners": ["exav"],
  "encryption": { "scheme": "aes-256-gcm-chunked-v1", "key": "<url-safe-base64-AES-256-key>", "chunk_size": 65536, "file_id": "abc123", "parts": 5 }
}
```

`categories` and `scanners` are the same union selectors as the sync endpoint,
both optional (neither → `DEFAULT_CATEGORIES`); `metadata` is opaque and echoed
back. **Response `202`:** `{ "job_id": "…", "status": "pending" }`.

**`encryption`** (optional) marks the source as **client-encrypted** — the
service decrypts it before scanning, since a scanner would otherwise pronounce
opaque ciphertext clean. AES-256-GCM, one chunk per `chunk_size` plaintext bytes,
each `IV(12) || ciphertext || tag(16)` authenticated against
`f"{file_id}:{part}:{parts}"` (position **and** total, so reordering and trailing
truncation both fail). A bad key, wrong chunking, or tampered/truncated
ciphertext is a **permanent** failure, reported via the webhook as
`error_kind: "file"` (`decryption_failed: …`), never retried. Full caller spec
(field meanings, IV-uniqueness requirement, key-handling caveats):
[client-encryption.md](client-encryption.md).

### Webhook payloads

When `JWT_SIGNING_KEY` is configured, the POST carries an `Authorization: Bearer
<jwt>` signed by this service; its `bh` claim binds the exact body bytes. Verify
it against `/.well-known/jwks.json` to authenticate the callback (see
[security.md](security.md#signed-webhooks)). Delivery is a dedicated retriable
task — it retries with back-off and dead-letters if the receiver never accepts
it, so make your receiver **idempotent on `job_id`**. **Respond with a `2xx`
directly**: redirects are **not** followed (the token binds the original URL), so
a `3xx` is treated as a failed delivery and retried.

On success the worker POSTs the report plus the job context:

```jsonc
{ "job_id": "…", "status": "done", "filename": "file.pdf", "metadata": {…},
  "malware": false,
  "scanners": [{"scanner": "clamav", "category": "malware", "kind": "clean", "time": 0.01}] }
```

A **pre-scan** failure (bad host, download error, too large) instead posts
`{…, "status": "error", "error_kind": "file"|"transient", "error": "…"}`.
`error_kind` is `transient` (retryable infra — the service already exhausted its
own retries) or `file` (permanent property of the file). If *every* scanner fails
transiently, the report is delivered with `status: error`, `error_kind:
transient`. `status` is thus `done` on a completed scan and `error` on a failure.

## `GET /api/v1.0/jobs/{job_id}` — poll a job

Optional, off by default. When `WORKER_RESULT_TTL > 0` an async job's result is
stored (in the broker's Redis, expiring after that many seconds) so a caller can
poll it instead of — or as a fallback to — the webhook. The webhook stays the
**primary** channel; polling is the durability path for callers that can't
receive callbacks or that missed one.

Same Bearer-JWT auth as the scan endpoints (the token binds method + target). A
job is **owner-scoped**: you can only read a job your own `iss` submitted.

**Response `200`** — the same record the webhook delivers, with a `status`:

```jsonc
{ "job_id": "…", "status": "pending" }                       // still queued/running
{ "job_id": "…", "status": "done",  "malware": false, "scanners": [ … ] }  // finished
{ "job_id": "…", "status": "error", "error_kind": "file", "error": "…" }   // failed
```

Poll until `status` is `done` or `error`. **`404`** when the job is unknown, has
expired past its TTL, belongs to another caller, or the store is disabled
(`WORKER_RESULT_TTL=0`). **`401`** on a bad/missing token.

## `GET /check` · `GET /` — health

`200 Service OK` when the default scanners answer, otherwise `503`.

## `GET /.well-known/jwks.json` — webhook-signing public key

Unauthenticated JWK Set of this service's webhook-signing public key(s), derived
from `JWT_SIGNING_KEY` at boot. Receivers fetch it to verify signed webhook
callbacks. `{"keys": []}` when no signing key is configured.

## `GET /metrics` — Prometheus

Prometheus exposition (bearer-gated when `PROMETHEUS_API_KEY` is set): default
process metrics, scan counters
(`filescanner_scans_total{scanner,category,verdict,api_client}`,
`filescanner_scan_duration_seconds{scanner,api_client}`; `api_client` is the
caller's JWT `iss`), and signature-freshness gauges
(`filescanner_signature_outdated{scanner}`,
`filescanner_signature_version{scanner}`). See
[deployment.md](deployment.md#monitoring) for how to secure it.
