# API reference

Scan endpoints require an EdDSA **Bearer JWT** (`Authorization: Bearer <jwt>`);
see [deployment.md](deployment.md#authentication) and
[security.md](security.md#authentication). The token binds the request (method +
target, plus the JSON body on the async endpoint), so mint one per request.
`/check` and `/.well-known/jwks.json` are unauthenticated; `/metrics` is open
unless `PROMETHEUS_API_KEY` is set (then it needs `Authorization: Bearer <key>`).

## Versions

Two versions are served side by side and the path selects one. Everything below
documents **`/api/v2.0/`**, the current version.

`/api/v1.0/` is frozen and still answers every route, in the shape it always
did: one flat scalar per category at the top level (`"malware": true|false|null`)
with `error_kind` / `error` beside it, instead of `verdicts`. It is derived from
the same verdict this page describes — same computation, narrower vocabulary —
so the two versions cannot disagree about a file. Two things v1 cannot say, and
they are why v2 exists: `null` means both "the file could not be read" and "the
engines failed" (only `error_kind` separates them, and it is a single key for the
whole response), and a content-policy hit arrives as a detection because v1 has
no word for one. See [`src/wire.py`](../src/wire.py) for the exact mapping.

Moving a caller to v2 means changing the path **and** what it signs: the JWT's
`htu` binds the target, so a token minted for v1 is rejected on v2.

## `POST /api/v2.0/scan` — synchronous

Multipart upload of a single file under the `file` field. Selects work by
**category** and/or **scanner** and returns per-category aggregates plus a
per-scanner report. See [categories.md](categories.md) for the model.

| Param | In | Default | Meaning |
| --- | --- | --- | --- |
| `file` | form | — | The file to scan. |
| `categories` | query | `DEFAULT_CATEGORIES` | Comma-separated axes, e.g. `?categories=malware`. The deployment picks the engines; an axis it doesn't configure is a `400`. |
| `scanners` | query | — | Comma-separated engine names, e.g. `?scanners=clamav,exav`. **Unions** with `categories`. |

Naming neither uses `DEFAULT_CATEGORIES`. Naming a scanner without its category
narrows an axis; naming it alongside the category adds to it.

```bash
# $TOKEN is a request-bound JWT (see the README quick start for how to mint one);
# htu must include the query string, e.g. "/api/v2.0/scan?categories=malware".
curl -sf -H "Authorization: Bearer $TOKEN" -F "file=@file.pdf" \
     "http://localhost:8090/api/v2.0/scan?categories=malware"
```

**Response `200`** — a `verdicts` entry per **category** that ran, and each
scanner's result:

```json
{
  "verdicts": {
    "malware": {"kind": "malware", "reason": "Eicar-Test-Signature"}
  },
  "scanners": [
    {"scanner": "exav",   "category": "malware", "kind": "malware", "reason": "Eicar-Test-Signature", "location": "report.zip/payload.exe", "time": 0.02},
    {"scanner": "clamav", "category": "malware", "kind": "clean", "time": 0.01}
  ]
}
```

One entry per category that ran. Every shipped backend feeds `malware`, so a
response carries that one key today; a deployment that adds an axis gets one
more. The scored form (`"kind": "flagged"` with a `score`) is described below
for completeness — **no shipped backend produces it**, see
[categories.md](categories.md).

- **`verdicts[category].kind`** — the axis's answer in the scanners' own
  vocabulary: the same five words as a per-scanner `kind`, reduced across the
  category. It comes with the `reason` that belongs to it (signature / label /
  tag / message), the `location` of a detection inside a container, and — on a
  scored axis — a `score`.
- **How the category's engines reduce to one word**, in two rules:

  > **Precedence:** `malware` (or `flagged`) > `error` > `partial` > `clean`.
  > **Scope:** a detection counts from *any* scanner, advisory included; not
  > having read the whole file (`error`, `partial`) counts only from the
  > *deciding* ones.

  The precedence is what a caller acts on: a detection is a fact no other
  engine can soften, `error` before `partial` keeps a passing outage from being
  blamed on the file, and `clean` is last because it is the only word that
  requires every deciding engine to have read the file in full.
- **`verdicts[category].score`** — only on a scored axis, reduced by *max*
  across its scanners. It is **absent** rather than `0.0` when nothing scored,
  since `0.0` would assert "definitely not".
- **Per-scanner `kind`** is one of `clean`, `malware` (`reason` = signature),
  `flagged` (scored hit; `reason` = label, `score` = confidence), `partial`
  (`reason` = tag, e.g. `PASSWORD-PROTECTED` — could not be fully scanned,
  **not** clean), or `error` (transient failure to run that scanner). Each
  engine's wire vocabulary and how it maps onto these five words is in
  [glossary.md](glossary.md#3-the-five-words). A `malware`
  result may also carry **`location`** — the inner path of the matched member
  within a container (`report.zip/payload.exe`) — when the backend reports it
  (exav); it's omitted otherwise.
- The scanners run **in parallel**. Aggregation within an axis is strict: the
  file is only clean on that axis if every *deciding* scanner scanned it and
  found nothing. A scanner listed in `ADVISORY_SCANNERS` (see
  [categories.md](categories.md#advisory-scanners)) is not deciding: its
  result is reported with `"advisory": true` (the key is **omitted** rather
  than `false` otherwise), its detection counts, but its
  failure to examine the file does not — unless it ran alone. Note that
  "deciding" is therefore **not** simply the absence of that flag: when a
  category ran only advisory engines they decide it, so do not derive one from
  the other. The verdict already has the rule applied.

**Errors:** `400` (unknown category/scanner or empty selection), `401`
(bad/missing key), `413` (over `MAX_UPLOAD_SIZE`), `503` (every deciding
scanner failed to run **and** nothing was detected — a detection is reported
with a `200`, whichever engine made it).

## `POST /api/v2.0/scan-async` — asynchronous

JSON body describing a file to fetch and scan. The report is delivered to
`webhook_url` and, when the result store is enabled (`WORKER_RESULT_TTL > 0`), is
also retrievable by polling [`GET /api/v2.0/jobs/{job_id}`](#get-apiv20jobsjob_id--poll-a-job).
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

Every payload carries the version it is written in (`"api_version": "v2.0"`).
A callback has no route to select a version with, so its shape is the one the
**job was submitted under** — which is not necessarily the one you read now: a
scan outlives a deploy, so a job submitted before you upgraded is delivered
after it. Read the stamp rather than sniffing for keys, and on a version you do
not read, **acknowledge with a `2xx` and re-submit the scan** under the version
you speak. Refusing delivery does not help: the body was shaped at submission
time, so every retry carries the same one until it dead-letters.

The POST carries the job context — `job_id`, `filename`, and the `metadata` you
submitted — plus two fields that answer different questions and do not
substitute for one another: **`status`** says whether the job ran, **`verdicts`**
says what the scan concluded. Four shapes:

```jsonc
// 1. The scan ran and cleared the file. Release it.
{ "job_id": "…", "status": "done", "filename": "file.pdf", "metadata": {…},
  "verdicts": {"malware": {"kind": "clean"}},
  "scanners": [{"scanner": "clamav", "category": "malware", "kind": "clean", "time": 0.01}] }

// 2. The scan ran and could not clear the file. `status` describes the job,
//    not the file: this is a complete answer, and no retry produces another
//    one. Reject the file.
{ "job_id": "…", "status": "done", "filename": "locked.zip", "metadata": {…},
  "verdicts": {"malware": {"kind": "partial", "reason": "PASSWORD-PROTECTED"}},
  "scanners": [{"scanner": "exav", "category": "malware", "kind": "partial",
                "reason": "PASSWORD-PROTECTED", "time": 0.02}] }

// 3. Every deciding engine failed. The report is still attached and its
//    verdicts are `error`, but the job is marked failed. Retry it.
{ "job_id": "…", "status": "error", "filename": "locked.zip", "metadata": {…},
  "error_kind": "transient", "error": "all scanners failed",
  "verdicts": {"malware": {"kind": "error", "reason": "exav scan failed: …"}},
  "scanners": [{"scanner": "exav", "category": "malware", "kind": "error",
                "reason": "exav scan failed: …", "time": 0.01}] }

// 4. The job failed before scanning (bad host, download error, file too large,
//    decryption failed). Nothing ran, so there is no report at all — this is
//    the one shape with no `verdicts` key.
{ "job_id": "…", "status": "error", "filename": "huge.bin", "metadata": {…},
  "error_kind": "file", "error": "file_too_large: …" }
```

**`error_kind`** appears only next to `status: error`, and belongs to the job,
never to a verdict. It is `transient` (retryable infrastructure — the service
has already exhausted its own retries) or `file` (a permanent property of the
file, so retrying is pointless).

A caller's rule of thumb: retry on `status: error` or a `kind` of `error`,
block on `malware` / `flagged` / `partial`, release only on `clean`, and treat
anything it does not recognise as a block.

## `GET /api/v2.0/jobs/{job_id}` — poll a job

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
{ "job_id": "…", "status": "done",  "verdicts": {"malware": {"kind": "clean"}},
  "scanners": [ … ] }                                        // finished
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
