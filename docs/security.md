# Security

To **report** a vulnerability, see [`SECURITY.md`](../SECURITY.md). This page
describes the controls the service implements.

## SSRF protection

Async scans fetch a caller-supplied `url` and POST to a caller-supplied
`webhook_url`, so both are guarded against Server-Side Request Forgery. The guard
is the `ssrf.py` module vendored from
[suitenumerique/messages](https://github.com/suitenumerique/messages):

- **Scheme** is restricted to `http`/`https`; raw IP literals are rejected.
- **Resolution** — hostnames are resolved and refused if *any* record points at
  loopback, link-local, private, CGNAT (100.64.0.0/10), reserved, multicast, or
  cloud-metadata (`169.254.169.254`, `fd00:ec2::254`) space.
- **IP pinning** — the connection is pinned to the validated IP, so DNS can't be
  re-resolved to an internal address between the check and the request (a TOCTOU
  / DNS-rebinding attack).
- **Redirects** are followed manually, re-validating and re-pinning every hop,
  and an HTTPS→HTTP downgrade is refused.

The guard runs in the web process at request time (fast rejection) *and* in the
worker at fetch time (the actual protection). It is inert only under the
test/CI profiles (`settings.testing`).

### Allowlists

Two separate, intentionally-narrow allowlists (see [deployment.md](deployment.md#configuration)):

- `ALLOWED_URL_HOSTS` — a **positive restriction**: when set, only these
  hostnames may be submitted at all.
- `SSRF_ALLOWED_HOSTS` — a **bypass**: these hostnames are trusted to resolve to
  a private/internal address (e.g. internal object storage, an internal webhook
  receiver). Keep it minimal.

## Resource limits

An async download can't be used to exhaust a worker:

- `MAX_URL_SIZE` — a hard byte cap, enforced both against the `Content-Length`
  header and against the bytes actually streamed (a missing/understated header
  can't sneak past it).
- `DOWNLOAD_MAX_SECONDS` — a total wall-clock budget, so a server that dribbles
  bytes just inside each read timeout can't hold a worker slot indefinitely
  (slow-drip DoS).
- The downloaded file is always deleted in a `finally` block.

## Fail-closed scanning

A file is reported **clean only if it was actually scanned in full**:

- A missing verdict (path not visible to the scanner) or an `ERROR` verdict is
  never reported as clean.
- Extended verdicts (`LIMITS-EXCEEDED` / `UNSCANNABLE` / `PASSWORD-PROTECTED`,
  and any future tag) are surfaced as `unscannable`, never as malware and never
  as clean — see [scanner-backends.md](scanner-backends.md). Using
  [exav](https://github.com/sylvinus/exav) as the engine closes ClamAV's
  silent-`OK`-on-skipped-file gap.

## Authentication

API keys are required on scan endpoints and compared in **constant time**
(`hmac.compare_digest`) so a timing side channel can't recover a key.
