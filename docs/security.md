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

Scan endpoints authenticate with a short-lived EdDSA (Ed25519) **Bearer JWT**
(see [deployment.md](deployment.md#authentication)).

- **Verification.** Callers sign a token with their *private* key; we verify it
  with their *public* key, selected by the token's `iss` claim (`JWT_ISSUER_KEYS`).
  Because we hold only public keys, a leak of our config cannot forge caller
  tokens — the key advantage over a shared static key. The algorithm is
  **hard-pinned to EdDSA** (the verifier never trusts the token's own `alg`
  header), so `alg:none` / algorithm-confusion attacks don't apply, `aud` must
  match this service, and `exp - iat` is capped (`JWT_MAX_AGE`) to bound a
  captured token's replay window.
- **Request binding.** The token carries `htm` (method) and `htu` (path + query),
  and on the async endpoint `bh` (SHA-256 of the JSON body). We recompute and
  compare, so a captured token can't be replayed against a different endpoint or
  with a swapped `url` / `webhook_url`. The sync upload's file **bytes are not
  hashed** (only its method + target are bound).

## Signed webhooks

When `JWT_SIGNING_KEY` is set, each webhook callback carries an
`Authorization: Bearer <jwt>` signed with our private key, whose `bh` claim binds
the exact bytes POSTed. Receivers authenticate the callback and detect tampering
by verifying it against our public key, published at `/.well-known/jwks.json`
(derived from the private key at boot — a fixed private key yields a fixed public
key, so it is stable across restarts and replicas). The callback's `aud`/`htu`
bind the exact configured `webhook_url`, and **redirects are not followed** — a
`3xx` is a failed delivery — so the signed body only ever reaches the URL it was
signed for.
