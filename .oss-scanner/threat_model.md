# Threat model

## What this project does and where untrusted input enters

File Scanner is the antivirus service of La Suite numérique, a family of
French government applications. Applications such as
Transfers send it a file, or the URL of one, and get back a verdict per
category (`docs/categories.md`). Their users then download or refuse the file
on that verdict, so the scanner decides whether a file written by anyone on
the Internet reaches an agent of a public body.

It is a FastAPI service in `src/` (`src/app.py`) with dramatiq workers on a
Redis Streams broker (`src/worker.py`, `src/tasks.py`, `src/broker.py`). The
engines are ClamAV over the clamd protocol (`src/scanners/clamav.py`), exav, a
clamd-compatible engine (`src/scanners/exav.py`), and JCOP, the HTTP analysis
service of cyber.gouv.fr (`src/scanners/jcop.py`). `src/scanner.py` reduces
what the engines answer to one verdict per category, and `src/wire.py` writes
it in the v2 shape or downgrades it to the v1 shape. The Helm chart is in
`deploy/helm/file-scanner`.

Actors: calling applications, each identified by a JWT issuer (`iss`) whose
Ed25519 public key is configured in `JWT_ISSUER_KEYS`; the receivers of the
webhooks those callers name; the authors of the files and of the servers the
URLs point at, who are anyone; the operators (the queue dashboard, metrics).

Entry points, most exposed first:

- The file content. Every byte of a scanned file is attacker-controlled, and
  so is every byte that the server at a submitted URL sends back, headers and
  redirects included. The worker downloads it in `scan_task`
  (`src/tasks.py`), enforces `MAX_URL_SIZE` against the header and the bytes
  actually read and `DOWNLOAD_MAX_SECONDS` against the clock, and streams the
  result to the engines.
- Client-encrypted sources, `src/encryption.py`, spec in
  `docs/client-encryption.md`: AES-256-GCM per chunk, with an AAD of
  `file_id:part:parts`. The key comes in the request. A bad key, a wrong
  chunking or a tampered chunk must fail as a permanent error, never as a
  clean file.
- Outbound requests: the download of the submitted `url` and the POST of the
  result to the submitted `webhook_url`. Both go through `src/ssrf.py`
  (vendored from suitenumerique/messages), whose guarantees are listed in
  `docs/security.md`: http/https only, no IP literals, every resolved address
  checked, the connection pinned to the checked address, every redirect hop
  re-validated, no HTTPS to HTTP downgrade, and webhook redirects never
  followed. `ALLOWED_URL_HOSTS` restricts the hosts; `SSRF_ALLOWED_HOSTS`
  exempts some. A bypass of any of these is a finding.
- The scan API: `POST /api/v{1,2}.0/scan` (a synchronous multipart upload),
  `POST /api/v{1,2}.0/scan-async` (a URL and a webhook) and
  `GET /api/v{1,2}.0/jobs/{job_id}`. Authentication is in `src/jwt_auth.py`:
  EdDSA only, the issuer's key picked by `iss`, `aud` checked, the lifetime
  capped by `JWT_MAX_AGE`, and the token bound to the method and target
  (`htm`, `htu`) and, on the async endpoint, to the body hash (`bh`). A job is
  readable only by the issuer that created it (`src/results.py`, `fetch`).
- The signed webhooks: with `JWT_SIGNING_KEY` set, each callback carries a JWT
  bound to the body and to the configured `webhook_url`; receivers verify it
  with `/.well-known/jwks.json`.
- The operator surfaces: `/metrics` (`verify_prometheus` in `src/app.py`) and
  the dramatiq queue dashboard (`src/dashboard.py`, HTTP Basic and an
  optional IP allowlist), which can delete queued work.
- The clamd and exav replies, parsed in `src/scanners/clamav.py` and
  `exav.py`, and the JCOP responses in `jcop.py`.

## Components that matter most / least

Most important, report findings here first:

- `src/scanner.py`, `src/scanners/` and `src/wire.py`: whether a file can be
  reported clean when it was not fully scanned, or when an engine found
  something. The "Fail-closed scanning" section of `docs/security.md` and
  `docs/scanner-backends.md` list the rules.
- `src/tasks.py` and `src/encryption.py`: the download, the decryption, the
  limits and the cleanup of the temporary file.
- `src/ssrf.py` and its two callers.
- `src/jwt_auth.py` and the authentication dependencies in `src/app.py`.
- `src/results.py`: who can read a stored verdict.

Less important, but still in scope: `src/config.py` (the profiles and
`MAX_URL_SIZE` checks), `src/dashboard.py`, `src/metrics.py`, `src/broker.py`,
`src/worker.py`, the Helm chart in `deploy/helm/file-scanner` (network
policies, secrets, defaults) and `deploy/docker/`.

Out of scope as a target, do not report findings here: ClamAV, exav and
JCOP themselves (report a bug in how we call them or read their answers, not
a bug inside them), Redis, `tests/`, `client-examples/`, `deploy/scripts/`,
`docker-compose.yml`, `Makefile`; third-party code in `/opt/venv` and
`/opt/python`.

## How to exercise it

The image for this scan places the checkout at `/src`. The service code is in
`/src/src` and is on `PYTHONPATH`; the environment is `/opt/venv`, on `PATH`.

Redis and clamd (on `127.0.0.1:3310`, with the signatures downloaded at build
time and the limits of `docker-compose.yml`) run in the image. The first bash
shell starts them and exports `OSS_SCANNER_SERVICES_STARTED=1`; shells it
spawns inherit that and skip the start, so after `svcctl stop` run
`svcctl start` yourself. If the signature download failed during the build, clamd
does not start and the ClamAV integration tests skip themselves: check
`svcctl status` before reading a test run as full ClamAV coverage. `BASH_ENV`
only reaches bash, so a `sh` or `#!/bin/sh` script must run `svcctl start`
itself. Use `svcctl start`, `svcctl stop` and `svcctl status`. clamd takes a
few seconds to load its signatures; its log is `/var/log/clamav/clamav.log`.
exav is not in the image, so the tests marked `exav` skip themselves. JCOP is
an Internet service; mock it.

Run the tests:

```sh
cd /src
pytest --no-cov
```

`APP_CONFIG=config.CiConfig` is set, the profile CI uses. It ignores the
environment except `EXAV_HOSTS` (`CiConfig.exav_hosts`), which would enable
exav and un-skip the `exav` tests; it is unset here. It relaxes the
request-time SSRF check and runs tasks eagerly, so the tests do not need a
worker. Fixtures in `tests/conftest.py` mint valid request-bound JWTs
(`auth_client`) for the `dev-issuer` test key.
`tests/test_ssrf.py`, `tests/test_scanner.py`, `tests/test_async.py` and
`tests/test_encryption.py` show how to drive each layer.

To reproduce against the production profile, with the SSRF check active at
request time and the real broker:

```sh
cd /src
APP_CONFIG=config.ProductionConfig uvicorn app:app --app-dir src --port 8090 &
APP_CONFIG=config.ProductionConfig python -m worker &
```

The JWT, webhook signing and dashboard values set in the image are the public
development values of `deploy/env/app.defaults`. The throwaway private key of
the `dev-issuer` caller is in the quick start of `README.md`; mint a
request-bound token with
`python deploy/scripts/mint-token.py "$DEV_PRIV" dev-issuer POST /api/v2.0/scan-async body.json`.
The EICAR test string is the simplest file clamd detects.

## How you rate severity

Rate first whether a file can reach a user without the verdict it deserves.

Critical: remote code execution; authentication bypass on the scan API; a
file that an engine flags, or that was not fully scanned, reported clean, by
input that the file's author or the server at its URL controls; server-side
request forgery that reaches an internal or metadata address through `url` or
`webhook_url`; a leak of `JWT_SIGNING_KEY`, or a way to make the service sign
a body that a receiver would accept for another URL.

High: a caller reads or influences another caller's job or verdict; a token
replayed against another endpoint, target or body than the one it was minted
for; a decryption path that accepts a tampered or reordered chunk; a
webhook delivered to a URL other than the one the caller named; a path
traversal or write outside the temporary directory; the dashboard reachable
without its password.

Medium: a denial of service that one file or one URL causes despite
`MAX_URL_SIZE` and `DOWNLOAD_MAX_SECONDS` (a worker held, memory or disk
exhausted, clamd taken down); a v1 and a v2 view of the same result that
disagree on whether the file is blocked; a leak of a scanned file's content
or URL to someone other than its caller.

Low: a hardening gap with no demonstrated impact; a missing rate limit on an
authenticated endpoint; a crash that only the caller's own request feels.

Rules we apply on top:

- Show the path from the untrusted input to the effect.
- A finding that needs a valid caller key is one level lower when its only
  victim is that same caller.
- A report that depends on a development value from `deploy/env/` in
  production is not a finding.
- Anything that exists only under the `TestConfig`, `CiConfig` or
  `LocalConfig` profiles of `src/config.py` is not a finding; report against
  `ProductionConfig`.

## Anything to leave alone

- ClamAV misses some malware. A file that no engine detects is not a finding,
  unless our code turned a detection, an error or a partial scan into clean.
- A `partial` verdict (`LIMITS-EXCEEDED`, `UNSCANNABLE`,
  `PASSWORD-PROTECTED`, a decryption failure) is never clean and never
  malware by design: the caller decides what to do with an unscanned file.
- The synchronous upload binds only the method and target in its JWT, not the
  file bytes (`docs/security.md`). This is known.
- `/.well-known/jwks.json` is public by design, and so are `/` and `/check`.
- `testing` and `worker_eager` are read only from the profile class, never
  from the environment; that is deliberate.
- Every secret in `deploy/env/*.defaults` and `tests/` is a public
  development value, not a leak.
- The image runs clamd from Debian (1.4) and no exav; production runs the
  `clamav/clamav` and exav images of `docker-compose.yml` and the Helm chart.
- `ruff` runs in CI. Do not report its opinions.
- A dependency CVE with no reachable call path in this code is not wanted.

## How reports and patches should look

Submit one finding per report, with an input that reproduces it: a file or a
small HTTP server script that serves it, and the `curl` command with a minted
token; or a failing `pytest` test under `tests/` that uses the fixtures in
`tests/conftest.py`.

Include a patch as a diff. It must pass, from `/src`:

```sh
ruff check
ruff format --check
```

The line length is 88 characters (`pyproject.toml`).

Report security questions outside this scan privately, per `SECURITY.md`.
