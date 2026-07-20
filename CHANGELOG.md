# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Category-based, multi-axis scanning.** A request selects work by **category**
  (an axis of judgment, e.g. `malware`) and/or **scanner**, which union:
  `?categories=malware,nsfw` and/or `?scanners=clamav,exav` (and the matching
  fields on async); `DEFAULT_CATEGORIES` is used when neither is named. Each
  backend declares the category it feeds; the deployment maps categories to
  engines via the `DEFAULT_SCANNERS` JSON map. Selected scanners run **in
  parallel**, each on its own file handle. A *scored* axis (e.g. `nsfw`) is fully
  supported by the plumbing (`Verdict.score`, `Scanner.scored`, max-reduction)
  though no scored backend ships yet. Config is validated at boot
  (`validate_registry`). See `docs/categories.md`.
- **New `POST /api/v1.0/scan` and `/api/v1.0/scan-async` endpoints** returning a
  per-category aggregate plus a per-scanner breakdown, e.g.
  `{malware: false, nsfw: 0.99, scanners: [{scanner, category, kind, score?, reason?, time}]}`.
  A discrete axis reduces by *any* detection (bool); a scored axis by *max*
  (float, or `null` when nothing scored — never `0.0`). Within an axis,
  aggregation is **strict**: clean only if *every* scanner scanned it and found
  nothing. `/v2/scan-async` is kept as a deprecated alias for
  suitenumerique/transfers.
- **exav backend** (`scanners/exav.py`): a Rust reimplementation reusing the
  clamd protocol, with its own daemon pool (`EXAV_HOSTS`). It owns its structured
  `ERROR` tags (`LIMITS-EXCEEDED`, `UNSCANNABLE`, `PASSWORD-PROTECTED`, and any
  future code), surfaced as an `unscannable` result; unknown tags default to
  `UNSCANNABLE` so a new verdict is never mistaken for clean.
- **jcop backend** (`scanners/jcop.py`): [Je Clique Ou Pas](https://jecliqueoupas.cyber.gouv.fr)
  (cyber.gouv.fr), a submit-then-poll HTTP analyser modelled on
  suitenumerique/django-lasuite.
- **Prometheus metrics at `GET /metrics`** (`metrics.py`): scan counters
  (`filescanner_scans_total{scanner,category,verdict,api_client}`), duration
  (`filescanner_scan_duration_seconds{scanner,api_client}`) — `api_client` is the
  `API_KEYS` name of the caller, for per-consumer breakdowns — and
  signature-freshness gauges
  (`filescanner_signature_outdated`/`_version{scanner}`, refreshed lazily on
  scrape). Replaces the old `/check_version` endpoint.
- **Guarded queue dashboard** (`dashboard.py`): the web app (`uvicorn app:app`)
  serves the `dramatiq-redis-streams` dashboard — destructive & unauthenticated
  upstream — at `/dashboard`, behind mandatory Basic auth (fail-closed) + an
  optional IP allowlist (`WORKER_DASHBOARD_USER` / `WORKER_DASHBOARD_PASSWORD` /
  `WORKER_DASHBOARD_ALLOWED_IPS`). Mounted only when a password is set (unset ⇒
  not served).
- **Client-side load balancing** for the clamd backends: `CLAMAV_HOSTS` /
  `EXAV_HOSTS` (`host:port,…`) pick a daemon at random per scan, so a task retry
  fails over to another host without an external load balancer.
- Environment configuration for `MAX_UPLOAD_SIZE`, `MAX_URL_SIZE`,
  `URL_DOWNLOAD_TIMEOUT`, `DOWNLOAD_MAX_SECONDS`, `WEBHOOK_TIMEOUT`,
  `WEBHOOK_MAX_ATTEMPTS`, `CLAMAV_PORT`, `CLAMAV_TXT_URI`, `SSRF_ALLOWED_HOSTS`,
  `DEFAULT_SCANNERS` (a JSON `category → [engines]` map), `DEFAULT_CATEGORIES`,
  `CLAMAV_HOSTS`, `EXAV_HOSTS`, `JCOP_*`, and `WORKER_DASHBOARD_*`.
- `ruff`, `pytest`/`pytest-cov`, `pip-audit` and `pre-commit` developer tooling,
  with matching CI jobs. Integration tests that need a live daemon are marked
  `@pytest.mark.integration` and auto-skip when clamav is unreachable.
- Dependencies are now managed with **uv** via `pyproject.toml` + `uv.lock`
  (exact pins; runtime deps + a `dev` group), replacing `requirements*.txt`. The
  Docker build and CI use `uv sync --frozen`.
- `CONTRIBUTING.md`, `SECURITY.md`, `docs/`, and this changelog.
- A total transfer deadline (`DOWNLOAD_MAX_SECONDS`) on async downloads.
- `src/` layout with the test suite in a top-level `tests/`; every `config.py`
  setting is documented inline (env var + units).
- `Procfile` declaring the `web` and `worker` process types.

### Changed

- **Backend-agnostic scanner interface.** The app and worker depend only on a
  `Scanner` interface + normalized `Verdict` (`scanner.py`); engine specifics
  live in `scanners/clamav.py`, `scanners/exav.py`, and `scanners/jcop.py`.
  Renamed `clamav_rest.py` → `app.py`, folded `clamav_versions.py` into the
  backend, and made logging/titles product-neutral ("File Scanner"). A buggy
  backend raising a non-`ScannerError` is isolated as an `error` result rather
  than aborting the request or its sibling scanners.
- **Async scans now use [dramatiq](https://dramatiq.io/)** over the
  `dramatiq-redis-streams` broker (as in suitenumerique/st-home and /messages),
  replacing Celery. The broker is swappable in one module (`broker.py`) and tasks
  are enqueued with `task.send(...)`; tests run against an in-memory stub broker
  (no Redis). New `WORKER_*` env vars.
- **The worker scans over INSTREAM** instead of a shared-filesystem `SCAN` — it
  no longer shares a volume with the scanner, removing the root/volume-ownership
  dance entirely.
- **Production image is now distroless & multi-stage** (uv-managed CPython 3.14,
  `gcr.io/distroless/cc-debian13:nonroot`), mirroring suitenumerique/messages.
  Runs as `nonroot` with no entrypoint/gosu.
- **Makefile adopts the Messages conventions** — auto-generated `help`, and
  `bootstrap` / `run` / `stop` / `logs` targets (no more `make up`).
- SSRF protection now uses the `ssrf.py` module vendored from
  suitenumerique/messages: resolved-IP pinning and per-hop redirect
  re-validation defeat DNS-rebinding (TOCTOU) and redirect-to-internal attacks.
  The `webhook_url` is SSRF-validated too, and the positive host allowlist plus
  SSRF guard are re-enforced at the worker (`validation.py`), not just the web
  layer. `SSRF_ALLOWED_HOSTS` allows trusted internal destinations to bypass the
  private-IP block.
- API keys are compared in constant time.
- Renamed the single-endpoint clamd config vars to the `CLAMAV_*` family
  (`CLAMAV_HOST` / `CLAMAV_PORT` / `CLAMAV_SOCKET`) and the compose service to
  `clamav`, so all backend knobs are product-named; `clamd` now appears only
  where it means the wire protocol. Generic knobs dropped the stale product name
  too (`SCAN_DIR=/tmp/file-scanner`, `WORKER_QUEUE_NAMESPACE=file-scanner`).

### Fixed

- `CLAMAV_SOCKET` defaults to empty, so `CLAMAV_HOST`/`CLAMAV_PORT` work out of
  the box for a TCP daemon (the old `/app/run/clamd.sock` default silently
  overrode them).
- A scan no longer reports an unscannable file (an `ERROR` verdict) as malware; a
  recognised exav verdict yields an `unscannable` result, a transient/infra scan
  error is retried (surfacing `503` only when every scanner fails), and an
  untagged file error is surfaced as `unscannable` — never as a near-clean clean.
- A bare transient token (e.g. `TIMEOUT`) is routed to a retry rather than being
  mistaken for a permanent unscannable-file verdict.
- Removed a 0-byte test fixture whose test asserted nothing.

### Removed

- The legacy `POST /v2/scan` sync endpoint and its single-verdict response.
- `GET /check_version`; signature freshness is now Prometheus gauges on
  `/metrics`.
- `gitlint` and its CI job.
- The Locust load tests (`perf/`) and the stale, basic-auth client examples.
- Scalingo deployment manifest (`scalingo.json`); this platform is not supported
  here.
