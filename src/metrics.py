"""Prometheus metrics.

Exposed at ``GET /metrics`` on the web process (default Python/process metrics
plus the metrics below). Scans are recorded from :func:`scanner.run_scanners`,
the single choke point for both the sync endpoint and the async worker task.

Note: metrics live in the in-process registry, so the web process's ``/metrics``
covers the scans it runs (the sync endpoint). Async scans run in the separate
worker process; scrape it too, or enable prometheus multiprocess mode
(``PROMETHEUS_MULTIPROC_DIR``), to aggregate across both.
"""

import time

from prometheus_client import Counter, Gauge, Histogram

SCANS = Counter(
    "filescanner_scans_total",
    "File scans by scanner, category, verdict "
    "(clean/malware/flagged/unscannable/error), and API client (the JWT `iss` "
    "of the caller that made the request).",
    ["scanner", "category", "verdict", "api_client"],
)

SCAN_DURATION = Histogram(
    "filescanner_scan_duration_seconds",
    "Per-scanner scan duration in seconds, by API client.",
    ["scanner", "api_client"],
)

# Signature-database freshness (replaces the old /check_version endpoint),
# refreshed lazily on scrape — see refresh_signatures().
SIGNATURE_OUTDATED = Gauge(
    "filescanner_signature_outdated",
    "1 if the scanner's local signature DB is behind the latest published version.",
    ["scanner"],
)
SIGNATURE_VERSION = Gauge(
    "filescanner_signature_version",
    "The scanner's local signature DB version, when numeric.",
    ["scanner"],
)

# Signature lookups hit the daemon + DNS, so refresh at most this often.
SIGNATURE_REFRESH_TTL = 300  # seconds
_last_signature_refresh = 0.0


def record(result, api_client: str = "") -> None:
    """Record one ``scanner.ScannerResult`` for ``api_client`` (caller ``iss``)."""
    SCANS.labels(result.scanner, result.category, result.kind, api_client).inc()
    SCAN_DURATION.labels(result.scanner, api_client).observe(result.time)


def refresh_signatures(names, get_scanner) -> None:
    """Best-effort refresh of the signature-freshness gauges for ``names``.

    Rate-limited to ``SIGNATURE_REFRESH_TTL``. ``get_scanner`` is passed in so
    this module doesn't import :mod:`scanner` (which imports this one).
    """
    global _last_signature_refresh  # noqa: PLW0603 — module-level TTL cache
    now = time.monotonic()
    if now - _last_signature_refresh < SIGNATURE_REFRESH_TTL:
        return
    _last_signature_refresh = now
    for name in names:
        try:
            info = get_scanner(name).version()
        except Exception:  # noqa: S112 — freshness is best-effort, never fail a scrape
            continue
        if info is None:
            continue
        SIGNATURE_OUTDATED.labels(name).set(1 if info.outdated else 0)
        try:
            SIGNATURE_VERSION.labels(name).set(float(info.actual))
        except (TypeError, ValueError):
            pass
