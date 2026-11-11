"""Prometheus metrics. The full catalogue lives in ``docs/metrics.md``.

Two processes expose metrics, each scraped as its own target:

- the **web process** (``GET /metrics``, one uvicorn process): HTTP traffic,
  sync scans, and the queue-state gauges (read from Redis at scrape time, in
  one place so N workers don't each report the same backlog);
- the **worker** (``worker_metrics.py``, its own port): async scans, downloads,
  webhook deliveries, plus dramatiq's own per-message metrics. A worker forks
  several processes, so it runs prometheus_client in multiprocess mode
  (``PROMETHEUS_MULTIPROC_DIR``, set by ``worker.py`` before anything imports
  ``prometheus_client``) and one exposition server aggregates them.

The metric objects below are shared by both; each process only feeds the ones
that concern it, and a labelled metric that was never fed emits no sample.
"""

import logging
import threading
import time

from prometheus_client import Counter, Histogram
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector

logger = logging.getLogger("file-scanner")

SYNC = "sync"
ASYNC = "async"

# Histogram bucket upper bounds (seconds, or bytes for the file size).
#
# Scans run from milliseconds (a small file on clamd) to many minutes (a 2 GiB
# archive, or jcop's 600 s submit budget; clamd's MaxScanTime is 900 s).
_SCAN_DURATION_BUCKETS = (
    0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 900,
)  # fmt: skip
# Downloads are bounded by DOWNLOAD_MAX_SECONDS (300 s by default).
_DOWNLOAD_DURATION_BUCKETS = (0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600)
_WEBHOOK_DURATION_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)
_HTTP_DURATION_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300,
)  # fmt: skip
# 1 KiB .. 4 GiB, x4 per bucket.
_FILE_SIZE_BUCKETS = tuple(1024 * 4**i for i in range(12))

# --- Scans (both processes) ---------------------------------------------------

SCANS = Counter(
    "filescanner_scans_total",
    "Scanner runs, by scanner, category, verdict "
    "(clean/malware/flagged/partial/error), mode (sync/async) and API client "
    "(the JWT `iss` of the caller). An async job retried after a transient "
    "failure counts once per attempt.",
    ["scanner", "category", "verdict", "mode", "api_client"],
)

SCAN_DURATION = Histogram(
    "filescanner_scan_duration_seconds",
    "Duration of one scanner run, by scanner, verdict and mode.",
    ["scanner", "verdict", "mode"],
    buckets=_SCAN_DURATION_BUCKETS,
)

REPORTS = Counter(
    "filescanner_reports_total",
    "Per-category verdicts returned to callers (one per category per delivered "
    "result, after combining that category's scanners), by mode and API client.",
    ["category", "verdict", "mode", "api_client"],
)

FILE_SIZE = Histogram(
    "filescanner_file_size_bytes",
    "Size of the files scanned (plaintext, after any decryption), by mode.",
    ["mode"],
    buckets=_FILE_SIZE_BUCKETS,
)

# --- Async pipeline (worker) --------------------------------------------------

ASYNC_JOBS = Counter(
    "filescanner_async_jobs_total",
    "Async jobs that reached a terminal result, by status (done/error), "
    "error kind (file/transient, empty when done) and API client.",
    ["status", "error_kind", "api_client"],
)

DOWNLOADS = Counter(
    "filescanner_downloads_total",
    "Async source downloads, by outcome: ok, too_large, timeout, "
    "decrypt_failed, blocked (allowlist / SSRF guard), http_error, error.",
    ["outcome"],
)

DOWNLOAD_DURATION = Histogram(
    "filescanner_download_duration_seconds",
    "Duration of successful async source downloads (decryption included).",
    buckets=_DOWNLOAD_DURATION_BUCKETS,
)

WEBHOOKS = Counter(
    "filescanner_webhook_deliveries_total",
    "Webhook delivery attempts, by outcome: ok; retry (failed, will be "
    "retried); gave_up (failed on the last attempt, dead-lettered); blocked "
    "(host rejected by the SSRF guard, dropped).",
    ["outcome"],
)

WEBHOOK_DURATION = Histogram(
    "filescanner_webhook_duration_seconds",
    "Duration of one webhook POST, whatever its outcome.",
    buckets=_WEBHOOK_DURATION_BUCKETS,
)

# --- HTTP API (web) -----------------------------------------------------------

HTTP_REQUESTS = Counter(
    "filescanner_http_requests_total",
    "HTTP requests served by the API, by route template, method and status. "
    "Requests matching no API route (404s, the dashboard) count as route=other.",
    ["route", "method", "status"],
)

HTTP_DURATION = Histogram(
    "filescanner_http_request_duration_seconds",
    "HTTP request duration, by route template and method.",
    ["route", "method"],
    buckets=_HTTP_DURATION_BUCKETS,
)

# --- Recording helpers --------------------------------------------------------


def record_scan(result, mode: str, api_client: str = "") -> None:
    """Record one ``scanner.ScannerResult``."""
    SCANS.labels(result.scanner, result.category, result.kind, mode, api_client).inc()
    SCAN_DURATION.labels(result.scanner, result.kind, mode).observe(result.time)


def record_report(report, mode: str, api_client: str = "") -> None:
    """Record the per-category verdicts of a ``scanner.ScanReport`` delivered
    to a caller."""
    for category, verdict in report.verdicts().items():
        REPORTS.labels(category, verdict.kind, mode, api_client).inc()


# --- HTTP middleware ----------------------------------------------------------

_HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


class HTTPMetricsMiddleware:
    """Pure ASGI middleware feeding the ``filescanner_http_*`` metrics.

    The route label is the matched route's **template** (FastAPI stores the
    route in the scope), never the raw path, and unknown methods collapse to
    ``other`` — so a client can't blow up the label cardinality.
    """

    def __init__(self, app):
        """Wrap the ASGI ``app``."""
        self.app = app

    async def __call__(self, scope, receive, send):
        """Time the request and record its route, method and status."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status = 500  # unless the app gets a response out

        async def _send(message):
            """Capture the response status on its way out."""
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            route = getattr(scope.get("route"), "path", None) or "other"
            method = scope.get("method", "")
            method = method if method in _HTTP_METHODS else "other"
            HTTP_REQUESTS.labels(route, method, str(status)).inc()
            HTTP_DURATION.labels(route, method).observe(time.perf_counter() - start)


# --- Scrape-time collectors (web) ---------------------------------------------


class _CachedCollector(Collector):
    """A collector that reads an external system at scrape time, at most once
    every ``ttl`` seconds (so several scrapers don't multiply the load) and one
    read at a time. Subclasses build the metric families in ``_snapshot``."""

    def __init__(self, ttl: float):
        """Cache each snapshot for ``ttl`` seconds."""
        self._ttl = ttl
        self._lock = threading.Lock()
        self._cached: list = []
        self._cached_at = float("-inf")

    def describe(self):
        """Nothing: don't read anything when the collector is registered."""
        return []

    def collect(self):
        """The cached metric families, refreshed when older than ``ttl``. A
        failed refresh keeps the previous ones until the next ``ttl``."""
        with self._lock:
            now = time.monotonic()
            if now - self._cached_at >= self._ttl:
                try:
                    self._cached = self._snapshot()
                except Exception:
                    logger.warning(
                        "%s snapshot failed", type(self).__name__, exc_info=True
                    )
                self._cached_at = now
            return list(self._cached)

    def close(self) -> None:
        """Release what the collector holds (called when it is unregistered)."""

    def _snapshot(self) -> list:
        """Read the external system and build the metric families."""
        raise NotImplementedError


# --- Queue state (web) --------------------------------------------------------


def _text(value) -> str:
    """A Redis reply value as ``str`` (decoding bytes)."""
    return value.decode() if isinstance(value, bytes) else str(value)


class QueueStatsCollector(_CachedCollector):
    """Queue gauges read from the dramatiq-redis-streams keys at scrape time.

    One pipelined round-trip per scrape (cached ``ttl`` seconds so several
    scrapers don't multiply the load). The per-container healthcheck queues
    (``ping.<hostname>``) are left out. The key layout is the broker's own
    (``dramatiq_redis_streams.keys``): a message stays in its stream until
    acked (ack deletes it), its consumer group tracks delivery, dead letters go
    to a per-queue DLQ stream, delayed messages — retry back-offs included —
    to one sorted set for every queue.
    """

    def __init__(self, client, namespace: str, queues=(), ttl: float = 5.0):
        """Read the queues of ``namespace`` through ``client``; ``queues`` are
        listed even before anything was enqueued on them."""
        super().__init__(ttl)
        self._client = client
        self._namespace = namespace
        self._queues = set(queues)

    def close(self) -> None:
        """Close the Redis client."""
        self._client.close()

    def _queue_names(self) -> list[str]:
        """Known queues, minus the healthcheck and delay queues."""
        from dramatiq_redis_streams.keys import queues_key

        names = set(self._queues)
        for member in self._client.smembers(queues_key(self._namespace)):
            names.add(_text(member))
        return sorted(
            n for n in names if not n.startswith("ping.") and not n.endswith(".DQ")
        )

    def _snapshot(self) -> list:
        """One pipelined read of every queue's state."""
        from dramatiq_redis_streams.keys import (
            GROUP_NAME,
            delayed_key,
            dlq_stream_key,
            stream_key,
        )

        success = GaugeMetricFamily(
            "filescanner_queue_stats_success",
            "1 if the last read of the queue state from Redis succeeded; the "
            "other filescanner_queue_* metrics are absent when it is 0.",
        )
        try:
            queues = self._queue_names()
            pipe = self._client.pipeline(transaction=False)
            for q in queues:
                pipe.xinfo_groups(stream_key(q, self._namespace))
                pipe.xlen(dlq_stream_key(q, self._namespace))
                pipe.xrange(stream_key(q, self._namespace), count=1)
            pipe.zcard(delayed_key(self._namespace))
            res = pipe.execute(raise_on_error=False)
        except Exception:
            logger.warning("queue stats unavailable", exc_info=True)
            success.add_metric([], 0)
            return [success]

        backlog = GaugeMetricFamily(
            "filescanner_queue_backlog",
            "Messages enqueued but not yet delivered to any worker.",
            labels=["queue"],
        )
        in_flight = GaugeMetricFamily(
            "filescanner_queue_in_flight",
            "Messages delivered to a worker and not yet acknowledged.",
            labels=["queue"],
        )
        consumers = GaugeMetricFamily(
            "filescanner_queue_consumers",
            "Worker consumers registered on the queue (stale ones are reaped "
            "by the broker).",
            labels=["queue"],
        )
        oldest = GaugeMetricFamily(
            "filescanner_queue_oldest_message_age_seconds",
            "Age of the oldest unacknowledged message (waiting or in flight); "
            "0 when the queue is empty.",
            labels=["queue"],
        )
        dead = GaugeMetricFamily(
            "filescanner_queue_dead_letters",
            "Messages in the queue's dead-letter stream.",
            labels=["queue"],
        )
        delayed = GaugeMetricFamily(
            "filescanner_queue_delayed",
            "Delayed messages, retry back-offs included, across all queues.",
        )

        now_ms = time.time() * 1000
        for i, q in enumerate(queues):
            groups, dlq_len, first = res[3 * i : 3 * i + 3]
            group = None
            if isinstance(groups, list):
                group = next(
                    (g for g in groups if _text(g.get("name")) == GROUP_NAME), None
                )
            if group is not None:
                in_flight.add_metric([q], group.get("pending") or 0)
                consumers.add_metric([q], group.get("consumers") or 0)
                # Redis can't tell the lag right after entries are deleted out
                # of order (e.g. a flush); leave it out rather than guess.
                if group.get("lag") is not None:
                    backlog.add_metric([q], group["lag"])
            if isinstance(dlq_len, int):
                dead.add_metric([q], dlq_len)
            if isinstance(first, list):
                age = 0.0
                if first:
                    entry_ms = int(_text(first[0][0]).split("-", 1)[0])
                    age = max(0.0, (now_ms - entry_ms) / 1000)
                oldest.add_metric([q], age)
        if isinstance(res[-1], int):
            delayed.add_metric([], res[-1])

        success.add_metric([], 1)
        return [success, backlog, in_flight, consumers, oldest, dead, delayed]


# --- ClamAV signature database (web) -------------------------------------------


class ClamavDatabaseCollector(_CachedCollector):
    """The signature database each clamd daemon has loaded, read at scrape time
    with clamd's ``VERSION`` command (answered from memory: no file or network
    access on the daemon side).

    freshclam keeps the database current on its own but fails silently — clamd
    then keeps scanning with stale signatures. ``daily`` is published several
    times a day, so ``time() - filescanner_clamav_db_timestamp_seconds`` above a
    day or two means updates are broken (or clamd stopped reloading).

    ``fetch`` returns ``{daemon: DatabaseInfo | None}`` for every daemon of the
    pool, None for one that didn't answer (``ClamavScanner.database_info``).
    """

    def __init__(self, fetch, ttl: float = 60.0):
        """Poll ``fetch`` at most every ``ttl`` seconds."""
        super().__init__(ttl)
        self._fetch = fetch

    def _snapshot(self) -> list:
        """Ask every daemon for its database version and build time."""
        up = GaugeMetricFamily(
            "filescanner_clamav_up",
            "1 if the clamd daemon answered VERSION at the last check.",
            labels=["daemon"],
        )
        version = GaugeMetricFamily(
            "filescanner_clamav_db_version",
            "Version of the daily signature database the daemon has loaded.",
            labels=["daemon"],
        )
        built = GaugeMetricFamily(
            "filescanner_clamav_db_timestamp_seconds",
            "Build time (Unix) of the signature database the daemon has loaded.",
            labels=["daemon"],
        )
        try:
            daemons = self._fetch()
        except Exception:
            logger.warning("clamav database check failed", exc_info=True)
            daemons = {}
        for daemon, info in sorted(daemons.items()):
            up.add_metric([daemon], 0 if info is None else 1)
            if info is None:
                continue
            if info.version is not None:
                version.add_metric([daemon], info.version)
            if info.built is not None:
                built.add_metric([daemon], info.built)
        return [up, version, built]
