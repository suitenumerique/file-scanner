"""The worker's metrics endpoint.

A worker is several forked processes (``WORKER_PROCESSES``), so it runs
prometheus_client in **multiprocess mode**: ``worker.py`` points
``PROMETHEUS_MULTIPROC_DIR`` at a fresh directory before any process imports
``prometheus_client``, every process writes its samples there, and one extra
process — :func:`serve`, started by dramatiq as a middleware *fork* — serves
their aggregate at ``http://WORKER_METRICS_HOST:WORKER_METRICS_PORT/metrics``.

The metrics are ours (``metrics.py``: async scans, downloads, webhooks) plus
dramatiq's own per-message ones (``dramatiq_messages_total``,
``dramatiq_message_duration_milliseconds``, ...) from its ``Prometheus``
middleware, which writes to the same directory. Its stock exposition server is
replaced by :func:`serve` so the endpoint honours ``PROMETHEUS_API_KEY`` like
the web one.

``setup`` is what ``worker.py`` hands the dramatiq CLI as the broker: it returns
the shared broker with the middleware added. The middleware is worker-only —
the web process enqueues on the same broker and must not carry it.
"""

import hmac
import logging
import os
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from config import get_settings

settings = get_settings()
logger = logging.getLogger("file-scanner")


def metrics_dir() -> str:
    """The directory the worker processes share their samples through."""
    return settings.worker_metrics_dir or os.path.join(
        tempfile.gettempdir(), "file-scanner-metrics"
    )


def enabled() -> bool:
    """Whether the worker exposes metrics (``WORKER_METRICS_PORT`` > 0)."""
    return settings.worker_metrics_port > 0


def setup():
    """dramatiq CLI broker hook (``worker_metrics:setup``): add the Prometheus
    middleware (when enabled) to the shared broker."""
    from broker import broker

    if enabled():
        # Imported here: the module reads its env (dramatiq_prom_db, set by
        # worker.py) at import time.
        from dramatiq.middleware.prometheus import Prometheus

        class _Prometheus(Prometheus):
            """dramatiq's middleware, with :func:`serve` as its exposition fork."""

            @property
            def forks(self):
                """Fork :func:`serve` instead of the stock HTTP server."""
                return [serve]

        broker.add_middleware(_Prometheus())


def _authorized(header: str | None) -> bool:
    """Check the ``Authorization`` header against ``PROMETHEUS_API_KEY``
    (open when the key is unset)."""
    key = settings.prometheus_api_key
    if not key:
        return True
    return hmac.compare_digest((header or "").encode(), f"Bearer {key}".encode())


class _Handler(BaseHTTPRequestHandler):
    """Serves the aggregated multiprocess samples at ``/metrics``."""

    def do_GET(self):
        """Answer a scrape: 404 off ``/metrics``, 401 without the key."""
        if self.path.split("?", 1)[0] != "/metrics":
            self.send_error(404)
            return
        if not _authorized(self.headers.get("Authorization")):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            return
        # Imported per request, once PROMETHEUS_MULTIPROC_DIR is in place.
        from prometheus_client import (
            CONTENT_TYPE_LATEST,
            CollectorRegistry,
            generate_latest,
            multiprocess,
        )

        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        body = generate_latest(registry)
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE_LATEST)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        """Silence the per-request access log."""
        pass  # a scrape every few seconds is noise


def serve():
    """Run the exposition server (a dramatiq fork process; blocks)."""
    if not settings.prometheus_api_key:
        logger.warning(
            "PROMETHEUS_API_KEY is not set — the worker metrics endpoint is "
            "unauthenticated and its api_client label exposes caller identities. "
            "Set it, or isolate the endpoint at the network layer."
        )
    address = (settings.worker_metrics_host, settings.worker_metrics_port)
    ThreadingHTTPServer(address, _Handler).serve_forever()
