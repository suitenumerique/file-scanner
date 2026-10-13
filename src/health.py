"""End-to-end worker healthcheck: the dramatiq counterpart of ``celery inspect ping``.

Imported by the worker (``worker.py``), it declares a ``ping`` actor on a queue
of its own container (``ping.<hostname>``), so the ping is answered by this
worker and not another one. Run as a script (``python -m health``, the Docker
healthcheck and the k8s liveness probe), it sends a ping and waits for the
answer: exit 0 when it comes back, 1 otherwise. That covers the broker, the
consumer, a worker thread and the result backend.
"""

import socket
import sys

import dramatiq
from dramatiq.middleware import Middleware

from broker import broker

PING_QUEUE = f"ping.{socket.gethostname()}"


@dramatiq.actor(
    queue_name=PING_QUEUE,
    # Ahead of webhooks (5) and scans (10) when a worker thread frees.
    priority=0,
    store_results=True,
    max_retries=0,
    max_age=10_000,  # ms: the prober has given up by then
    result_ttl=30_000,  # ms
)
def ping():
    return "pong"


class _DropPingQueue(Middleware):
    """Delete this container's ping stream when its worker stops, so a new
    stream per container does not pile up in Redis and on the dashboard. A
    crashed container leaves its stream behind; the dashboard removes it."""

    def after_worker_shutdown(self, broker, worker):
        from dramatiq_redis_streams.keys import queues_key, stream_key

        try:
            broker.client.srem(queues_key(broker.namespace), PING_QUEUE)
            broker.client.delete(stream_key(PING_QUEUE, broker.namespace))
        except Exception:  # noqa: S110 — best effort, the worker is exiting
            pass


# The stub broker (eager mode) has no Redis client and no stream to drop.
if hasattr(broker, "client"):
    broker.add_middleware(_DropPingQueue())


if __name__ == "__main__":
    try:
        result = ping.send().get_result(block=True, timeout=5_000)
    except Exception:  # any failure means unhealthy
        sys.exit(1)
    # A ping skipped as too old stores None.
    sys.exit(0 if result == "pong" else 1)
