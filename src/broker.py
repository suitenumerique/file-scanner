"""Background-task broker setup and the ``@register_task`` decorator.

Adapted from the non-Django dramatiq setup in suitenumerique/st-home. Task
modules decorate their functions with ``@register_task`` (imported from here),
which keeps them free of any direct dependency on the queue implementation —
swapping the broker touches only this module.

Declaring a task is Redis-free (the broker connects only when the worker starts
consuming), so importing task modules — for the tests or the CLI — needs no
Redis. In eager mode (tests / minimal dev) an in-process stub broker runs tasks
synchronously on enqueue, so no Redis and no worker are needed at all.
"""

import logging

import dramatiq
from dramatiq.brokers.stub import StubBroker
from dramatiq.middleware import CurrentMessage

from config import get_settings

logger = logging.getLogger("file-scanner")
settings = get_settings()


def _make_broker():
    if settings.worker_eager:
        # In-memory stub: ``.send()`` enqueues without Redis and without running
        # the task (there is no worker loop). Tests exercise the task body by
        # calling ``scan_task.fn(...)`` directly, and endpoints get a real 202
        # without a scan running inline. No Redis required.
        return StubBroker()
    # Lazy import so the eager/test path never needs the streams package.
    from dramatiq_redis_streams import StreamsBroker

    return StreamsBroker(
        url=settings.worker_broker_url,
        namespace=settings.worker_queue_namespace,
    )


# Built once, at import. Task modules import this module (directly or via
# ``register_task``) before declaring actors, so every actor binds to this
# broker; ``worker.py`` hands the dramatiq CLI ``broker`` as the broker module.
broker = _make_broker()
# CurrentMessage lets a running task read its own retry count (see tasks.py).
broker.add_middleware(CurrentMessage())
dramatiq.set_broker(broker)


def register_task(fn=None, *, queue="default", **options):
    """Register a function as a background task actor.

    Thin wrapper over :func:`dramatiq.actor`. ``queue`` maps to ``queue_name``;
    any other actor option (``max_retries``, ``min_backoff``, ``time_limit``, …)
    is forwarded. Enqueue with ``task.send(args)``.
    """

    def decorator(func):
        return dramatiq.actor(func, queue_name=queue, **options)

    return decorator(fn) if fn is not None else decorator
