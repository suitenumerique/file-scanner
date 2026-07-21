"""Optional async-job result store (poll a scan by ``job_id``).

The primary delivery channel for an async scan is the webhook; this adds a small,
TTL-bounded record so a caller can also **poll** a job by id
(``GET /api/v1.0/jobs/{job_id}``). It is opt-in: with ``WORKER_RESULT_TTL == 0``
the store is absent and the service stays fully stateless (webhook-only).

Storage is **dramatiq's own result backend** (``broker.result_backend`` — a
``RedisBackend`` in the same Redis as the streams broker, a ``StubBackend`` in
eager mode). dramatiq keys results by *message*, so we mint a minimal keying
``Message`` from the ``job_id`` and store/read the record under it. We drive the
backend directly rather than via ``store_results=True`` auto-capture because the
record is **owner-scoped** (the caller ``iss``) and **pending-aware** (seeded at
accept time) — neither of which plain return-value capture models — and because
the store must run inside the task body (the worker's auto-capture never fires
when tests invoke ``scan_task.fn`` directly).

The worker writes the terminal record where it enqueues the webhook; the web
endpoint seeds a ``pending`` record on accept. A poll only returns a job the same
caller submitted, else ``404``. A storage failure is swallowed — the store is a
convenience channel and must never fail a scan.
"""

import logging

import dramatiq
from dramatiq.results import ResultMissing

from broker import result_backend
from config import get_settings

logger = logging.getLogger("file-scanner")
settings = get_settings()

# Statuses a stored record carries. PENDING is interim (store-only); the terminal
# DONE / ERROR also travel in the webhook payload.
PENDING, DONE, ERROR = "pending", "done", "error"

# Records are keyed under one synthetic actor/queue so a job_id maps to a single
# backend key. The values are arbitrary — only internal consistency between
# record() and fetch() matters (both build the key from the same job_id).
_ACTOR = "scan_task"
_QUEUE = "default"


def _key_message(job_id: str) -> dramatiq.Message:
    """A minimal ``Message`` whose (namespace, queue, actor, message_id) fix the
    backend key for ``job_id`` — dramatiq keys results by the message."""
    return dramatiq.Message(
        queue_name=_QUEUE,
        actor_name=_ACTOR,
        args=(),
        kwargs={},
        options={},
        message_id=job_id,
    )


def enabled() -> bool:
    """True when the result store is configured (``WORKER_RESULT_TTL > 0``)."""
    return settings.worker_result_ttl > 0


def record(job_id, owner, payload) -> None:
    """Persist ``payload`` for ``job_id`` under ``owner`` with the configured TTL.

    No-op when the store is disabled. A storage failure is logged and swallowed:
    the webhook (when set) remains the source of truth, so a Redis blip must not
    fail the scan."""
    if not enabled():
        return
    try:
        result_backend.store_result(
            _key_message(job_id),
            {"owner": owner, "record": payload},
            settings.worker_result_ttl * 1000,  # dramatiq TTLs are milliseconds
        )
    except Exception as exc:
        logger.warning(f"Could not store result for job {job_id}: {exc}")


def fetch(job_id, owner):
    """Return the stored record for ``job_id`` **iff** it belongs to ``owner``,
    else ``None`` (unknown, expired, disabled, or another caller's job)."""
    if not enabled():
        return None
    try:
        wrapper = result_backend.get_result(_key_message(job_id))
    except ResultMissing:
        return None
    except Exception as exc:
        logger.warning(f"Could not read result for job {job_id}: {exc}")
        return None
    if not isinstance(wrapper, dict) or wrapper.get("owner") != owner:
        return None
    return wrapper.get("record")


def _reset_for_tests() -> None:
    """Wipe the in-memory StubBackend between tests (its store is class-level)."""
    getattr(result_backend, "results", {}).clear()
