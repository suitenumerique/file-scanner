import logging
import os
import time
import timeit
import uuid

import clamd
import requests as http_requests
from celery import Celery

from config import get_settings

logger = logging.getLogger("CLAMAV-REST")

settings = get_settings()
celery_app = Celery("clamav_tasks", broker=settings.celery_broker_url)

os.makedirs(settings.scan_dir, exist_ok=True)

if settings.clamd_socket:
    _cd = clamd.ClamdUnixSocket(path=settings.clamd_socket)
else:
    _cd = clamd.ClamdNetworkSocket(host=settings.clamd_host, port=settings.clamd_port)


def _send_webhook(webhook_url, payload):
    """Best-effort push of the scan result to the caller.

    The service is stateless: nothing is persisted, so the webhook is the ONLY
    delivery channel for an async scan. A few retries with back-off; if it
    never lands, the result is lost and the caller's own reaper is expected to
    re-submit.
    """
    for attempt in range(1, settings.webhook_max_attempts + 1):
        try:
            resp = http_requests.post(
                webhook_url, json=payload, timeout=settings.webhook_timeout
            )
            resp.raise_for_status()
            logger.info(
                f"Webhook delivered for job {payload.get('job_id')} (attempt {attempt})"
            )
            return True
        except http_requests.RequestException as exc:
            logger.warning(
                f"Webhook attempt {attempt}/{settings.webhook_max_attempts} failed "
                f"for job {payload.get('job_id')}: {exc}"
            )
            if attempt < settings.webhook_max_attempts:
                time.sleep(2 * attempt)
    logger.error(
        f"Giving up on webhook for job {payload.get('job_id')} after "
        f"{settings.webhook_max_attempts} attempts"
    )
    return False


class ScanError(Exception):
    """A scan that failed, tagged with whether a retry could help.

    ``kind="transient"`` — infrastructure (clamd unreachable, download glitch,
    path not visible): a retry may succeed. ``kind="file"`` — the file itself
    can't be scanned (clamd opened it but rejected its content, oversized): a
    retry won't help, the caller should ask the user to remove it.
    """

    def __init__(self, message, kind):
        super().__init__(message)
        self.kind = kind


# clamd returns an ERROR verdict for both file problems (encrypted, malformed,
# oversized) and the occasional infra hiccup. Default such verdicts to "file"
# and only downgrade to "transient" on these unambiguous resource signals.
_TRANSIENT_CLAMD_HINTS = (
    "allocate",
    "time limit",
    "timeout",
    "no space",
)


def _clamd_error_kind(reason):
    text = (reason or "").lower()
    return "transient" if any(h in text for h in _TRANSIENT_CLAMD_HINTS) else "file"


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def scan_task(self, job_id, url, filename=None, webhook_url=None, metadata=None):
    """Download a file from ``url``, scan it, and push the result to ``webhook_url``.

    Fully stateless: everything the task needs travels in the message, and the
    only output is the webhook POST. The payload mirrors the old
    ``GET /v2/jobs/{id}`` body so existing webhook receivers are unaffected.
    """
    file_path = None
    result = {"job_id": job_id, "filename": filename, "metadata": metadata}
    try:
        file_path = os.path.join(settings.scan_dir, str(uuid.uuid4()))
        response = http_requests.get(
            url, stream=True, timeout=settings.url_download_timeout
        )
        response.raise_for_status()

        # Size guard, defence in depth: trust the Content-Length header for a
        # cheap up-front reject, then also cap the bytes actually written — a
        # missing, malformed or understated header must not let an unbounded
        # body fill the scan volume.
        declared = response.headers.get("Content-Length")
        try:
            declared = int(declared) if declared else None
        except ValueError:
            declared = None
        if declared and declared > settings.max_url_size:
            response.close()
            result.update(
                status="error",
                error_kind="file",
                error=f"file_too_large: {declared} bytes exceeds "
                f"{settings.max_url_size} limit",
            )
            if webhook_url:
                _send_webhook(webhook_url, result)
            return

        written = 0
        with open(file_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                written += len(chunk)
                if written > settings.max_url_size:
                    raise ScanError(
                        f"file_too_large: streamed over {settings.max_url_size} "
                        "bytes (Content-Length missing or understated)",
                        kind="file",
                    )
                f.write(chunk)

        start_time = timeit.default_timer()
        scan = _cd.scan(file_path)
        elapsed = timeit.default_timer() - start_time

        scan_result = scan.get(file_path)
        # Fail closed: a missing entry (path not visible to clamd, access
        # failure) or an ERROR verdict means the file was NOT scanned — never
        # report that as clean.
        if scan_result is None:
            # No entry for our path: clamd couldn't see / access the file
            # (mount or config issue) — infrastructure, so retryable.
            raise ScanError(
                f"clamd returned no verdict for {file_path}: {scan!r}",
                kind="transient",
            )
        status, reason = scan_result
        if status == "ERROR":
            raise ScanError(
                f"clamd scan error for {file_path}: {reason}",
                kind=_clamd_error_kind(reason),
            )

        result.update(
            status="done",
            malware=status != "OK",
            reason=reason if status != "OK" else None,
            time=elapsed,
        )
        logger.info(
            f"Async scan job {job_id} complete. Malware: {result['malware']}, "
            f"Time: {elapsed:.3f}s"
        )
        if webhook_url:
            _send_webhook(webhook_url, result)

    except ScanError as exc:
        logger.error(f"Job {job_id} scan error ({exc.kind}): {exc}")
        # A file-bound failure won't pass on retry — report it at once. A
        # transient one gets the normal retry budget before we give up.
        if exc.kind == "file":
            result.update(status="error", error_kind="file", error=str(exc))
            if webhook_url:
                _send_webhook(webhook_url, result)
            return
        if self.request.retries >= self.max_retries:
            result.update(status="error", error_kind="transient", error=str(exc))
            if webhook_url:
                _send_webhook(webhook_url, result)
            return
        raise self.retry(exc=exc)

    except http_requests.RequestException as exc:
        # Download failures report at once rather than retrying: the URL is
        # frozen in the task args, so a stale/expired presigned URL wouldn't
        # recover on retry — the caller re-submits with a fresh URL. Marked
        # transient precisely so that caller (reaper / user retry) does so.
        logger.error(f"Job {job_id} download failed: {exc}")
        result.update(
            status="error", error_kind="transient", error=f"download_failed: {exc}"
        )
        if webhook_url:
            _send_webhook(webhook_url, result)

    except clamd.ConnectionError as exc:
        logger.error(f"Job {job_id} scan failed: {exc}")
        # Transient — only notify once retries are exhausted, so the caller
        # isn't told "error" for a scan a retry may still complete.
        if self.request.retries >= self.max_retries:
            result.update(
                status="error", error_kind="transient", error=f"scan_failed: {exc}"
            )
            if webhook_url:
                _send_webhook(webhook_url, result)
            return
        raise self.retry(exc=exc)

    except Exception as exc:
        logger.error(f"Job {job_id} unexpected error: {exc}")
        if self.request.retries >= self.max_retries:
            result.update(status="error", error_kind="transient", error=str(exc))
            if webhook_url:
                _send_webhook(webhook_url, result)
            return
        raise self.retry(exc=exc)

    finally:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
