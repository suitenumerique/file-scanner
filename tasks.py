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

        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > settings.max_url_size:
            response.close()
            result.update(
                status="error",
                error=f"file_too_large: {content_length} bytes exceeds "
                f"{settings.max_url_size} limit",
            )
            if webhook_url:
                _send_webhook(webhook_url, result)
            return

        with open(file_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        start_time = timeit.default_timer()
        scan = _cd.scan(file_path)
        elapsed = timeit.default_timer() - start_time

        scan_result = scan.get(file_path)
        status, reason = ("OK", None) if scan_result is None else scan_result

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

    except http_requests.RequestException as exc:
        result.update(status="error", error=f"download_failed: {exc}")
        logger.error(f"Job {job_id} download failed: {exc}")
        if webhook_url:
            _send_webhook(webhook_url, result)

    except clamd.ConnectionError as exc:
        logger.error(f"Job {job_id} scan failed: {exc}")
        # Transient — only notify once retries are exhausted, so the caller
        # isn't told "error" for a scan a retry may still complete.
        if self.request.retries >= self.max_retries:
            result.update(status="error", error=f"scan_failed: {exc}")
            if webhook_url:
                _send_webhook(webhook_url, result)
        raise self.retry(exc=exc)

    except Exception as exc:
        logger.error(f"Job {job_id} unexpected error: {exc}")
        if self.request.retries >= self.max_retries:
            result.update(status="error", error=str(exc))
            if webhook_url:
                _send_webhook(webhook_url, result)
        raise self.retry(exc=exc)

    finally:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
