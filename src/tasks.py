import contextlib
import json
import logging
import os
import timeit
import uuid

import requests as http_requests
from dramatiq.middleware import CurrentMessage

import encryption
import jwt_auth
from broker import register_task
from config import get_settings
from scanner import ScannerError, run_scanners
from ssrf import SSRFSafeSession, SSRFValidationError
from validation import assert_scannable

logger = logging.getLogger("file-scanner")

settings = get_settings()

os.makedirs(settings.download_dir, exist_ok=True)

# One SSRF-protected HTTP client for both the download and the webhook: it pins
# the resolved IP (no DNS-rebinding window) and re-validates every redirect hop.
_session = SSRFSafeSession()

# Retry budget for transient failures (matches the actor's max_retries below).
MAX_RETRIES = 2


def _retries_exhausted() -> bool:
    """True when we should stop retrying and report the failure now.

    Reads the running task's retry count via dramatiq's CurrentMessage. Outside
    a worker — synchronous eager execution in tests / minimal dev — there is no
    retry loop, so we always report immediately (the webhook still fires once).
    """
    msg = CurrentMessage.get_current_message()
    if msg is None:
        return True
    return msg.options.get("retries", 0) >= MAX_RETRIES


@register_task(
    max_retries=settings.webhook_max_attempts,
    min_backoff=1_000,
    max_backoff=60_000,
)
def deliver_webhook(webhook_url, payload):
    """Push one scan result to the caller's webhook — its own retriable task.

    The service is stateless, so the webhook is the ONLY delivery channel for an
    async scan; it must be as durable as the scan itself. Rather than a blocking
    in-line retry loop inside ``scan_task`` (which would re-download and re-scan
    on the heavy scanner tier just because a receiver blipped, and would dead-
    letter the scan args — including the decryption key — on failure), delivery
    is a *separate* actor: ``scan_task`` computes the report once and enqueues
    this. One HTTP attempt per invocation; a transient failure re-raises so
    dramatiq retries with back-off and, once the budget is spent, dead-letters
    the message. The dead-lettered payload is the report only — it carries no
    decryption key — so it is safe to inspect/replay from the queue dashboard.

    A blocked/unsafe webhook host is *permanent* (it won't become safe on
    retry), so it is logged and dropped rather than retried.
    """
    job = payload.get("job_id")
    # Serialise ourselves so the signature binds the EXACT bytes we POST. When a
    # signing key is configured, a short-lived EdDSA token authenticates the
    # callback and its `bh` claim pins this body; receivers verify it against our
    # JWKS. Unset ⇒ sent unsigned (no header).
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    token = jwt_auth.sign_webhook(webhook_url, body)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        # Do NOT follow redirects: the signed token binds this exact webhook_url,
        # and a callback endpoint has no business redirecting. A 3xx is a failed
        # delivery (the receiver must accept with a 2xx), surfaced for retry.
        resp = _session.post(
            webhook_url,
            timeout=settings.webhook_timeout,
            data=body,
            headers=headers,
            allow_redirects=False,
        )
        if resp.is_redirect:
            raise http_requests.HTTPError(
                f"webhook returned redirect {resp.status_code} to "
                f"{resp.headers.get('Location')!r}; not followed"
            )
        resp.raise_for_status()
    except SSRFValidationError as exc:
        logger.error(f"Webhook host rejected for job {job}: {exc}")
        return
    except http_requests.RequestException as exc:
        # Re-raise so dramatiq retries (back-off) and dead-letters if it never
        # lands; the caller's own reaper remains the last-resort safety net.
        logger.warning(f"Webhook delivery failed for job {job}: {exc}")
        raise
    logger.info(f"Webhook delivered for job {job}")


class FileError(Exception):
    """A download-side problem with the file itself (oversized, timed out) —
    permanent, so it is reported at once rather than retried."""


def _report_error(result, webhook_url, kind, message):
    """Populate ``result`` with a pre-scan error and enqueue its delivery."""
    result.update(status="error", error_kind=kind, error=message)
    if webhook_url:
        deliver_webhook.send(webhook_url, result)


def _deliver(result, webhook_url, report, *, transient_error=False):
    """Enqueue delivery of the per-scanner report to the webhook."""
    result.update(report.as_dict())  # malware + scanners breakdown
    if transient_error:
        result.update(
            status="error", error_kind="transient", error="all scanners failed"
        )
    if webhook_url:
        deliver_webhook.send(webhook_url, result)


def _check_limits(read_bytes, download_start):
    """Enforce the size + total-time download budgets mid-stream (raises
    ``FileError``). The per-read socket timeout alone can't stop a server that
    dribbles one byte just inside each window (slow-drip DoS), and a missing or
    understated Content-Length must not let an unbounded body fill the volume."""
    if timeit.default_timer() - download_start > settings.download_max_seconds:
        raise FileError(
            f"download_timeout: exceeded {settings.download_max_seconds}s "
            "total transfer budget"
        )
    if read_bytes > settings.max_url_size:
        raise FileError(
            f"file_too_large: streamed over {settings.max_url_size} bytes "
            "(Content-Length missing or understated)"
        )


def _write_plaintext(response, file_path, download_start):
    """Stream the body straight to disk, bounded by the size + time budgets.

    ``closing(response)`` releases the pooled connection even when a limit trips
    mid-stream (the body isn't fully read).
    """
    read = 0
    with contextlib.closing(response), open(file_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            read += len(chunk)
            _check_limits(read, download_start)
            f.write(chunk)


def _write_decrypted(response, file_path, download_start, enc):
    """Stream the ciphertext, decrypt chunk by chunk, write plaintext.

    Buffers wire bytes until a whole crypto chunk is available; only the tail may
    be short. The cap counts ciphertext bytes, which bounds the plaintext too.
    """
    scheme = enc.get("scheme", encryption.SCHEME)
    if scheme not in encryption.SCHEMES:
        raise encryption.DecryptionError(f"unsupported encryption scheme {scheme!r}")
    try:
        key = encryption.decode_key(enc["key"])
        file_id = enc["file_id"]
        chunk_size = int(enc["chunk_size"])
        parts = int(enc["parts"])
    except (KeyError, TypeError, ValueError) as exc:
        raise encryption.DecryptionError(f"invalid encryption params: {exc}") from exc
    lo, hi = settings.encryption_min_chunk_size, settings.encryption_max_chunk_size
    if not lo <= chunk_size <= hi:
        raise encryption.DecryptionError(
            f"chunk_size {chunk_size} out of range ({lo}..{hi})"
        )
    if parts < 0:
        raise encryption.DecryptionError(f"invalid parts {parts}")
    blob_size = chunk_size + encryption.OVERHEAD_PER_CHUNK

    buffer = bytearray()
    part_number = 0
    read = 0
    with contextlib.closing(response), open(file_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            read += len(chunk)
            _check_limits(read, download_start)
            buffer.extend(chunk)
            while len(buffer) >= blob_size:
                part_number += 1
                f.write(
                    encryption.decrypt_chunk(
                        key, bytes(buffer[:blob_size]), file_id, part_number, parts
                    )
                )
                del buffer[:blob_size]
        # A shorter tail chunk just means the plaintext wasn't an exact multiple
        # of chunk_size; an empty buffer here means it was.
        if buffer:
            part_number += 1
            f.write(
                encryption.decrypt_chunk(
                    key, bytes(buffer), file_id, part_number, parts
                )
            )
    # Trailing-truncation guard: per-chunk auth can't see whole trailing chunks
    # dropped on a boundary, so the caller-declared total (bound into every
    # chunk's AAD) must match what we actually decrypted.
    if part_number != parts:
        raise encryption.DecryptionError(
            f"expected {parts} chunks, decrypted {part_number} (truncated?)"
        )


@register_task(max_retries=MAX_RETRIES, min_backoff=30_000, max_backoff=30_000)
def scan_task(
    job_id,
    url,
    scanners,
    filename=None,
    webhook_url=None,
    metadata=None,
    api_client="",
    encryption_params=None,
):
    """Download a file from ``url``, scan it with ``scanners``, and push the
    per-scanner report to ``webhook_url``.

    Fully stateless: everything the task needs travels in the message, and the
    only output is the webhook POST. The file is streamed to each scanner, so the
    worker needs no filesystem shared with the scanners.

    ``encryption_params`` (``{scheme, key, chunk_size, file_id, parts}``) marks
    the source as client-encrypted: decrypt before scanning, since a scanner would
    otherwise pronounce opaque ciphertext clean. Omit it and the body is scanned
    as-is.
    """
    file_path = None
    result = {"job_id": job_id, "filename": filename, "metadata": metadata}
    report = None
    try:
        # Defense in depth: re-enforce the allowlist + SSRF guard at the worker
        # (the request-layer check isn't the only way a job can reach us).
        assert_scannable(url, webhook_url)

        file_path = os.path.join(settings.download_dir, str(uuid.uuid4()))
        response = _session.get(url, timeout=settings.url_download_timeout, stream=True)
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
            raise FileError(
                f"file_too_large: {declared} bytes exceeds "
                f"{settings.max_url_size} limit"
            )

        # Stream to disk (both writers enforce the size + total-time budgets via
        # _check_limits). A client-encrypted source is decrypted to plaintext
        # first, or the scanner would pronounce opaque ciphertext clean.
        download_start = timeit.default_timer()
        if encryption_params:
            _write_decrypted(response, file_path, download_start, encryption_params)
        else:
            _write_plaintext(response, file_path, download_start)

        # Each scanner opens its own handle on the downloaded file so they can
        # stream in parallel.
        report = run_scanners(
            scanners, lambda: open(file_path, "rb"), api_client=api_client
        )

    except FileError as exc:
        logger.error(f"Job {job_id} file error: {exc}")
        _report_error(result, webhook_url, "file", str(exc))
        return

    except encryption.DecryptionError as exc:
        # A retry can't fix bad bytes or a bad key — report as a file error so
        # the caller drops the file instead of looping. Never log the key.
        logger.error(f"Job {job_id} decryption failed: {exc}")
        _report_error(result, webhook_url, "file", f"decryption_failed: {exc}")
        return

    except SSRFValidationError as exc:
        logger.error(f"Job {job_id} blocked by scan policy: {exc}")
        _report_error(result, webhook_url, "file", f"ssrf_blocked: {exc}")
        return

    except http_requests.RequestException as exc:
        # Download failures report at once: the URL is frozen in the task args,
        # so a stale/expired presigned URL wouldn't recover on retry.
        logger.error(f"Job {job_id} download failed: {exc}")
        _report_error(result, webhook_url, "transient", f"download_failed: {exc}")
        return

    except Exception as exc:
        logger.error(f"Job {job_id} unexpected error: {exc}")
        if _retries_exhausted():
            _report_error(result, webhook_url, "transient", str(exc))
            return
        raise

    finally:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)

    # Download + scan succeeded. When EVERY scanner failed transiently, retry the
    # whole job; report only once the budget is spent.
    if report.all_errored:
        if not _retries_exhausted():
            raise ScannerError("all scanners failed transiently")
        _deliver(result, webhook_url, report, transient_error=True)
        return

    logger.info(f"Async scan job {job_id} complete. Malware: {report.malware}")
    _deliver(result, webhook_url, report)
