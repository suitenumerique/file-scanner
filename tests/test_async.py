"""Async scan-async endpoint and the dramatiq worker task's verdict/error
reporting.

The webhook is a callback with no route of its own, so the shape of its body
follows the API version the job was *submitted* under. These cases run the
current version (v2) unless they say otherwise.
"""

import base64
import inspect
import os
from unittest import mock

import clamd
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import encryption
import tasks
import wire
from app import settings
from tasks import scan_task

ASYNC_URL = "/api/v2.0/scan-async"
ASYNC_URL_V1 = "/api/v1.0/scan-async"


def test_tasks_use_dedicated_queues():
    # Heavy scans and light webhook delivery ride separate queues so they can be
    # scaled independently; the single worker consumes both by default.
    assert scan_task.queue_name == "scans"
    assert tasks.deliver_webhook.queue_name == "webhooks"
    # Webhooks outrank scans (lower number runs first) so a buffered callback is
    # picked ahead of buffered scans when a worker thread frees.
    assert tasks.deliver_webhook.priority < scan_task.priority


# --- endpoint ---


def test_requires_auth(client):
    r = client.post(ASYNC_URL, json={"url": "http://example.com/f"})
    assert r.status_code == 401


def test_requires_url(auth_client):
    r = auth_client.post(ASYNC_URL, json={})
    assert r.status_code == 422


def test_rejects_bad_scheme(auth_client):
    r = auth_client.post(ASYNC_URL, json={"url": "ftp://evil.com/f"})
    assert r.status_code == 422


def test_requires_webhook(auth_client):
    r = auth_client.post(ASYNC_URL, json={"url": "http://example.com/f.pdf"})
    assert r.status_code == 422


def test_rejects_unknown_scanner(auth_client):
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "scanners": ["bogus"],
        },
    )
    assert r.status_code == 400


def test_creates_job(auth_client):
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "filename": "f.pdf",
            "webhook_url": "http://callback.example.com/av",
        },
    )
    assert r.status_code == 202
    assert "job_id" in r.json()
    assert r.json()["status"] == "pending"


def test_creates_job_with_categories(auth_client):
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "categories": ["malware"],
        },
    )
    assert r.status_code == 202


def test_rejects_unknown_category(auth_client):
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "categories": ["nsfw"],
        },
    )
    assert r.status_code == 400


def test_creates_job_with_encryption(auth_client):
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "encryption": {
                "key": "A" * 43,
                "chunk_size": 65536,
                "file_id": "abc",
                "parts": 1,
            },
        },
    )
    assert r.status_code == 202


def test_rejects_a_scan_clamav_would_decide_past_its_ceiling(auth_client, monkeypatch):
    import scanner as scanner_mod

    monkeypatch.setattr(scanner_mod.settings, "max_url_size", 3 * 1024**3)
    monkeypatch.setattr(scanner_mod.settings, "advisory_scanners", "clamav")
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "scanners": ["clamav"],
        },
    )
    assert r.status_code == 400
    assert "clamav cannot decide" in r.json()["detail"]


def test_rejects_unknown_encryption_scheme(auth_client):
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "encryption": {
                "scheme": "rot13",
                "key": "A" * 43,
                "chunk_size": 65536,
                "file_id": "abc",
                "parts": 1,
            },
        },
    )
    assert r.status_code == 422


def test_rejects_bad_encryption_key_length(auth_client):
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "encryption": {"key": "tooshort", "chunk_size": 65536, "file_id": "abc"},
        },
    )
    assert r.status_code == 422


def test_rejects_too_small_chunk_size(auth_client):
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "encryption": {
                "key": "A" * 43,
                "chunk_size": 1,
                "file_id": "abc",
                "parts": 1,
            },
        },
    )
    assert r.status_code == 422


def test_allowed_url_hosts(auth_client, monkeypatch):
    monkeypatch.setattr(settings, "allowed_url_hosts", "trusted.example.com")

    r = auth_client.post(ASYNC_URL, json={"url": "http://evil.com/f"})
    assert r.status_code == 400
    assert "not allowed" in r.json()["detail"]

    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://trusted.example.com/f",
            "webhook_url": "http://callback.example.com/av",
        },
    )
    assert r.status_code == 202


# --- worker task ---


@pytest.fixture
def run_task(clamav):
    """Invoke ``scan_task.fn`` with the download + INSTREAM boundaries stubbed and
    the webhook *enqueue* captured; returns the list of payloads handed to the
    delivery actor. Delivery is a separate task, so ``scan_task`` only enqueues
    it — the captured payload is what would be delivered."""

    def _run(
        verdict=("OK", None),
        instream=None,
        get=None,
        content_length=None,
        chunks=None,
        scanners=("clamav",),
        encryption_params=None,
        scanned=None,
        wire_version=wire.V2,
    ):
        sent = []

        def _capture(_url, payload):
            sent.append(dict(payload))
            return True

        response = mock.MagicMock()
        response.headers = (
            {"Content-Length": str(content_length)} if content_length else {}
        )
        response.iter_content.return_value = chunks if chunks is not None else [b"data"]

        cd = mock.MagicMock()
        if instream is not None:
            cd.instream.side_effect = instream
        elif scanned is not None:
            # Record the bytes handed to the scanner (to prove decryption).
            def _capture_scan(fh):
                scanned.append(fh.read())
                return {"stream": verdict}

            cd.instream.side_effect = _capture_scan
        else:
            cd.instream.return_value = {"stream": verdict}

        with (
            mock.patch.object(tasks.deliver_webhook, "send", side_effect=_capture),
            mock.patch.object(
                tasks._session,
                "get",
                side_effect=get,
                return_value=None if get else response,
            ),
            mock.patch.object(clamav, "_client", return_value=cd),
        ):
            scan_task.fn(
                "job1",
                "http://src/f.bin",
                list(scanners),
                "f.bin",
                "http://cb/av",
                None,
                "",
                encryption_params,
                wire_version,
            )
        return sent

    return _run


def test_task_clean(run_task):
    (sent,) = run_task(verdict=("OK", None))
    assert sent["verdicts"]["malware"]["kind"] == "clean"
    assert sent["scanners"][0]["kind"] == "clean"
    assert sent["status"] == "done"
    assert "error_kind" not in sent


def test_task_infected(run_task):
    (sent,) = run_task(verdict=("FOUND", "Eicar-Test-Signature"))
    assert sent["verdicts"]["malware"]["kind"] == "malware"
    assert sent["scanners"][0]["reason"] == "Eicar-Test-Signature"


def test_task_partial(run_task):
    # clamav backend flattens an ERROR to UNSCANNABLE (exav preserves the tag).
    # The file was not examined in full: the verdict says so outright, so the
    # caller blocks it without retrying.
    (sent,) = run_task(verdict=("ERROR", "Encrypted data"))
    assert sent["status"] == "done"
    assert sent["verdicts"]["malware"] == {
        "kind": "partial",
        "reason": "UNSCANNABLE",
    }
    assert sent["scanners"][0]["kind"] == "partial"
    assert sent["scanners"][0]["reason"] == "UNSCANNABLE"


def test_task_all_scanners_error_is_transient(run_task):
    (sent,) = run_task(verdict=("ERROR", "Time limit reached"))
    assert sent["error_kind"] == "transient"


def test_task_connection_error_is_transient(run_task):
    def _boom(_fh):
        raise clamd.ConnectionError("clamd down")

    (sent,) = run_task(instream=_boom)
    assert sent["error_kind"] == "transient"


def test_task_ssrf_blocked_is_file(run_task):
    from ssrf import SSRFValidationError

    def _boom(*_a, **_k):
        raise SSRFValidationError("host resolves to loopback address")

    (sent,) = run_task(get=_boom)
    assert sent["error_kind"] == "file"
    assert sent["error"].startswith("ssrf_blocked:")


def test_task_too_large_is_file(run_task):
    (sent,) = run_task(content_length=settings.max_url_size + 1)
    assert sent["error_kind"] == "file"


def test_task_cap_counts_the_plaintext_of_an_encrypted_source(run_task, monkeypatch):
    """MAX_URL_SIZE bounds the file the scanners see: a ciphertext over it by
    exactly its chunking overhead is accepted, one plaintext byte more is
    not."""
    cap = 2 * _CHUNK
    monkeypatch.setattr(tasks.settings, "max_url_size", cap)
    plaintext = b"P" * cap  # two full chunks: wire = cap + 2 * 28
    wire = _encrypt(plaintext)
    assert len(wire) == cap + 2 * encryption.OVERHEAD_PER_CHUNK
    scanned = []
    (sent,) = run_task(
        chunks=[wire],
        content_length=len(wire),
        encryption_params=_params(plaintext),
        scanned=scanned,
    )
    assert "error_kind" not in sent
    assert scanned == [plaintext]

    plaintext = b"P" * (cap + 1)  # one byte over: a third (tiny) chunk
    wire = _encrypt(plaintext)
    (sent,) = run_task(
        chunks=[wire], content_length=len(wire), encryption_params=_params(plaintext)
    )
    assert sent["error_kind"] == "file"
    assert sent["error"].startswith("file_too_large")


def test_task_encrypted_wire_over_its_room_is_rejected_up_front(run_task, monkeypatch):
    cap = 2 * _CHUNK
    monkeypatch.setattr(tasks.settings, "max_url_size", cap)
    room = cap + 2 * encryption.OVERHEAD_PER_CHUNK
    (sent,) = run_task(content_length=room + 1, encryption_params=_params(b"P" * cap))
    assert sent["error_kind"] == "file"
    assert sent["error"].startswith("file_too_large")


def test_task_unbounded_body_capped_as_file(run_task, monkeypatch):
    monkeypatch.setattr(tasks.settings, "max_url_size", 8)
    (sent,) = run_task(chunks=[b"x" * 20])
    assert sent["error_kind"] == "file"


def test_task_malformed_content_length_ignored(run_task):
    (sent,) = run_task(content_length="not-a-number")
    assert sent["verdicts"]["malware"]["kind"] == "clean"
    assert "error_kind" not in sent


def test_task_download_failure_is_transient(run_task):
    def _boom(*_a, **_k):
        raise tasks.http_requests.RequestException("connection reset")

    (sent,) = run_task(get=_boom)
    assert sent["error_kind"] == "transient"


# --- webhook delivery actor (its own retriable task) ---


def test_deliver_webhook_success():
    resp = mock.MagicMock()
    resp.is_redirect = False
    resp.raise_for_status.return_value = None
    with mock.patch.object(tasks._session, "post", return_value=resp) as post:
        tasks.deliver_webhook.fn("http://cb/av", {"job_id": "j"})  # no raise
    post.assert_called_once()
    assert post.call_args.kwargs["allow_redirects"] is False


def test_deliver_webhook_redirect_is_failure():
    # A webhook must not redirect: a 3xx is a failed delivery (retried), never
    # followed (the signed token binds the original webhook_url).
    resp = mock.MagicMock()
    resp.is_redirect = True
    resp.status_code = 302
    resp.headers = {"Location": "http://elsewhere.example.com/av"}
    with mock.patch.object(tasks._session, "post", return_value=resp):
        with pytest.raises(tasks.http_requests.HTTPError):
            tasks.deliver_webhook.fn("http://cb/av", {"job_id": "j"})


def test_deliver_webhook_transient_reraises_for_retry():
    # A transient failure must propagate so dramatiq retries + eventually DLQs.
    with mock.patch.object(
        tasks._session,
        "post",
        side_effect=tasks.http_requests.RequestException("connection reset"),
    ):
        with pytest.raises(tasks.http_requests.RequestException):
            tasks.deliver_webhook.fn("http://cb/av", {"job_id": "j"})


def test_deliver_webhook_blocked_host_is_permanent():
    from ssrf import SSRFValidationError

    # A blocked webhook host won't become safe on retry: log + drop, never raise.
    with mock.patch.object(
        tasks._session, "post", side_effect=SSRFValidationError("resolves to loopback")
    ):
        tasks.deliver_webhook.fn("http://cb/av", {"job_id": "j"})  # returns, no raise


# --- client-encrypted sources (decrypt before scanning) ---

_KEY = b"\x11" * 32
_KEY_FRAGMENT = base64.urlsafe_b64encode(_KEY).decode().rstrip("=")  # 43 chars
_FILE_ID = "file-abc"
_CHUNK = 4096  # >= settings.encryption_min_chunk_size


def _nparts(plaintext, chunk_size=_CHUNK):
    return -(-len(plaintext) // chunk_size)  # ceil division


def _encrypt(plaintext, key=_KEY, file_id=_FILE_ID, chunk_size=_CHUNK):
    """Build the ciphertext stream the caller sends: one crypto chunk per
    ``chunk_size`` of plaintext, each ``IV || ciphertext || tag`` bound to
    ``f"{file_id}:{part}:{parts}"`` (1-based part, total parts)."""
    parts = _nparts(plaintext, chunk_size)
    out = []
    for part, i in enumerate(range(0, len(plaintext), chunk_size), start=1):
        iv = os.urandom(encryption.IV_BYTES)
        aad = f"{file_id}:{part}:{parts}".encode()
        out.append(iv + AESGCM(key).encrypt(iv, plaintext[i : i + chunk_size], aad))
    return b"".join(out)


def _params(plaintext, key_fragment=_KEY_FRAGMENT, chunk_size=_CHUNK, file_id=_FILE_ID):
    return {
        "key": key_fragment,
        "chunk_size": chunk_size,
        "file_id": file_id,
        "parts": _nparts(plaintext, chunk_size),
    }


def test_task_decrypts_before_scan(run_task):
    plaintext = b"NOT A VIRUS, just secret bytes.\n"
    scanned = []
    (sent,) = run_task(
        chunks=[_encrypt(plaintext)],
        encryption_params=_params(plaintext),
        scanned=scanned,
    )
    assert sent["verdicts"]["malware"]["kind"] == "clean"
    assert scanned == [plaintext]  # the scanner saw plaintext, not ciphertext


def test_task_decrypts_multi_chunk_with_short_tail(run_task):
    plaintext = b"A" * (2 * _CHUNK + 5)  # two full chunks + a short tail
    scanned = []
    (sent,) = run_task(
        chunks=[_encrypt(plaintext)],
        encryption_params=_params(plaintext),
        scanned=scanned,
    )
    assert scanned == [plaintext]
    assert sent["verdicts"]["malware"]["kind"] == "clean"


def test_task_decrypt_wire_chunking_is_irrelevant(run_task):
    plaintext = b"reassembled across arbitrary wire boundaries " * 200  # multi-chunk
    wire = _encrypt(plaintext)
    pieces = [wire[i : i + 7] for i in range(0, len(wire), 7)]  # tiny 7-byte reads
    scanned = []
    (sent,) = run_task(
        chunks=pieces, encryption_params=_params(plaintext), scanned=scanned
    )
    assert scanned == [plaintext]
    assert sent["verdicts"]["malware"]["kind"] == "clean"


def test_task_infected_plaintext_is_reported(run_task):
    (sent,) = run_task(
        verdict=("FOUND", "Eicar-Test-Signature"),
        chunks=[_encrypt(b"whatever")],
        encryption_params=_params(b"whatever"),
    )
    assert sent["verdicts"]["malware"]["kind"] == "malware"


def test_task_wrong_key_is_file_error(run_task):
    wrong = base64.urlsafe_b64encode(b"\x22" * 32).decode().rstrip("=")
    (sent,) = run_task(
        chunks=[_encrypt(b"secret")],
        encryption_params=_params(b"secret", key_fragment=wrong),
    )
    assert sent["error_kind"] == "file"
    assert sent["error"].startswith("decryption_failed:")


def test_task_malformed_key_is_file_error(run_task):
    (sent,) = run_task(
        chunks=[_encrypt(b"secret")],
        encryption_params=_params(b"secret", key_fragment="not-url-safe+/"),
    )
    assert sent["error_kind"] == "file"


def test_task_truncated_ciphertext_is_file_error(run_task):
    plaintext = b"a long enough secret payload to truncate"
    (sent,) = run_task(
        chunks=[_encrypt(plaintext)[:-5]], encryption_params=_params(plaintext)
    )
    assert sent["error_kind"] == "file"


def test_task_trailing_chunk_truncation_is_detected(run_task):
    # Drop a whole trailing chunk: it lands on a boundary and each remaining
    # chunk still authenticates, but the declared total no longer matches.
    plaintext = b"Z" * (3 * _CHUNK)  # exactly three full chunks
    blob = _CHUNK + encryption.OVERHEAD_PER_CHUNK
    truncated = _encrypt(plaintext)[: 2 * blob]  # chunk 3 removed entirely
    (sent,) = run_task(chunks=[truncated], encryption_params=_params(plaintext))
    assert sent["error_kind"] == "file"
    assert "chunks" in sent["error"]  # "expected 3 chunks, decrypted 2 (truncated?)"


def test_task_unsupported_scheme_is_file_error(run_task):
    # Direct-enqueue path (bypasses endpoint validation): an unknown scheme is a
    # permanent file error, not a retried transient one.
    plaintext = b"whatever payload here"
    params = _params(plaintext)
    params["scheme"] = "rot13"
    (sent,) = run_task(chunks=[_encrypt(plaintext)], encryption_params=params)
    assert sent["error_kind"] == "file"
    assert "scheme" in sent["error"]


# --- the version travels with the job ---------------------------------------


def _delivered(result, version):
    """Run ``_finalize`` on a terminal ``result``; returns (webhook body, stored
    record). This is the hand-off the version rides through — the download and
    scan before it are covered elsewhere."""
    sent, stored = [], []
    with (
        mock.patch.object(
            tasks.deliver_webhook,
            "send",
            side_effect=lambda _url, body: sent.append(body),
        ),
        mock.patch.object(
            tasks.results,
            "record",
            side_effect=lambda _j, _o, rec: stored.append(dict(rec)),
        ),
    ):
        tasks._finalize(result, "http://cb/av", "caller", version)
    return sent[0], stored[0]


def _terminal(kind, **rest):
    return {
        "job_id": "j1",
        "status": "done",
        "verdicts": {"malware": {"kind": kind, **rest}},
        "scanners": [{"scanner": "clamav", "category": "malware", "kind": kind}],
    }


def test_a_v1_job_is_called_back_in_the_v1_shape():
    """The callback has no route to ask with, so the version the job was
    submitted under is the only thing that can decide its shape."""
    body, _ = _delivered(_terminal("malware", reason="Eicar-Test-Signature"), wire.V1)
    assert body["malware"] is True
    assert "verdicts" not in body
    assert body["api_version"] == wire.V1


def test_a_v2_job_is_called_back_with_its_verdicts():
    body, _ = _delivered(_terminal("partial", reason="UNSCANNABLE"), wire.V2)
    assert body["verdicts"]["malware"]["kind"] == "partial"
    assert body["api_version"] == wire.V2


def test_a_v1_job_gets_the_error_kind_that_qualifies_a_null():
    body, _ = _delivered(_terminal("partial", reason="UNSCANNABLE"), wire.V1)
    assert body["malware"] is None
    assert body["error_kind"] == "file"


def test_the_record_is_stored_canonically_whatever_the_job_version():
    """Either version can poll any job, so the stored record cannot be the
    caller's shape — the poll route downgrades it on the way out."""
    _, record = _delivered(_terminal("malware", reason="Eicar"), wire.V1)
    assert record["verdicts"]["malware"]["kind"] == "malware"
    assert "api_version" not in record


def test_the_default_shape_is_v1_for_a_message_queued_before_this_version():
    """A job enqueued by the previous worker carries no version argument at all.
    It was submitted by a v1 caller by definition — nothing else existed — so
    the default must answer it in v1, not in a shape it cannot read. This is a
    rollout guarantee, not a preference: it is what keeps the jobs in flight
    during the deploy from coming back unreadable."""
    default = inspect.signature(scan_task.fn).parameters["wire_version"].default
    assert default == wire.V1


def _submitted_version(auth_client, url):
    """The version handed to the task by a submit on ``url`` (SSRF guard stubbed
    — the point here is the path, not the destination)."""
    import app

    body = {"url": "http://src/f.bin", "webhook_url": "http://cb/av"}
    with (
        mock.patch.object(app, "assert_scannable"),
        mock.patch.object(scan_task, "send") as send,
    ):
        r = auth_client.post(url, json=body)
    assert r.status_code == 202, r.text
    return send.call_args.args[-1]


def test_the_submitted_version_is_carried_into_the_message(auth_client):
    """The endpoint is what reads the path; the task only obeys it. This is the
    hand-off that lets a callback know its own shape later."""
    assert _submitted_version(auth_client, ASYNC_URL_V1) == wire.V1
    assert _submitted_version(auth_client, ASYNC_URL) == wire.V2
