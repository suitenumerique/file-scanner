"""Async /api/v1.0/scan-async endpoint (+ the /v2/scan-async alias transfers uses)
and the dramatiq worker task's verdict/error reporting."""

import base64
import os
from unittest import mock

import clamd
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import encryption
import tasks
from app import settings
from tasks import scan_task

ASYNC_URL = "/api/v1.0/scan-async"


# --- endpoint ---


def test_requires_auth(client):
    r = client.post(ASYNC_URL, json={"url": "http://example.com/f"})
    assert r.status_code == 401


def test_requires_url(client, auth):
    r = client.post(ASYNC_URL, json={}, headers=auth)
    assert r.status_code == 422


def test_rejects_bad_scheme(client, auth):
    r = client.post(ASYNC_URL, json={"url": "ftp://evil.com/f"}, headers=auth)
    assert r.status_code == 422


def test_requires_webhook(client, auth):
    r = client.post(ASYNC_URL, json={"url": "http://example.com/f.pdf"}, headers=auth)
    assert r.status_code == 422


def test_rejects_unknown_scanner(client, auth):
    r = client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "scanners": ["bogus"],
        },
        headers=auth,
    )
    assert r.status_code == 400


def test_creates_job(client, auth):
    r = client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "filename": "f.pdf",
            "webhook_url": "http://callback.example.com/av",
        },
        headers=auth,
    )
    assert r.status_code == 202
    assert "job_id" in r.json()
    assert r.json()["status"] == "pending"


def test_creates_job_with_categories(client, auth):
    r = client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "categories": ["malware"],
        },
        headers=auth,
    )
    assert r.status_code == 202


def test_rejects_unknown_category(client, auth):
    r = client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "categories": ["nsfw"],
        },
        headers=auth,
    )
    assert r.status_code == 400


def test_creates_job_with_encryption(client, auth):
    r = client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "encryption": {"key": "A" * 43, "chunk_size": 65536, "file_id": "abc"},
        },
        headers=auth,
    )
    assert r.status_code == 202


def test_rejects_bad_encryption_key_length(client, auth):
    r = client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "encryption": {"key": "tooshort", "chunk_size": 65536, "file_id": "abc"},
        },
        headers=auth,
    )
    assert r.status_code == 422


def test_v2_async_alias(client, auth):
    # transfers posts to the /v2/scan-async alias.
    r = client.post(
        "/v2/scan-async",
        json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
        },
        headers=auth,
    )
    assert r.status_code == 202


def test_allowed_url_hosts(client, auth, monkeypatch):
    monkeypatch.setattr(settings, "allowed_url_hosts", "trusted.example.com")

    r = client.post(ASYNC_URL, json={"url": "http://evil.com/f"}, headers=auth)
    assert r.status_code == 400
    assert "not allowed" in r.json()["detail"]

    r = client.post(
        ASYNC_URL,
        json={
            "url": "http://trusted.example.com/f",
            "webhook_url": "http://callback.example.com/av",
        },
        headers=auth,
    )
    assert r.status_code == 202


# --- worker task ---


@pytest.fixture
def run_task(clamav):
    """Invoke ``scan_task.fn`` with the download + INSTREAM boundaries stubbed and
    the webhook captured; returns the list of payloads pushed. Called directly, so
    there is no retry loop — a transient failure is reported at once."""

    def _run(
        verdict=("OK", None),
        instream=None,
        get=None,
        content_length=None,
        chunks=None,
        scanners=("clamav",),
        encryption_params=None,
        scanned=None,
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
            mock.patch.object(tasks, "_send_webhook", side_effect=_capture),
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
            )
        return sent

    return _run


def test_task_clean(run_task):
    (sent,) = run_task(verdict=("OK", None))
    assert sent["malware"] is False
    assert sent["scanners"][0]["kind"] == "clean"
    assert "error_kind" not in sent


def test_task_infected(run_task):
    (sent,) = run_task(verdict=("FOUND", "Eicar-Test-Signature"))
    assert sent["malware"] is True
    assert sent["scanners"][0]["reason"] == "Eicar-Test-Signature"


def test_task_unscannable(run_task):
    # clamav backend flattens an ERROR to UNSCANNABLE (exav preserves the tag).
    (sent,) = run_task(verdict=("ERROR", "Encrypted data"))
    assert sent["malware"] is False
    assert sent["scanners"][0]["kind"] == "unscannable"
    assert sent["scanners"][0]["reason"] == "UNSCANNABLE"
    assert "error_kind" not in sent


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


def test_task_unbounded_body_capped_as_file(run_task, monkeypatch):
    monkeypatch.setattr(tasks.settings, "max_url_size", 8)
    (sent,) = run_task(chunks=[b"x" * 20])
    assert sent["error_kind"] == "file"


def test_task_malformed_content_length_ignored(run_task):
    (sent,) = run_task(content_length="not-a-number")
    assert sent["malware"] is False
    assert "error_kind" not in sent


def test_task_download_failure_is_transient(run_task):
    def _boom(*_a, **_k):
        raise tasks.http_requests.RequestException("connection reset")

    (sent,) = run_task(get=_boom)
    assert sent["error_kind"] == "transient"


# --- client-encrypted sources (decrypt before scanning) ---

_KEY = b"\x11" * 32
_KEY_FRAGMENT = base64.urlsafe_b64encode(_KEY).decode().rstrip("=")  # 43 chars
_FILE_ID = "file-abc"
_CHUNK = 64


def _encrypt(plaintext, key=_KEY, file_id=_FILE_ID, chunk_size=_CHUNK):
    """Build the ciphertext stream the caller sends: one crypto chunk per
    ``chunk_size`` of plaintext, each ``IV || ciphertext || tag`` and bound to
    ``f"{file_id}:{part}"`` (1-based)."""
    parts = []
    for part, i in enumerate(range(0, len(plaintext), chunk_size), start=1):
        iv = os.urandom(encryption.IV_BYTES)
        aad = f"{file_id}:{part}".encode()
        parts.append(iv + AESGCM(key).encrypt(iv, plaintext[i : i + chunk_size], aad))
    return b"".join(parts)


def _params(key_fragment=_KEY_FRAGMENT, chunk_size=_CHUNK, file_id=_FILE_ID):
    return {"key": key_fragment, "chunk_size": chunk_size, "file_id": file_id}


def test_task_decrypts_before_scan(run_task):
    plaintext = b"NOT A VIRUS, just secret bytes.\n"
    scanned = []
    (sent,) = run_task(
        chunks=[_encrypt(plaintext)], encryption_params=_params(), scanned=scanned
    )
    assert sent["malware"] is False
    assert scanned == [plaintext]  # the scanner saw plaintext, not ciphertext


def test_task_decrypts_multi_chunk_with_short_tail(run_task):
    plaintext = b"A" * (2 * _CHUNK + 5)  # two full chunks + a short tail
    scanned = []
    (sent,) = run_task(
        chunks=[_encrypt(plaintext)], encryption_params=_params(), scanned=scanned
    )
    assert scanned == [plaintext]
    assert sent["malware"] is False


def test_task_decrypt_wire_chunking_is_irrelevant(run_task):
    plaintext = b"reassembled across arbitrary wire boundaries " * 4
    wire = _encrypt(plaintext)
    pieces = [wire[i : i + 7] for i in range(0, len(wire), 7)]  # tiny 7-byte reads
    scanned = []
    (sent,) = run_task(chunks=pieces, encryption_params=_params(), scanned=scanned)
    assert scanned == [plaintext]
    assert sent["malware"] is False


def test_task_infected_plaintext_is_reported(run_task):
    (sent,) = run_task(
        verdict=("FOUND", "Eicar-Test-Signature"),
        chunks=[_encrypt(b"whatever")],
        encryption_params=_params(),
    )
    assert sent["malware"] is True


def test_task_wrong_key_is_file_error(run_task):
    wrong = base64.urlsafe_b64encode(b"\x22" * 32).decode().rstrip("=")
    (sent,) = run_task(
        chunks=[_encrypt(b"secret")], encryption_params=_params(key_fragment=wrong)
    )
    assert sent["error_kind"] == "file"
    assert sent["error"].startswith("decryption_failed:")


def test_task_malformed_key_is_file_error(run_task):
    (sent,) = run_task(
        chunks=[_encrypt(b"secret")],
        encryption_params=_params(key_fragment="not-url-safe+/"),
    )
    assert sent["error_kind"] == "file"


def test_task_truncated_ciphertext_is_file_error(run_task):
    wire = _encrypt(b"a long enough secret payload to truncate")[:-5]
    (sent,) = run_task(chunks=[wire], encryption_params=_params())
    assert sent["error_kind"] == "file"
