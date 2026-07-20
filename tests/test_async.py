"""Async /api/v1.0/scan-async endpoint (+ the /v2/scan-async alias transfers uses)
and the dramatiq worker task's verdict/error reporting."""

from unittest import mock

import clamd
import pytest

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
        cd.instream.side_effect = instream
        cd.instream.return_value = None if instream else {"stream": verdict}

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
