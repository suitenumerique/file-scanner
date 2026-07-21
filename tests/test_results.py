"""Optional async-job result store and the GET /api/v1.0/jobs/{job_id} poll route.

The store is opt-in (WORKER_RESULT_TTL); these tests enable it by monkeypatching the
TTL and clearing the in-process eager-mode store between cases.
"""

from unittest import mock

import pytest

import results
import tasks
from app import settings

JOBS_URL = "/api/v1.0/jobs"
ASYNC_URL = "/api/v1.0/scan-async"


@pytest.fixture
def store_on(monkeypatch):
    """Enable the store (positive TTL) on a clean in-memory store for one test."""
    monkeypatch.setattr(settings, "worker_result_ttl", 3600)
    results._reset_for_tests()


# --- store unit ---


def test_store_disabled_is_noop(monkeypatch):
    monkeypatch.setattr(settings, "worker_result_ttl", 0)
    results._reset_for_tests()
    results.record("j1", "owner", {"status": "done"})
    assert results.fetch("j1", "owner") is None


def test_store_roundtrip(store_on):
    results.record("j1", "owner", {"job_id": "j1", "status": "done", "malware": False})
    got = results.fetch("j1", "owner")
    assert got["status"] == "done"
    assert got["malware"] is False


def test_store_owner_scoped(store_on):
    results.record("j1", "owner", {"job_id": "j1", "status": "done"})
    # A different caller can't read it — indistinguishable from absent.
    assert results.fetch("j1", "intruder") is None


def test_store_unknown_is_none(store_on):
    assert results.fetch("nope", "owner") is None


# --- poll endpoint ---


def test_poll_requires_auth(client, store_on):
    assert client.get(f"{JOBS_URL}/whatever").status_code == 401


def test_poll_disabled_is_404(auth_client, monkeypatch):
    monkeypatch.setattr(settings, "worker_result_ttl", 0)
    assert auth_client.get(f"{JOBS_URL}/whatever").status_code == 404


def test_poll_unknown_is_404(auth_client, store_on):
    assert auth_client.get(f"{JOBS_URL}/does-not-exist").status_code == 404


def test_poll_is_owner_scoped(auth_client, store_on):
    # A record owned by someone else is 404 for this caller (dev-issuer).
    results.record("other", "someone-else", {"job_id": "other", "status": "done"})
    assert auth_client.get(f"{JOBS_URL}/other").status_code == 404


def test_webhook_optional_when_store_enabled(auth_client, store_on):
    # With the store on, a webhook-less async scan is accepted (poll instead).
    r = auth_client.post(ASYNC_URL, json={"url": "http://example.com/f.pdf"})
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    s = auth_client.get(f"{JOBS_URL}/{job_id}")
    assert s.status_code == 200
    assert s.json()["status"] == "pending"


def test_poll_pending_then_done(auth_client, clamav, store_on):
    # Create (seeds a pending record), poll, then run the worker as the same
    # caller and poll again for the terminal result.
    r = auth_client.post(
        ASYNC_URL,
        json={
            "url": "http://example.com/f.pdf",
            "filename": "f.pdf",
            "webhook_url": "http://cb/av",
        },
    )
    job_id = r.json()["job_id"]
    assert auth_client.get(f"{JOBS_URL}/{job_id}").json()["status"] == "pending"

    cd = mock.MagicMock()
    cd.instream.return_value = {"stream": ("OK", None)}
    response = mock.MagicMock()
    response.headers = {}
    response.iter_content.return_value = [b"data"]
    with (
        mock.patch.object(tasks.deliver_webhook, "send"),
        mock.patch.object(tasks._session, "get", return_value=response),
        mock.patch.object(clamav, "_client", return_value=cd),
    ):
        tasks.scan_task.fn(
            job_id,
            "http://src/f.bin",
            ["clamav"],
            "f.pdf",
            "http://cb/av",
            None,
            "dev-issuer",  # the caller the auth_client authenticates as
            None,
        )

    body = auth_client.get(f"{JOBS_URL}/{job_id}").json()
    assert body["status"] == "done"
    assert body["malware"] is False
    assert body["scanners"][0]["kind"] == "clean"


def test_poll_records_error(auth_client, clamav, store_on):
    # A pre-scan failure (download error) is stored as an error record too.
    r = auth_client.post(
        ASYNC_URL,
        json={"url": "http://example.com/f.pdf", "webhook_url": "http://cb/av"},
    )
    job_id = r.json()["job_id"]

    def _boom(*_a, **_k):
        raise tasks.http_requests.RequestException("connection reset")

    with (
        mock.patch.object(tasks.deliver_webhook, "send"),
        mock.patch.object(tasks._session, "get", side_effect=_boom),
    ):
        tasks.scan_task.fn(
            job_id,
            "http://src/f.bin",
            ["clamav"],
            None,
            "http://cb/av",
            None,
            "dev-issuer",
            None,
        )

    body = auth_client.get(f"{JOBS_URL}/{job_id}").json()
    assert body["status"] == "error"
    assert body["error_kind"] == "transient"
