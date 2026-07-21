"""SSRF guard: hostname validation, the IP-pinned redirect session, and the
/api/v1.0/scan-async request boundary."""

import socket
from unittest import mock

import pytest

from app import settings
from ssrf import SSRFSafeSession, SSRFValidationError, validate_hostname


def _gai(*ips):
    """A socket.getaddrinfo-shaped return value for the given IPs."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


# --- validate_hostname ---


def test_public_is_allowed():
    with mock.patch("ssrf.socket.getaddrinfo", return_value=_gai("93.184.216.34")):
        assert validate_hostname("host.example.com") == ["93.184.216.34"]


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "10.0.0.1",  # RFC1918
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",  # CGNAT
        "::1",  # IPv6 loopback
        "fd00::1",  # IPv6 unique-local
    ],
)
def test_non_public_is_rejected(ip):
    with mock.patch("ssrf.socket.getaddrinfo", return_value=_gai(ip)):
        with pytest.raises(SSRFValidationError):
            validate_hostname("host.example.com")


def test_any_non_public_record_rejects():
    with mock.patch(
        "ssrf.socket.getaddrinfo", return_value=_gai("93.184.216.34", "10.0.0.1")
    ):
        with pytest.raises(SSRFValidationError):
            validate_hostname("host.example.com")


def test_unresolvable_is_rejected():
    with mock.patch("ssrf.socket.getaddrinfo", side_effect=socket.gaierror):
        with pytest.raises(SSRFValidationError):
            validate_hostname("does-not-exist.invalid")


def test_ip_literal_rejected_by_default():
    with pytest.raises(SSRFValidationError):
        validate_hostname("93.184.216.34")


def test_allowlisted_host_bypasses_private_block(monkeypatch):
    monkeypatch.setattr(settings, "ssrf_allowed_hosts", "internal.storage")
    with mock.patch("ssrf.socket.getaddrinfo", return_value=_gai("10.0.0.5")):
        assert validate_hostname("internal.storage") == ["10.0.0.5"]


# --- SSRFSafeSession redirect handling ---


def test_each_hop_is_revalidated():
    session = SSRFSafeSession()
    hop1 = mock.MagicMock(
        status_code=302, headers={"Location": "http://b.example.com/x"}
    )
    hop2 = mock.MagicMock(status_code=200, headers={})
    fake = mock.MagicMock()
    fake.get.side_effect = [hop1, hop2]
    with mock.patch.object(
        session, "_pinned_session", return_value=(fake, "h")
    ) as pinned:
        resp = session.get("http://a.example.com/x", timeout=5)
    assert resp is hop2
    assert pinned.call_count == 2  # one pin per hop → the redirect target was validated


def test_https_to_http_downgrade_refused():
    session = SSRFSafeSession()
    redirect = mock.MagicMock(
        status_code=302, headers={"Location": "http://b.example.com/x"}
    )
    fake = mock.MagicMock()
    fake.get.return_value = redirect
    with mock.patch.object(session, "_pinned_session", return_value=(fake, "h")):
        with pytest.raises(SSRFValidationError):
            session.get("https://a.example.com/x", timeout=5)


# --- /api/v1.0/scan-async boundary (guard active only when not testing) ---


@pytest.fixture
def guard_active(monkeypatch):
    """Turn off the test-mode SSRF bypass for the request-layer check."""
    monkeypatch.setattr(settings, "testing", False)


def test_metadata_url_rejected(auth_client, guard_active):
    def _reject(hostname, **_):
        raise SSRFValidationError(f"{hostname} resolves to cloud metadata endpoint")

    with mock.patch("validation.validate_hostname", side_effect=_reject):
        r = auth_client.post(
            "/api/v1.0/scan-async",
            json={
                "url": "http://metadata.example.com/latest/meta-data",
                "webhook_url": "http://callback.example.com/av",
            },
        )
    assert r.status_code == 400
    assert "metadata" in r.json()["detail"]


def test_public_url_accepted(auth_client, guard_active):
    with mock.patch("validation.validate_hostname", return_value=["93.184.216.34"]):
        r = auth_client.post(
            "/api/v1.0/scan-async",
            json={
                "url": "http://example.com/f.pdf",
                "webhook_url": "http://callback.example.com/av",
            },
        )
    assert r.status_code == 202
