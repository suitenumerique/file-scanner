"""HTTP API: metrics, health, version, auth, and the sync /api/v1.0/scan endpoint."""

from unittest import mock

import clamd
import pytest

import metrics
from app import settings
from scanner import VersionInfo

SCAN_URL = "/api/v1.0/scan"


def test_metrics_endpoint(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "filescanner_scans_total" in r.text


def test_metrics_bearer_gate_when_key_set(client, monkeypatch):
    # With PROMETHEUS_API_KEY set, /metrics requires the matching bearer token.
    monkeypatch.setattr(settings, "prometheus_api_key", "s3cret")
    assert client.get("/metrics").status_code == 401
    assert (
        client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )
    ok = client.get("/metrics", headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200
    assert "filescanner_scans_total" in ok.text


def test_metrics_label_api_client(client, auth, clamav_cd):
    # A scan is attributed to the caller's API_KEYS name (here "drive").
    clamav_cd.instream.return_value = {"stream": ("OK", None)}
    client.post(SCAN_URL, files={"file": ("f.txt", b"data")}, headers=auth)
    r = client.get("/metrics")
    assert 'api_client="drive"' in r.text


def test_metrics_signature_gauges(client, clamav, monkeypatch):
    monkeypatch.setattr(metrics, "_last_signature_refresh", 0.0)  # bypass the TTL
    with mock.patch.object(
        clamav, "version", return_value=VersionInfo("27000", "27000", False)
    ):
        r = client.get("/metrics")
    assert r.status_code == 200
    assert 'filescanner_signature_outdated{scanner="clamav"} 0.0' in r.text
    assert 'filescanner_signature_version{scanner="clamav"} 27000.0' in r.text


# --- health ---


@pytest.mark.integration
def test_healthcheck_ok(client):
    r = client.get("/check")
    assert r.status_code == 200
    assert r.text == "Service OK"


def test_healthcheck_no_service(client, clamav):
    with mock.patch.object(clamav, "ping", return_value=False):
        r = client.get("/check")
    assert r.status_code == 503


def test_healthcheck_ping_swallows_errors(client, clamav_cd):
    clamav_cd.ping.side_effect = clamd.ConnectionError()
    r = client.get("/check")
    assert r.status_code == 503


# --- auth ---


def test_auth_required(client):
    r = client.post(SCAN_URL, files={"file": ("f.txt", b"data")})
    assert r.status_code == 401


def test_auth_bad_key(client):
    r = client.post(
        SCAN_URL, files={"file": ("f.txt", b"data")}, headers={"X-API-Key": "wrong"}
    )
    assert r.status_code == 401


@pytest.mark.integration
def test_auth_ok(client, auth):
    r = client.post(SCAN_URL, files={"file": ("f.txt", b"clean")}, headers=auth)
    assert r.status_code == 200


# --- sync scan against a real clamav (auto-skipped without a daemon, run in CI) ---


@pytest.mark.integration
def test_eicar(client, auth, eicar, eicar_outputs):
    r = client.post(SCAN_URL, files={"file": ("eicar.txt", eicar)}, headers=auth)
    assert r.status_code == 200
    assert r.json()["malware"]
    assert r.json()["scanners"][0]["reason"] in eicar_outputs


@pytest.mark.integration
def test_clean_file(client, auth):
    r = client.post(SCAN_URL, files={"file": ("clean.txt", b"NO VIRUS")}, headers=auth)
    assert r.status_code == 200
    assert r.json()["malware"] is False
    assert r.json()["scanners"][0]["kind"] == "clean"


@pytest.mark.integration
def test_encrypted_archive(client, auth):
    with open("client-examples/protected.zip", "rb") as f:
        r = client.post(SCAN_URL, files={"file": ("protected.zip", f)}, headers=auth)
    assert r.status_code == 200
    assert "malware" in r.json()


@pytest.mark.integration
def test_xls_macro(client, auth):
    with open("client-examples/eicar-excel-macro-powershell-echo.xls", "rb") as f:
        r = client.post(SCAN_URL, files={"file": ("macro.xls", f)}, headers=auth)
    assert r.status_code == 200
    assert r.json()["malware"]


@pytest.mark.integration
def test_payload_right_size(client, auth):
    content = b"\0" * (settings.max_upload_size - 10000)
    r = client.post(SCAN_URL, files={"file": ("big.bin", content)}, headers=auth)
    assert r.status_code == 200
    assert r.json()["malware"] is False


# --- exav backend (skipped unless an exav daemon is configured + reachable) ---


@pytest.mark.exav
def test_exav_eicar(client, auth, eicar, eicar_outputs):
    r = client.post(
        f"{SCAN_URL}?scanners=exav", files={"file": ("eicar.txt", eicar)}, headers=auth
    )
    assert r.status_code == 200
    entry = r.json()["scanners"][0]
    assert r.json()["malware"]
    assert entry["scanner"] == "exav"
    assert entry["category"] == "malware"
    assert entry["reason"] in eicar_outputs


@pytest.mark.exav
def test_exav_clean(client, auth):
    r = client.post(
        f"{SCAN_URL}?scanners=exav",
        files={"file": ("clean.txt", b"NO VIRUS")},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["malware"] is False
    assert r.json()["scanners"][0]["scanner"] == "exav"
    assert r.json()["scanners"][0]["kind"] == "clean"


def test_payload_too_large(client, auth):
    content = b"\0" * (settings.max_upload_size + 1000)
    r = client.post(SCAN_URL, files={"file": ("toobig.bin", content)}, headers=auth)
    assert r.status_code == 413


# --- verdict mapping (mocked INSTREAM) ---


def test_unscannable_not_malware(client, auth, clamav_cd):
    # An ERROR reply is unscannable, never malware. The clamav backend flattens
    # it to UNSCANNABLE (exav would preserve its structured tag — see
    # test_scanner.py::test_exav_error_tag_is_unscannable).
    clamav_cd.instream.return_value = {"stream": ("ERROR", "Encrypted data")}
    r = client.post(SCAN_URL, files={"file": ("locked.zip", b"data")}, headers=auth)
    assert r.status_code == 200
    assert r.json()["malware"] is False
    entry = r.json()["scanners"][0]
    assert entry["kind"] == "unscannable"
    assert entry["reason"] == "UNSCANNABLE"


def test_all_scanners_error_returns_503(client, auth, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("ERROR", "Can't allocate memory")}
    r = client.post(SCAN_URL, files={"file": ("f.bin", b"data")}, headers=auth)
    assert r.status_code == 503


def test_untagged_file_error_is_unscannable(client, auth, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("ERROR", "Broken archive")}
    r = client.post(SCAN_URL, files={"file": ("f.bin", b"data")}, headers=auth)
    assert r.status_code == 200
    assert r.json()["scanners"][0]["reason"] == "UNSCANNABLE"


def test_scanners_param_selects(client, auth, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("OK", None)}
    r = client.post(
        f"{SCAN_URL}?scanners=clamav", files={"file": ("f.txt", b"data")}, headers=auth
    )
    assert r.status_code == 200
    entry = r.json()["scanners"][0]
    assert entry["scanner"] == "clamav"
    assert entry["category"] == "malware"


def test_categories_param_selects(client, auth, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("OK", None)}
    r = client.post(
        f"{SCAN_URL}?categories=malware",
        files={"file": ("f.txt", b"data")},
        headers=auth,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["malware"] is False  # per-category top-level key
    assert body["scanners"][0]["scanner"] == "clamav"


def test_unknown_scanner_rejected(client, auth):
    r = client.post(
        f"{SCAN_URL}?scanners=bogus", files={"file": ("f.txt", b"data")}, headers=auth
    )
    assert r.status_code == 400


def test_unknown_category_rejected(client, auth):
    r = client.post(
        f"{SCAN_URL}?categories=nsfw", files={"file": ("f.txt", b"data")}, headers=auth
    )
    assert r.status_code == 400
