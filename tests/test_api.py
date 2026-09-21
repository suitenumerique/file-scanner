"""HTTP API: metrics, health, version, auth, and the sync /api/v1.0/scan endpoint."""

from unittest import mock

import clamd
import pytest
from conftest import is_eicar_signature

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


def test_metrics_label_api_client(auth_client, clamav_cd):
    # A scan is attributed to the caller's JWT `iss` (here "dev-issuer").
    clamav_cd.instream.return_value = {"stream": ("OK", None)}
    auth_client.post(SCAN_URL, files={"file": ("f.txt", b"data")})
    r = auth_client.get("/metrics")
    assert 'api_client="dev-issuer"' in r.text


def test_metrics_signature_gauges(client, clamav, monkeypatch):
    # Bypass the refresh TTL. Must be -inf, not 0.0: the check is
    # ``monotonic() - _last < TTL`` and ``monotonic()`` is seconds since boot, so
    # on a freshly-booted CI runner it can be < TTL, leaving 0.0 within the window
    # and skipping the refresh. "Infinitely long ago" is always past the TTL.
    monkeypatch.setattr(metrics, "_last_signature_refresh", float("-inf"))
    # ``/metrics`` uses ``resolve_scanners()`` to decide which scanners to
    # refresh, and that reads ``DEFAULT_CATEGORIES`` from settings. An
    # empty default (env-less CI runs) makes ``resolve_scanners`` raise
    # ValueError, which the endpoint swallows — no gauge samples emit, and
    # the assertions below never see them. Pin the default explicitly so
    # the test is env-agnostic.
    monkeypatch.setattr(settings, "default_categories", "malware")
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


def test_auth_bad_token(client):
    r = client.post(
        SCAN_URL,
        files={"file": ("f.txt", b"data")},
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert r.status_code == 401


@pytest.mark.integration
def test_auth_ok(auth_client):
    r = auth_client.post(SCAN_URL, files={"file": ("f.txt", b"clean")})
    assert r.status_code == 200


# --- sync scan against a real clamav (auto-skipped without a daemon, run in CI) ---


@pytest.mark.integration
def test_eicar(auth_client, eicar):
    r = auth_client.post(SCAN_URL, files={"file": ("eicar.txt", eicar)})
    assert r.status_code == 200
    assert r.json()["malware"]
    assert is_eicar_signature(r.json()["scanners"][0]["reason"])


@pytest.mark.integration
def test_clean_file(auth_client):
    r = auth_client.post(SCAN_URL, files={"file": ("clean.txt", b"NO VIRUS")})
    assert r.status_code == 200
    assert r.json()["malware"] is False
    assert r.json()["scanners"][0]["kind"] == "clean"


@pytest.mark.integration
def test_payload_right_size(auth_client):
    content = b"\0" * (settings.max_upload_size - 10000)
    r = auth_client.post(SCAN_URL, files={"file": ("big.bin", content)})
    assert r.status_code == 200
    assert r.json()["malware"] is False


# --- exav backend (skipped unless an exav daemon is configured + reachable) ---


@pytest.mark.exav
def test_exav_eicar(auth_client, eicar):
    r = auth_client.post(
        f"{SCAN_URL}?scanners=exav", files={"file": ("eicar.txt", eicar)}
    )
    assert r.status_code == 200
    entry = r.json()["scanners"][0]
    assert r.json()["malware"]
    assert entry["scanner"] == "exav"
    assert entry["category"] == "malware"
    assert is_eicar_signature(entry["reason"])


@pytest.mark.exav
def test_exav_clean(auth_client):
    r = auth_client.post(
        f"{SCAN_URL}?scanners=exav", files={"file": ("clean.txt", b"NO VIRUS")}
    )
    assert r.status_code == 200
    assert r.json()["malware"] is False
    assert r.json()["scanners"][0]["scanner"] == "exav"
    assert r.json()["scanners"][0]["kind"] == "clean"


def test_payload_too_large(auth_client):
    content = b"\0" * (settings.max_upload_size + 1000)
    r = auth_client.post(SCAN_URL, files={"file": ("toobig.bin", content)})
    assert r.status_code == 413


# --- verdict mapping (mocked INSTREAM) ---


def test_unscannable_is_neither_clean_nor_malware(auth_client, clamav_cd):
    # An ERROR reply is unscannable: never malware, never clean either — the
    # axis is unknown and the report blames the file. The clamav backend
    # flattens the reason to UNSCANNABLE (exav preserves its category).
    clamav_cd.instream.return_value = {"stream": ("ERROR", "Encrypted data")}
    r = auth_client.post(SCAN_URL, files={"file": ("locked.zip", b"data")})
    assert r.status_code == 200
    body = r.json()
    assert body["malware"] is None
    assert body["error_kind"] == "file"
    entry = body["scanners"][0]
    assert entry["kind"] == "unscannable"
    assert entry["reason"] == "UNSCANNABLE"


def test_all_scanners_error_returns_503(auth_client, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("ERROR", "Can't allocate memory")}
    r = auth_client.post(SCAN_URL, files={"file": ("f.bin", b"data")})
    assert r.status_code == 503


def test_untagged_file_error_is_unscannable(auth_client, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("ERROR", "Broken archive")}
    r = auth_client.post(SCAN_URL, files={"file": ("f.bin", b"data")})
    assert r.status_code == 200
    assert r.json()["scanners"][0]["reason"] == "UNSCANNABLE"


def test_scanners_param_selects(auth_client, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("OK", None)}
    r = auth_client.post(
        f"{SCAN_URL}?scanners=clamav", files={"file": ("f.txt", b"data")}
    )
    assert r.status_code == 200
    entry = r.json()["scanners"][0]
    assert entry["scanner"] == "clamav"
    assert entry["category"] == "malware"


def test_categories_param_selects(auth_client, clamav_cd):
    clamav_cd.instream.return_value = {"stream": ("OK", None)}
    r = auth_client.post(
        f"{SCAN_URL}?categories=malware", files={"file": ("f.txt", b"data")}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["malware"] is False  # per-category top-level key
    assert body["scanners"][0]["scanner"] == "clamav"


def test_unknown_scanner_rejected(auth_client):
    r = auth_client.post(
        f"{SCAN_URL}?scanners=bogus", files={"file": ("f.txt", b"data")}
    )
    assert r.status_code == 400


def test_unknown_category_rejected(auth_client):
    r = auth_client.post(
        f"{SCAN_URL}?categories=nsfw", files={"file": ("f.txt", b"data")}
    )
    assert r.status_code == 400


def test_probe_access_logs_are_dropped_when_successful():
    """uvicorn's access log for a 200 on /check, / or /metrics is noise;
    anything else on those paths, and every other path, still logs."""
    import logging

    from app import _DropProbeAccessLogs

    flt = _DropProbeAccessLogs()

    def record(path, status, method="GET"):
        # Exactly uvicorn's call: '%s - "%s %s HTTP/%s" %d' with 5 args.
        return logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            "",
            0,
            '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:1", method, path, "1.1", status),
            None,
        )

    assert flt.filter(record("/check", 200)) is False
    assert flt.filter(record("/", 200)) is False
    assert flt.filter(record("/metrics", 200)) is False
    assert flt.filter(record("/metrics?x=1", 200)) is False
    assert flt.filter(record("/check", 503)) is True
    assert flt.filter(record("/metrics", 401)) is True
    assert flt.filter(record("/checks", 200)) is True
    assert flt.filter(record("/api/v1.0/scan-async", 202, "POST")) is True
    # A record that isn't uvicorn's access line passes through untouched.
    other = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "hi", (), None)
    assert flt.filter(other) is True
