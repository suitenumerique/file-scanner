import socket
import unittest
from unittest import mock

import clamd
from fastapi import HTTPException
from fastapi.testclient import TestClient

import tasks
from clamav_rest import (
    _resolves_to_public_only,
    _validate_url,
    app,
    cd,
    settings,
)
from clamav_versions import parse_local_version, parse_remote_version
from config import TEST_API_KEY
from tasks import _clamd_error_kind, scan_task
from version import __version__

client = TestClient(app)
AUTH = {"X-API-Key": TEST_API_KEY}

# pylint: disable=anomalous-backslash-in-string
EICAR = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

EICAR_TEST_OUTPUTS = (
    "Eicar-Test-Signature",
    "Win.Test.EICAR_HDB-1",
)


class VersionParsingTest(unittest.TestCase):
    def test_parse_local_version(self):
        text = "ClamAV 0.100.2/12321/Fri May 31 07:57:34 2019"
        self.assertEqual(parse_local_version(text), "12321")

    def test_parse_remote_version(self):
        text = "220.101.2:58:remote:1559294940:1:63:48725:32823"
        self.assertEqual(parse_remote_version(text), "remote")


class VersionEndpointTest(unittest.TestCase):
    @mock.patch("clamav_rest.versions.get_remote_version_number", return_value="100")
    @mock.patch("clamav_rest.versions.get_local_version_number", return_value="100")
    def test_versions_in_sync(self, local, remote):
        r = client.get("/check_version")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["outdated"])
        self.assertEqual(r.json()["service"], __version__)

    @mock.patch("clamav_rest.versions.get_remote_version_number", return_value="200")
    @mock.patch("clamav_rest.versions.get_local_version_number", return_value="100")
    def test_versions_outdated(self, local, remote):
        r = client.get("/check_version")
        self.assertEqual(r.status_code, 500)
        self.assertTrue(r.json()["outdated"])


class HealthcheckTest(unittest.TestCase):
    def test_healthcheck_ok(self):
        r = client.get("/check")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, "Service OK")

    @mock.patch.object(cd, "ping", side_effect=clamd.ConnectionError())
    def test_healthcheck_no_service(self, _):
        r = client.get("/check")
        self.assertEqual(r.status_code, 503)

    @mock.patch.object(cd, "ping", side_effect=Exception("Oops"))
    def test_healthcheck_unexpected_error(self, _):
        r = client.get("/check")
        self.assertEqual(r.status_code, 503)


class AuthTest(unittest.TestCase):
    def test_auth_required(self):
        r = client.post("/v2/scan", files={"file": ("f.txt", b"data")})
        self.assertEqual(r.status_code, 401)

    def test_auth_bad_key(self):
        r = client.post("/v2/scan", files={"file": ("f.txt", b"data")}, headers={"X-API-Key": "wrong"})
        self.assertEqual(r.status_code, 401)

    def test_auth_ok(self):
        r = client.post("/v2/scan", files={"file": ("f.txt", b"clean")}, headers=AUTH)
        self.assertEqual(r.status_code, 200)


class ScanV2Test(unittest.TestCase):
    def test_eicar(self):
        r = client.post("/v2/scan", files={"file": ("eicar.txt", EICAR)}, headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["malware"])
        self.assertIn(r.json()["reason"], EICAR_TEST_OUTPUTS)

    def test_clean_file(self):
        r = client.post("/v2/scan", files={"file": ("clean.txt", b"NO VIRUS")}, headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["malware"])

    def test_encrypted_archive(self):
        with open("client-examples/protected.zip", "rb") as f:
            r = client.post("/v2/scan", files={"file": ("protected.zip", f)}, headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertIn("malware", r.json())

    def test_xls_macro(self):
        with open("client-examples/eicar-excel-macro-powershell-echo.xls", "rb") as f:
            r = client.post("/v2/scan", files={"file": ("macro.xls", f)}, headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["malware"])

    def test_xls_dde(self):
        with open("client-examples/eicar-excel-dde-cmd-powershell-echo.xls", "rb") as f:
            r = client.post("/v2/scan", files={"file": ("dde.xls", f)}, headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertIn("malware", r.json())

    def test_payload_right_size(self):
        content = b"\0" * (settings.max_upload_size - 10000)
        r = client.post("/v2/scan", files={"file": ("big.bin", content)}, headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["malware"])

    def test_payload_too_large(self):
        content = b"\0" * (settings.max_upload_size + 1000)
        r = client.post("/v2/scan", files={"file": ("toobig.bin", content)}, headers=AUTH)
        self.assertEqual(r.status_code, 413)


class ScanAsyncTest(unittest.TestCase):
    def test_requires_auth(self):
        r = client.post("/v2/scan-async", json={"url": "http://example.com/f"})
        self.assertEqual(r.status_code, 401)

    def test_requires_url(self):
        r = client.post("/v2/scan-async", json={}, headers=AUTH)
        self.assertEqual(r.status_code, 422)

    def test_rejects_bad_scheme(self):
        r = client.post("/v2/scan-async", json={"url": "ftp://evil.com/f"}, headers=AUTH)
        self.assertEqual(r.status_code, 422)

    def test_requires_webhook(self):
        r = client.post("/v2/scan-async", json={"url": "http://example.com/f.pdf"}, headers=AUTH)
        self.assertEqual(r.status_code, 422)

    def test_creates_job(self):
        r = client.post("/v2/scan-async", json={
            "url": "http://example.com/f.pdf",
            "filename": "f.pdf",
            "webhook_url": "http://callback.example.com/av",
        }, headers=AUTH)
        self.assertEqual(r.status_code, 202)
        self.assertIn("job_id", r.json())
        self.assertEqual(r.json()["status"], "pending")

    def test_with_metadata(self):
        r = client.post("/v2/scan-async", json={
            "url": "http://example.com/f.pdf",
            "webhook_url": "http://callback.example.com/av",
            "metadata": {"file_id": "abc123"},
        }, headers=AUTH)
        self.assertEqual(r.status_code, 202)

    def test_allowed_url_hosts(self):
        original = settings.allowed_url_hosts
        settings.allowed_url_hosts = "trusted.example.com"
        try:
            r = client.post("/v2/scan-async", json={"url": "http://evil.com/f"}, headers=AUTH)
            self.assertEqual(r.status_code, 400)
            self.assertIn("not allowed", r.json()["detail"])

            r = client.post("/v2/scan-async", json={
                "url": "http://trusted.example.com/f",
                "webhook_url": "http://callback.example.com/av",
            }, headers=AUTH)
            self.assertEqual(r.status_code, 202)
        finally:
            settings.allowed_url_hosts = original


class ClamdErrorKindTest(unittest.TestCase):
    """An ERROR verdict from clamd is 'file' (unscannable — caller must drop
    it) unless its reason carries an unambiguous resource signal, which makes
    it 'transient' (retryable)."""

    def test_transient_hints(self):
        for reason in (
            "can't allocate memory",
            "Time limit reached",
            "read timeout",
            "No space left on device",
            "WRITE: NO SPACE",  # case-insensitive
        ):
            self.assertEqual(_clamd_error_kind(reason), "transient", reason)

    def test_file_reasons(self):
        for reason in (
            "Encrypted.PDF",
            "Heuristics.Encrypted.Zip",
            "Broken archive",
            "",
            None,
        ):
            self.assertEqual(_clamd_error_kind(reason), "file", repr(reason))


class ScanTaskClassificationTest(unittest.TestCase):
    """``scan_task`` runs eagerly and reports its verdict (and, on failure, an
    ``error_kind``) through the single webhook channel. A *file* failure is
    reported at once; a *transient* one only after the retry budget is spent,
    so the webhook fires exactly once either way."""

    @classmethod
    def setUpClass(cls):
        cls._eager = tasks.celery_app.conf.task_always_eager
        tasks.celery_app.conf.task_always_eager = True
        tasks.celery_app.conf.task_eager_propagates = False

    @classmethod
    def tearDownClass(cls):
        tasks.celery_app.conf.task_always_eager = cls._eager

    def _run(self, scan=None, get=None, content_length=None, chunks=None):
        """Run scan_task with the download + clamd boundaries stubbed and the
        webhook captured. Returns the list of payloads pushed to the webhook."""
        sent = []

        def _capture(_url, payload):
            sent.append(dict(payload))
            return True

        response = mock.MagicMock()
        response.headers = (
            {"Content-Length": str(content_length)} if content_length else {}
        )
        response.iter_content.return_value = chunks if chunks is not None else [b"data"]

        with mock.patch.object(tasks, "_send_webhook", side_effect=_capture), \
            mock.patch.object(
                tasks.http_requests,
                "get",
                side_effect=get,
                return_value=None if get else response,
            ), \
            mock.patch.object(
                tasks._cd,
                "scan",
                side_effect=scan or (lambda p: {p: ("OK", None)}),
            ):
            scan_task.apply(
                args=["job1", "http://src/f.bin", "f.bin", "http://cb/av", None]
            )
        return sent

    def test_clean(self):
        sent = self._run(scan=lambda p: {p: ("OK", None)})
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["status"], "done")
        self.assertFalse(sent[0]["malware"])
        self.assertNotIn("error_kind", sent[0])

    def test_infected(self):
        sent = self._run(scan=lambda p: {p: ("FOUND", "Eicar-Test-Signature")})
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["status"], "done")
        self.assertTrue(sent[0]["malware"])
        self.assertEqual(sent[0]["reason"], "Eicar-Test-Signature")

    def test_error_verdict_file(self):
        sent = self._run(scan=lambda p: {p: ("ERROR", "Encrypted.PDF")})
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["status"], "error")
        self.assertEqual(sent[0]["error_kind"], "file")

    def test_error_verdict_transient(self):
        sent = self._run(scan=lambda p: {p: ("ERROR", "Time limit reached")})
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["status"], "error")
        self.assertEqual(sent[0]["error_kind"], "transient")

    def test_no_verdict_is_transient(self):
        sent = self._run(scan=lambda p: {})
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["error_kind"], "transient")

    def test_too_large_is_file(self):
        sent = self._run(content_length=settings.max_url_size + 1)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["status"], "error")
        self.assertEqual(sent[0]["error_kind"], "file")

    def test_unbounded_body_capped_as_file(self):
        # No Content-Length header, but the streamed body exceeds the cap: the
        # byte-counting guard rejects it as a file error instead of writing an
        # unbounded body to disk.
        with mock.patch.object(tasks.settings, "max_url_size", 8):
            sent = self._run(chunks=[b"x" * 20])
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["status"], "error")
        self.assertEqual(sent[0]["error_kind"], "file")

    def test_malformed_content_length_ignored(self):
        # A non-numeric Content-Length must not crash the task; it's treated as
        # absent and the (small) body scans normally.
        sent = self._run(content_length="not-a-number")
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["status"], "done")
        self.assertNotIn("error_kind", sent[0])

    def test_download_failure_is_transient(self):
        def _boom(*_a, **_k):
            raise tasks.http_requests.RequestException("connection reset")

        sent = self._run(get=_boom)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["error_kind"], "transient")

    def test_clamd_connection_error_is_transient(self):
        def _boom(_p):
            raise clamd.ConnectionError("clamd down")

        sent = self._run(scan=_boom)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["error_kind"], "transient")


def _gai(*ips):
    """Build a socket.getaddrinfo-shaped return value for the given IPs."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


class ResolvesToPublicOnlyTest(unittest.TestCase):
    """`_resolves_to_public_only` is the SSRF core: it returns False as soon as
    any A/AAAA record points at non-public space, and fails open (True) only
    when the name doesn't resolve at all."""

    def _resolves(self, *ips):
        with mock.patch("clamav_rest.socket.getaddrinfo", return_value=_gai(*ips)):
            return _resolves_to_public_only("host.example.com")

    def test_public_is_allowed(self):
        self.assertTrue(self._resolves("93.184.216.34"))

    def test_non_public_is_rejected(self):
        for ip in (
            "127.0.0.1",        # loopback
            "10.0.0.1",         # RFC1918
            "192.168.1.1",      # RFC1918
            "172.16.0.1",       # RFC1918
            "169.254.169.254",  # link-local: cloud metadata endpoint
            "0.0.0.0",          # unspecified
            "224.0.0.1",        # multicast
            "240.0.0.1",        # reserved
            "::1",              # IPv6 loopback
            "fd00::1",          # IPv6 unique-local
        ):
            self.assertFalse(self._resolves(ip), ip)

    def test_any_non_public_record_rejects(self):
        # A hostname that resolves to both a public and a private address must
        # be rejected — a DNS-rebinding style trick can't slip through.
        self.assertFalse(self._resolves("93.184.216.34", "10.0.0.1"))

    def test_unresolvable_fails_open(self):
        # By design: let the download surface a clear network error rather than
        # a misleading 400.
        with mock.patch(
            "clamav_rest.socket.getaddrinfo", side_effect=socket.gaierror
        ):
            self.assertTrue(_resolves_to_public_only("does-not-exist.invalid"))


class ValidateUrlTest(unittest.TestCase):
    """`_validate_url` wires the SSRF guard into request handling. The guard is
    only active when `settings.testing` is False, so we flip it here."""

    def setUp(self):
        self._testing = settings.testing
        settings.testing = False

    def tearDown(self):
        settings.testing = self._testing

    def test_missing_hostname_is_rejected(self):
        # Independent of the testing flag, but cheap to assert here.
        with self.assertRaises(HTTPException) as ctx:
            _validate_url("not-a-url")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_public_host_passes(self):
        with mock.patch(
            "clamav_rest.socket.getaddrinfo", return_value=_gai("93.184.216.34")
        ):
            _validate_url("https://example.com/f.pdf")  # no raise

    def test_non_public_host_is_rejected(self):
        with mock.patch(
            "clamav_rest.socket.getaddrinfo", return_value=_gai("169.254.169.254")
        ):
            with self.assertRaises(HTTPException) as ctx:
                _validate_url("http://metadata.internal/latest/meta-data")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("non-public", ctx.exception.detail)

    def test_guard_skipped_when_testing(self):
        # With testing back on, even a metadata IP passes _validate_url — the
        # guard is deliberately inert in the test/CI configs.
        settings.testing = True
        with mock.patch(
            "clamav_rest.socket.getaddrinfo", return_value=_gai("169.254.169.254")
        ):
            _validate_url("http://metadata.internal/x")  # no raise


class ScanAsyncSsrfTest(unittest.TestCase):
    """End-to-end: a URL resolving to a non-public address is refused with 400
    at the /v2/scan-async boundary when the guard is active."""

    def setUp(self):
        self._testing = settings.testing
        settings.testing = False

    def tearDown(self):
        settings.testing = self._testing

    # These patch `_resolves_to_public_only` (already covered end-to-end by
    # ResolvesToPublicOnlyTest) rather than socket.getaddrinfo: the latter is
    # process-global, so a mocked resolver would also hijack the Celery broker
    # connection that a 202 triggers via scan_task.delay().
    def test_metadata_url_rejected(self):
        with mock.patch("clamav_rest._resolves_to_public_only", return_value=False):
            r = client.post("/v2/scan-async", json={
                "url": "http://metadata.example.com/latest/meta-data",
                "webhook_url": "http://callback.example.com/av",
            }, headers=AUTH)
        self.assertEqual(r.status_code, 400)
        self.assertIn("non-public", r.json()["detail"])

    def test_public_url_accepted(self):
        with mock.patch("clamav_rest._resolves_to_public_only", return_value=True):
            r = client.post("/v2/scan-async", json={
                "url": "http://example.com/f.pdf",
                "webhook_url": "http://callback.example.com/av",
            }, headers=AUTH)
        self.assertEqual(r.status_code, 202)


if __name__ == "__main__":
    unittest.main()
