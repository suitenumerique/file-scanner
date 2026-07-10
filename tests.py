import unittest
from unittest import mock

import clamd
from fastapi.testclient import TestClient

import tasks
from clamav_rest import app, cd, settings
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


if __name__ == "__main__":
    unittest.main()
