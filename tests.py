import unittest
from unittest import mock

import clamd
from fastapi.testclient import TestClient

from clamav_rest import app, cd, settings
from clamav_versions import parse_local_version, parse_remote_version
from config import TEST_API_KEY
from database import engine
from models import Base
from version import __version__

Base.metadata.create_all(engine)

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

    def test_creates_job(self):
        r = client.post("/v2/scan-async", json={"url": "http://example.com/f.pdf", "filename": "f.pdf"}, headers=AUTH)
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

            r = client.post("/v2/scan-async", json={"url": "http://trusted.example.com/f"}, headers=AUTH)
            self.assertEqual(r.status_code, 202)
        finally:
            settings.allowed_url_hosts = original


class JobStatusTest(unittest.TestCase):
    def test_requires_auth(self):
        r = client.get("/v2/jobs/nonexistent")
        self.assertEqual(r.status_code, 401)

    def test_not_found(self):
        r = client.get("/v2/jobs/nonexistent", headers=AUTH)
        self.assertEqual(r.status_code, 404)

    def test_returns_created_job(self):
        create = client.post("/v2/scan-async", json={"url": "http://example.com/f.pdf"}, headers=AUTH)
        job_id = create.json()["job_id"]
        r = client.get(f"/v2/jobs/{job_id}", headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["job_id"], job_id)


if __name__ == "__main__":
    unittest.main()
