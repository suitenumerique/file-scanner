"""Shared fixtures for the test suite."""

import time
from unittest import mock

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import jwt_auth
from app import app
from scanner import get_scanner

TEST_ISSUER = "dev-issuer"


def _reachable(name: str) -> bool:
    try:
        return get_scanner(name).ping()
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    """Auto-skip scanner integration tests when their daemon isn't reachable, so
    a bare local ``pytest`` stays green; ``make test`` runs them against the
    container. ``@pytest.mark.integration`` → clamav; ``@pytest.mark.exav`` →
    exav (also skipped when exav isn't configured). Reachability checked once."""
    for marker, scanner, reason in (
        ("integration", "clamav", "clamav daemon not reachable"),
        ("exav", "exav", "exav daemon not configured/reachable"),
    ):
        if _reachable(scanner):
            continue
        skip = pytest.mark.skip(reason=reason)
        for item in items:
            if marker in item.keywords:
                item.add_marker(skip)


class _MintAuth(httpx.Auth):
    """httpx auth that mints a fresh, correctly **request-bound** EdDSA JWT for
    each outgoing request (method + target, plus the body hash) — so tests just
    call ``auth_client`` like ``client`` and get a valid token every time,
    without threading per-request binding through every call site."""

    # Buffer the body before signing so request.content is readable even for
    # multipart uploads (its hash is harmless on sync, which doesn't bind it).
    requires_request_body = True

    def __init__(self, private_key, iss=TEST_ISSUER, aud="file-scanner"):
        self._priv, self._iss, self._aud = private_key, iss, aud

    def auth_flow(self, request):
        now = int(time.time())
        query = request.url.query.decode()
        htu = request.url.path + (f"?{query}" if query else "")
        payload = {
            "iss": self._iss,
            "aud": self._aud,
            "iat": now,
            "exp": now + 300,
            "htm": request.method,
            "htu": htu,
        }
        if request.content:
            payload["bh"] = jwt_auth.body_hash(request.content)
        request.headers["Authorization"] = (
            f"Bearer {jwt_auth.encode(payload, private_key=self._priv)}"
        )
        yield request


@pytest.fixture
def client():
    """An unauthenticated TestClient (for health, metrics, and 401 checks)."""
    return TestClient(app)


@pytest.fixture
def auth_client():
    """A TestClient authenticated as the test caller ``dev-issuer``: it installs that
    caller's public key and auto-signs every request with a bound Bearer JWT."""
    priv = Ed25519PrivateKey.generate()
    with mock.patch.dict(
        jwt_auth._ISSUER_KEYS, {TEST_ISSUER: priv.public_key()}, clear=True
    ):
        c = TestClient(app)
        c.auth = _MintAuth(priv)
        yield c


@pytest.fixture
def clamav_cd(clamav):
    """A mock clamd client wired into the clamav backend (the app + worker build
    a client per scan via ``_client()``). Configure ``.instream`` / ``.ping``."""
    cd = mock.MagicMock()
    with mock.patch.object(clamav, "_client", return_value=cd):
        yield cd


@pytest.fixture
def eicar():
    """The harmless EICAR antivirus test signature."""
    return rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture
def eicar_outputs():
    """Signature names clamd/exav report EICAR under."""
    return ("Eicar-Test-Signature", "Win.Test.EICAR_HDB-1")


@pytest.fixture
def clamav():
    """The default backend under the test config. The app and worker share this
    cached instance, so patching its ``_cd`` covers both."""
    return get_scanner("clamav")
