"""Shared fixtures for the test suite."""

from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app import app
from config import TEST_API_KEY
from scanner import get_scanner


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


@pytest.fixture
def client():
    return TestClient(app)


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
def auth():
    return {"X-API-Key": TEST_API_KEY}


@pytest.fixture
def clamav():
    """The default backend under the test config. The app and worker share this
    cached instance, so patching its ``_cd`` covers both."""
    return get_scanner("clamav")
