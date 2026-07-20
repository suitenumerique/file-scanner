"""Shared fixtures for the test suite."""

from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app import app
from config import TEST_API_KEY
from scanner import get_scanner


def _clamav_reachable() -> bool:
    try:
        return get_scanner("clamav").ping()
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    """Auto-skip ``@pytest.mark.integration`` tests when no clamav daemon is
    reachable, so a bare local ``pytest`` stays green; ``make test`` runs them
    against the container. Checked once per session."""
    if _clamav_reachable():
        return
    skip = pytest.mark.skip(reason="clamav daemon not reachable")
    for item in items:
        if "integration" in item.keywords:
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
