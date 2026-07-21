"""JCOP backend: hash → results cache → submit → poll → Verdict."""

import io
from unittest import mock

import pytest
import requests

import scanner as scanner_mod
from scanner import ScannerError, get_scanner
from scanners.jcop import JcopScanner


def _resp(status, payload=None):
    r = mock.MagicMock(status_code=status)
    r.json.return_value = payload or {}
    return r


@pytest.fixture
def jcop():
    return JcopScanner(
        base_url="https://jcop.test/api/v1", api_key="tok", poll_interval=0
    )


def _scan(jcop, get, post=None):
    with (
        mock.patch("scanners.jcop.requests.get", side_effect=get),
        mock.patch("scanners.jcop.requests.post", return_value=post),
    ):
        return jcop.scan(io.BytesIO(b"payload"))


def test_requires_config():
    with pytest.raises(RuntimeError):
        JcopScanner(base_url="", api_key="")


def test_cache_hit_clean(jcop):
    v = _scan(jcop, get=[_resp(200, {"done": True, "is_malware": False})])
    assert v.kind == "clean"


def test_cache_hit_malware(jcop):
    v = _scan(
        jcop,
        get=[_resp(200, {"done": True, "is_malware": True, "error": "Win.Trojan"})],
    )
    assert v.malware
    assert v.reason == "Win.Trojan"


def test_submit_then_poll_to_clean(jcop):
    get = [
        _resp(404),
        _resp(200, {"done": False}),
        _resp(200, {"done": True, "is_malware": False}),
    ]
    with (
        mock.patch("scanners.jcop.requests.get", side_effect=get),
        mock.patch(
            "scanners.jcop.requests.post", return_value=_resp(200, {"id": "job1"})
        ) as post,
    ):
        v = jcop.scan(io.BytesIO(b"payload"))
    assert v.kind == "clean"
    post.assert_called_once()


@pytest.mark.parametrize(
    "payload,tag",
    [({"done": True, "error_code": 413}, "TOO-LARGE"), ({"done": True}, "UNSCANNABLE")],
)
def test_unclassified_is_unscannable(jcop, payload, tag):
    v = _scan(jcop, get=[_resp(200, payload)])
    assert v.kind == "unscannable"
    assert v.reason == tag


def test_bad_key_raises(jcop):
    with pytest.raises(ScannerError):
        _scan(jcop, get=[_resp(401)])


def test_connection_error_raises(jcop):
    with pytest.raises(ScannerError):
        _scan(jcop, get=requests.RequestException("boom"))


def test_timeout_raises():
    jcop = JcopScanner(
        base_url="https://jcop.test/api/v1",
        api_key="tok",
        poll_interval=0,
        submit_timeout=0,
    )
    with mock.patch(
        "scanners.jcop.requests.get", side_effect=[_resp(200, {"done": False})]
    ):
        with pytest.raises(ScannerError):
            jcop.scan(io.BytesIO(b"payload"))


@pytest.mark.parametrize(
    "status,ok", [(200, True), (404, True), (401, True), (503, False)]
)
def test_ping(jcop, status, ok):
    with mock.patch("scanners.jcop.requests.get", return_value=_resp(status)):
        assert jcop.ping() is ok


def test_ping_connection_error(jcop):
    with mock.patch(
        "scanners.jcop.requests.get", side_effect=requests.RequestException()
    ):
        assert jcop.ping() is False


def test_registry_builds_jcop(monkeypatch):
    monkeypatch.setattr(
        scanner_mod.settings, "jcop_base_url", "https://jcop.test/api/v1"
    )
    monkeypatch.setattr(scanner_mod.settings, "jcop_api_key", "tok")
    scanner_mod._cache.pop("jcop", None)
    try:
        assert isinstance(get_scanner("jcop"), JcopScanner)
    finally:
        scanner_mod._cache.pop("jcop", None)
